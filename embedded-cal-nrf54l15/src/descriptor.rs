/// Pointer to memory address 1.
/// It means that the descriptor chain is over
#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
pub(crate) const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;
/// Single EasyDMA scatter-gather job entry.
///
/// This structure maps directly to one hardware “job entry” consumed by the
/// EasyDMA engine when scatter-gather mode is enabled. Each descriptor describes
/// one contiguous memory region to be read from or written to by DMA.
/// `next` must either point to the next `Descriptor` in the chain or be the
#[repr(C)]
#[derive(Debug, Clone, Copy)]

pub(crate) struct Descriptor {
    /// Start address of the memory region for this DMA job.
    ///
    /// Must be DMA-accessible memory.
    pub(crate) addr: *mut u8,
    /// Pointer to the next descriptor in the scatter-gather job list.
    ///
    /// Should be LAST_DESC_PTR in case of the last descriptor of the chain.
    pub(crate) next: *mut Descriptor,
    // FIXME: Improve documentation, explain the magic number 0x2000_0000
    /// Length, in bytes, of the memory region described by `addr`.
    pub(crate) sz: u32,
    // FIXME: Improve documentation, enum all possible tags.
    /// DMA attribute / tag field.
    pub(crate) dmatag: u32,
}

impl Descriptor {
    fn empty() -> Self {
        Self {
            addr: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            sz: 0,
            dmatag: 0,
        }
    }
}

/// Fixed-capacity scatter-gather descriptor chain.
///
/// This type owns a small array of `Descriptor`s and tracks how many entries
/// are currently in use.
///
/// DescriptorChain also make sure they are linked like a linked-list
/// and the last Descriptor.next is always LAST_DESC_PTR
// There is no reason the value is 4, it was just because it was the biggest chain used on HASH example.
// This can be generic.
pub(crate) struct DescriptorChain {
    descs: [Descriptor; 4],
    count: usize,
}

impl DescriptorChain {
    /// Creates an empty `DescriptorChain`.
    ///
    /// The chain is initialized with all descriptors zero-filled and contains
    /// no active entries.
    pub(crate) fn new() -> Self {
        Self {
            descs: [Descriptor::empty(); 4],
            count: 0,
        }
    }

    /// Appends a descriptor to the end of the chain.
    ///
    /// This method:
    /// - Stores `desc` in the next free slot.
    /// - Updates the `next` pointer of the previous descriptor to point to the
    ///   newly added one.
    /// - Ensures the newly added descriptor’s `next` pointer is set to
    ///   `LAST_DESC_PTR`, marking it as the terminal job entry.
    ///
    /// # Panics
    ///
    /// Panics if the chain is already at full capacity.
    ///
    /// # Safety / Correctness requirements
    ///
    /// - The descriptor and all previously pushed descriptors must remain
    ///   valid and unmodified while a DMA transfer is in progress.
    /// - All descriptors in the chain must describe DMA-accessible memory.
    /// - The chain must not be mutated after being handed to the EasyDMA
    ///   hardware until the END or ERROR event is observed.
    pub(crate) fn push(&mut self, desc: Descriptor) {
        assert!(self.count < 4);

        let idx = self.count;
        self.descs[idx] = desc;
        self.count += 1;

        // update links
        if idx > 0 {
            let prev = idx - 1;
            self.descs[prev].next = &mut self.descs[idx];
        }

        self.descs[idx].next = LAST_DESC_PTR;
    }

    /// Returns a mutable pointer to the first descriptor in the chain.
    ///
    /// This pointer is intended to be written to the EasyDMA input/output pointer
    /// register to start a scatter-gather transfer.
    ///
    /// If the chain is empty, this function returns a null pointer, indicating
    /// that no DMA jobs are configured.
    pub(crate) fn first(&mut self) -> *mut Descriptor {
        if self.count == 0 {
            core::ptr::null_mut()
        } else {
            &mut self.descs[0]
        }
    }
}
