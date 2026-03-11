// DMA descriptor layout and tag encoding below were reverse-engineered from
// https://github.com/nrfconnect/sdk-nrf
// `sdk-nrf/.../sxsymcrypt/src/cmdma.h` and the associated cryptomaster driver.

/// Bit 29 of a descriptor's `sz` field.
///
/// When set, instructs the cryptomaster DMA pusher to realign the output data
/// to the start of the destination buffer, rather than continuing at whatever
/// byte offset the previous transfer ended. Required whenever the output
/// descriptor does not start on a natural alignment boundary.
///
/// Source: `DMA_REALIGN = (1 << 29)` in `sdk-nrf/subsys/nrf_security/src/drivers/cracen/sxsymcrypt/src/cmdma.h`.
pub(crate) const DMA_REALIGN: usize = 0x2000_0000;

/// Pointer to memory address 1.
/// It means that the descriptor chain is over
#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;
/// Single EasyDMA scatter-gather job entry.
///
/// This structure maps directly to one hardware “job entry” consumed by the
/// EasyDMA engine when scatter-gather mode is enabled. Each descriptor describes
/// one contiguous memory region to be read from or written to by DMA.
/// `next` must either point to the next `Descriptor` in the chain or be the
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Descriptor {
    /// Start address of the memory region for this DMA job.
    ///
    /// Must be DMA-accessible memory.
    addr: *mut u8,
    /// Pointer to the next descriptor in the scatter-gather job list.
    ///
    /// Should be LAST_DESC_PTR in case of the last descriptor of the chain.
    next: *mut Descriptor,
    /// Length, in bytes, of the memory region described by `addr`.
    ///
    /// Bits [27:0] hold the byte count. Bit 29 (`DMA_REALIGN`) may be set to
    /// instruct the pusher to realign output to the buffer start. Use the
    /// [`sz`] helper to construct this field correctly.
    sz: u32,
    /// DMA engine selector and transfer attributes for the cryptomaster.
    ///
    /// The low bits select which hardware engine receives the data (e.g. BA413
    /// for SHA-2). Higher bits encode data type (header vs. payload), the
    /// "last descriptor" flag, and optional byte-ignore counts. See the
    /// `DMATAG_BA413_*` constants in `lib.rs` for the values used by this
    /// driver.
    dmatag: u32,
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

    fn new(addr: *mut u8, sz: u32, dmatag: u32) -> Self {
        Self {
            addr,
            next: core::ptr::null_mut(),
            sz,
            dmatag,
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
pub(crate) struct DescriptorChain<const N: usize> {
    descs: [Descriptor; N],
    count: usize,
}

impl<const N: usize> DescriptorChain<N> {
    /// Creates an empty `DescriptorChain`.
    ///
    /// The chain is initialized with all descriptors zero-filled and contains
    /// no active entries.
    pub(crate) fn new() -> Self {
        Self {
            descs: [Descriptor::empty(); N],
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
    pub(crate) fn push(&mut self, addr: *mut u8, sz: u32, dmatag: u32) {
        assert!(self.count < N);
        let desc = Descriptor::new(addr, sz, dmatag);

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

    /// Returns an address to the first descriptor in the chain.
    ///
    /// This pointer is intended to be written to the EasyDMA input/output pointer
    /// register to start a scatter-gather transfer.
    pub(crate) fn first(&mut self) -> u32 {
        &mut self.descs[0] as *mut Descriptor as u32
    }
}

/// Constructs a descriptor `sz` field from a byte count.
///
/// Asserts the count is a multiple of 4 (word-aligned), then ORs in
/// [`DMA_REALIGN`] (bit 29) so the cryptomaster pusher realigns output to the
/// buffer start.
#[inline]
pub(crate) const fn sz(n: usize) -> u32 {
    debug_assert!(
        n % 4 == 0,
        "Sizes passed through this function need to be in multiples of the word size"
    );
    (n | DMA_REALIGN) as u32
}
