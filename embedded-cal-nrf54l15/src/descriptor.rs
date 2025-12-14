#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
pub(crate) const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Descriptor {
    pub(crate) addr: *mut u8,
    pub(crate) next: *mut Descriptor,
    pub(crate) sz: u32,
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

pub(crate) struct DescriptorChain {
    descs: [Descriptor; 4],
    count: usize,
}

impl DescriptorChain {
    pub(crate) fn new() -> Self {
        Self {
            descs: [Descriptor::empty(); 4],
            count: 0,
        }
    }

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

    pub(crate) fn first(&mut self) -> *mut Descriptor {
        if self.count == 0 {
            core::ptr::null_mut()
        } else {
            &mut self.descs[0]
        }
    }
}
