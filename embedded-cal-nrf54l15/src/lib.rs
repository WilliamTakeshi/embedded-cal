#![no_std]
mod descriptor;

use descriptor::DescriptorChain;
use nrf_pac::{cracen, cracencore};

use crate::descriptor::sz;

const MAX_DESCRIPTOR_CHAIN_LEN: usize = 4;
const INTERNAL_STATE_LEN: usize = 32;

pub struct Nrf54l15Cal {
    // FIXME: No need to enable and take ownership of everything
    // it's possible to have a more granular ownership
    cracen: cracen::Cracen,
    cracen_core: cracencore::Cracencore,
}

impl embedded_cal::Cal for Nrf54l15Cal {}

impl Nrf54l15Cal {
    pub fn new(cracen: cracen::Cracen, cracen_core: cracencore::Cracencore) -> Self {
        // Enable cryptomaster
        cracen.enable().write(|w| {
            w.set_cryptomaster(true);
            w.set_rng(true);
            w.set_pkeikg(true)
        });

        Self {
            cracen,
            cracen_core,
        }
    }
}

impl Drop for Nrf54l15Cal {
    fn drop(&mut self) {
        // Disable cryptomaster on drop
        self.cracen.enable().write(|w| {
            w.set_cryptomaster(false);
            w.set_rng(false);
            w.set_pkeikg(false)
        });
    }
}

pub struct HashState {
    // FIXME: Use this when implement SHA2-224
    _variant: embedded_cal::plumbing::hash::Sha2ShortVariant,
    state: Option<[u8; 32]>,
    processed_bytes: usize,
}

pub enum HashResult {
    Sha256([u8; 32]),
}

impl AsRef<[u8]> for HashResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(r) => &r[..],
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NoFullAlgorithms {}

impl embedded_cal::HashAlgorithm for NoFullAlgorithms {
    fn len(&self) -> usize {
        match *self {}
    }
}

impl AsRef<[u8]> for NoFullAlgorithms {
    fn as_ref(&self) -> &[u8] {
        match *self {}
    }
}

impl embedded_cal::HashProvider for Nrf54l15Cal {
    type Algorithm = NoFullAlgorithms;
    type HashState = NoFullAlgorithms;
    type HashResult = NoFullAlgorithms;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {}
    }

    fn update(&mut self, instance: &mut Self::HashState, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {}
    }
}

impl embedded_cal::plumbing::Plumbing for Nrf54l15Cal {}

impl embedded_cal::plumbing::hash::Hash for Nrf54l15Cal {}

impl embedded_cal::plumbing::hash::Sha2Short for Nrf54l15Cal {
    const SUPPORTED: bool = true;
    const SEND_PADDING: bool = false;
    const FIRST_CHUNK_SIZE: usize = 64;
    const UPDATE_MULTICHUNK: bool = true;

    type State = HashState;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        Self::State {
            _variant: variant,
            state: None,
            processed_bytes: 0,
        }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        let mut new_state: [u8; 32] = [0x00; 32];

        let header: [u8; 4] = [0x08, 0x00, 0x00, 0x00];

        let state_len = INTERNAL_STATE_LEN;

        let mut output_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();
        output_descriptors.push(new_state.as_mut_ptr(), sz(state_len), 32);

        let mut input_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();

        input_descriptors.push(header.as_ptr() as *mut u8, sz(4), 19);

        if let Some(state) = &instance.state {
            input_descriptors.push(state.as_ptr() as *mut u8, sz(state_len), 99);
        }

        input_descriptors.push(
            data.as_ptr() as *mut u8,
            0x2000_0000 | data.len() as u32,
            35,
        );

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        instance.state = Some(new_state);
        instance.processed_bytes += data.len();
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        let mut pad: [u8; 256] = [0x00; 256];

        let padding_size = embedded_cal_software::sha256_padding(
            instance.processed_bytes + last_chunk.len(),
            &mut pad,
        );

        let algo_len = 32;
        let state_len = INTERNAL_STATE_LEN;

        let mut out: [u8; 64] = [0x00; 64];

        let mut output_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();
        output_descriptors.push(out.as_mut_ptr(), sz(algo_len), 32);

        let header: [u8; 4] = [0x08, 0x04, 0x00, 0x00];

        let mut input_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();

        input_descriptors.push(header.as_ptr() as *mut u8, sz(4), 19);

        if let Some(state) = &instance.state {
            input_descriptors.push(state.as_ptr() as *mut u8, sz(state_len), 99);
        }

        input_descriptors.push(last_chunk.as_ptr() as *mut u8, last_chunk.len() as u32, 3);

        input_descriptors.push(
            pad.as_ptr() as *mut u8,
            0x2000_0000 | padding_size as u32,
            35,
        );

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        target.copy_from_slice(&out[..32]);
    }
}

impl Nrf54l15Cal {
    fn execute_cryptomaster_dma<const N: usize>(
        &mut self,
        input_descriptors: &mut DescriptorChain<N>,
        output_descriptors: &mut DescriptorChain<N>,
    ) -> () {
        let dma = self.cracen_core.cryptmstrdma();
        // Configure DMA source
        dma.fetchaddrlsb()
            .write_value(input_descriptors.first() as u32);

        // Configure DMA sink
        dma.pushaddrlsb()
            .write_value(output_descriptors.first() as u32);

        dma.config().write(|w| {
            w.set_fetchctrlindirect(true);
            w.set_pushctrlindirect(true);
            w.set_fetchstop(false);
            w.set_pushstop(false);
            w.set_softrst(false)
        });

        // Start DMA
        dma.start().write(|w| {
            w.set_startfetch(true);
            w.set_startpush(true)
        });

        // Wait
        while dma.status().read().fetchbusy() {}
        while dma.status().read().pushbusy() {}
    }
}
