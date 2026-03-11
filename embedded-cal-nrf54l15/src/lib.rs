//! nRF54L15 CRACEN cryptomaster backend for embedded-cal.
//!
//! Most of the hardware interaction in this crate (DMA descriptor layout, tag
//! encoding, algorithm config words, and the cryptomaster register sequence)
//! was reverse-engineered from the Nordic SDK (`sdk-nrf`), specifically:
//!   - `subsys/nrf_security/src/drivers/cracen/sxsymcrypt/*`
//!   - `subsys/nrf_security/src/drivers/cracen/cracenpsa/*`
#![no_std]
mod descriptor;

use descriptor::DescriptorChain;
use nrf_pac::{cracen, cracencore};

use crate::descriptor::sz;

/// Maximum number of descriptors in a single DMA input or output chain.
///
/// Four covers all cases for one hash chunk: config word + state + (optional
/// padding) + payload data.
const MAX_DESCRIPTOR_CHAIN_LEN: usize = 4;

/// Size of the SHA-256 internal state in bytes (256 bits ÷ 8).
const INTERNAL_STATE_LEN: usize = 32;

/// Sent as the first byte of the 4-byte config-word descriptor that opens
/// every DMA input chain. See the SHA-256 `sxhashalg` struct in
/// `sdk-nrf/.../sxsymcrypt/src/hash.c`.
const SHA256_BA413_MODE: u8 = 0x08;

/// DMA tag for the algorithm-configuration descriptor (BA413 hash engine).
///
/// Encoded as `DMATAG_BA413(3) | DMATAG_CONFIG(offset=0)(16) = 19`.
/// `DMATAG_CONFIG` (bit 4) marks this descriptor as carrying a hardware
/// configuration word rather than message data. Must be the first descriptor
/// in every input chain.
/// Source: `cmdma.h` — `DMATAG_BA413 = 3`, `DMATAG_CONFIG(o) = (1<<4)|(o<<8)`.
const DMATAG_BA413_CFG: u32 = 19;

/// DMA tag for the intermediate SHA-256 state (running-hash) descriptor.
///
/// Encoded as `DMATAG_BA413(3) | DMATAG_DATATYPE_HEADER(1<<6=64) |
/// DMATAG_LAST(1<<5=32) = 99`. `DATATYPE_HEADER` tells the BA413 engine this
/// buffer contains the running digest state for a mid-stream resume rather
/// than fresh message data. `LAST` signals no further header descriptors
/// follow before payload.
/// Source: `cmdma.h` — `DMATAG_DATATYPE_HEADER = (1<<6)`, `DMATAG_LAST = (1<<5)`.
const DMATAG_BA413_STATE: u32 = 99;

/// DMA tag for the final (or only) message-data descriptor (BA413 hash engine).
///
/// Encoded as `DMATAG_BA413(3) | DMATAG_LAST(1<<5=32) = 35`. `LAST` signals
/// to the cryptomaster that no further input descriptors follow in this chain.
/// Source: `cmdma.h` — `DMATAG_BA413 = 3`, `DMATAG_LAST = (1<<5)`.
const DMATAG_BA413_DATA_LAST: u32 = 35;

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
    // We could instead make this unconditional and then set state (in init) to 0x6a, 0x09, 0xe6,
    // 0x67, ... (the big-endian version of the SHA256 starting points 0x6a09e667u32), but the
    // hardware has the values, so why not use them.
    state: Option<[u8; 32]>,
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

impl embedded_cal::HashProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal::NoHashAlgorithms;
    type HashState = embedded_cal::NoHashAlgorithms;
    type HashResult = embedded_cal::NoHashAlgorithms;

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
    const SEND_PADDING: bool = true;
    const FIRST_CHUNK_SIZE: usize = 64;
    const UPDATE_MULTICHUNK: bool = true;

    type State = HashState;

    fn init(&mut self, variant: embedded_cal::plumbing::hash::Sha2ShortVariant) -> Self::State {
        match variant {
            embedded_cal::plumbing::hash::Sha2ShortVariant::Sha256 => (),
            // Although really all we need to support it is probably just copying the requested
            // length into the output buffer
            _ => todo!("Unsupported variant"),
        };

        Self::State { state: None }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        debug_assert!(
            data.len() % 64 == 0,
            "Chunking requirements laid out in Self::FIRST_CHUNK_SIZE not upheld."
        );

        let mut new_state: [u8; 32] = [0x00; 32];

        let header: [u8; 4] = [SHA256_BA413_MODE, 0x00, 0x00, 0x00];

        let state_len = INTERNAL_STATE_LEN;

        let mut output_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();
        output_descriptors.push(new_state.as_mut_ptr(), sz(state_len), 32);

        let mut input_descriptors = DescriptorChain::<MAX_DESCRIPTOR_CHAIN_LEN>::new();

        input_descriptors.push(header.as_ptr() as *mut u8, sz(4), DMATAG_BA413_CFG);

        if let Some(state) = &instance.state {
            input_descriptors.push(state.as_ptr() as *mut u8, sz(state_len), DMATAG_BA413_STATE);
        }

        input_descriptors.push(
            data.as_ptr() as *mut u8,
            sz(data.len()),
            DMATAG_BA413_DATA_LAST,
        );

        self.execute_cryptomaster_dma(&mut input_descriptors, &mut output_descriptors);

        instance.state = Some(new_state);
    }

    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]) {
        debug_assert!(
            last_chunk.is_empty(),
            "Self::SEND_PADDING=true requires user not to send any last chunk"
        );

        target.copy_from_slice(&instance.state.unwrap());
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
