/// A single entry in the CCM DMA job list.
///
/// The hardware walks a null-terminated array of these to locate each logical
/// piece of the CCM input or output (lengths, AAD, message data). The layout
/// is dictated by the CRACEN hardware ABI and must remain `#[repr(C, packed)]`.
/// `ptr` is stored as `u32` because the hardware register holds a 32-bit address.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct EcbJob {
    ptr: u32,
    attr_and_len: [u8; 4], // [len_lo, len_mid, len_hi, attr]
}

/// Attribute tags that identify the role of each [`EcbJob`] to the hardware.
///
/// The discriminant values are fixed by the CRACEN CCM peripheral specification.
#[repr(u8)]
enum EcbJobAttr {
    /// Length of the AAD in bytes.
    Alen = 11,
    /// Length of the message (plaintext or ciphertext, excluding tag) in bytes.
    Mlen = 12,
    /// AAD payload bytes.
    Adata = 13,
    /// Message payload bytes (plaintext for encrypt; ciphertext+tag for decrypt).
    Mdata = 14,
}

impl EcbJob {
    fn new(ptr: *const u8, length: u8, tag: EcbJobAttr) -> Self {
        EcbJob {
            ptr: ptr as u32,
            attr_and_len: [length, 0, 0, tag as u8],
        }
    }
    const fn zero() -> Self {
        EcbJob {
            ptr: 0,
            attr_and_len: [0; 4],
        }
    }
}

// ── BA411E AES engine — cryptomaster DMA tags and command words ──────────────────────────────────
//
// Sources: sdk-nrf subsys/nrf_security/src/drivers/cracen/sxsymcrypt/src/{cmdma.h,cmaes.h,aead.c}
//
// DMATAG layout (input descriptors only; the pusher ignores dmatag on output descriptors):
//   bits [3:0]  — engine selector  (DMATAG_BA411 = 1)
//   bit    [4]  — config-register write flag  (DMATAG_CONFIG sets this)
//   bit    [6]  — header/AAD data type flag   (DMATAG_DATATYPE_HEADER)
//   bits [12:8] — trailing padding bytes to ignore  (DMATAG_IGN, see descriptor::dmatag_ign)
//   bits [15:8] — config register offset when bit 4 is set

const DMATAG_BA411: u32 = 1;

// Config-register descriptors (bit 4 set; register offset in bits [15:8]):
const DMATAG_AES_CFG: u32 = DMATAG_BA411 | (1 << 4); // offset 0x00 → 0x0011
const DMATAG_AES_KEY: u32 = DMATAG_BA411 | (1 << 4) | (0x08 << 8); // offset 0x08 → 0x0811

// Data descriptors:
const DMATAG_AES_AAD: u32 = DMATAG_BA411 | (1 << 6); // DATATYPE_HEADER → 0x0041
const DMATAG_AES_DATA: u32 = DMATAG_BA411; // plaintext / ciphertext / tag → 0x0001

// Command words written as the first input descriptor (dmatag = DMATAG_AES_CFG):
//   bits [15:8] — mode: 1 << (8 + mode_id); CCM mode_id = 5 → bit 13 → 0x2000
//   bit     [0] — direction: 0 = encrypt, 1 = decrypt
// Key size is NOT encoded here — the BA411E infers it from the byte count of the
// key descriptor (16 bytes → AES-128, 32 bytes → AES-256).
const AES_CCM_MODE: u32 = 1 << 13; // CMDMA_AEAD_MODE_SET(5)
const AES_CMD_CCM_256_ENCRYPT: u32 = AES_CCM_MODE; // 0x2000
const AES_CMD_CCM_256_DECRYPT: u32 = AES_CCM_MODE | 1; // 0x2001

use crate::descriptor::{DescriptorChain, Input, Output, dmatag_ign};

fn collect_aad(aad: impl embedded_cal::AadGenerator) -> ([u8; 255], usize) {
    let mut buf = [0u8; 255];
    let mut len: usize = 0;
    for chunk in aad.items() {
        buf[len..len + chunk.len()].copy_from_slice(chunk);
        len += chunk.len();
    }
    (buf, len)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    AesCcm16_64_128,
    AesCcm16_64_256,
}

impl embedded_cal::AeadAlgorithm for AeadAlgorithm {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 16,
            AeadAlgorithm::AesCcm16_64_256 => 32,
        }
    }

    fn tag_length(&self) -> usize {
        8
    }

    fn nonce_length(&self) -> usize {
        13
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            10 => Some(AeadAlgorithm::AesCcm16_64_128),
            11 => Some(AeadAlgorithm::AesCcm16_64_256),
            _ => None,
        }
    }
}

pub enum AeadKey {
    AesCcm16_64_128([u8; 16]),
    AesCcm16_64_256([u8; 32]),
}

pub enum AeadTag {
    AesCcm16_64_128([u8; 8]),
    AesCcm16_64_256([u8; 8]),
}

impl AsRef<[u8]> for AeadTag {
    fn as_ref(&self) -> &[u8] {
        match self {
            AeadTag::AesCcm16_64_128(r) => &r[..],
            AeadTag::AesCcm16_64_256(r) => &r[..],
        }
    }
}

impl super::Nrf54l15Cal {
    fn ccm_run(&mut self) -> bool {
        use nrf_pac::ccm::vals;
        self.ccm.tasks_start().write_value(1);
        while self.ccm.events_end().read() == 0 {}
        self.ccm.events_end().write_value(0);
        self.ccm.macstatus().read().macstatus() == vals::Macstatus::CHECK_PASSED
    }

    fn ccm_setup(&mut self, mode: nrf_pac::ccm::vals::Mode) {
        use nrf_pac::ccm::vals;
        self.ccm
            .enable()
            .write(|w| w.set_enable(vals::Enable::ENABLED));
        // For non-BT protocols, adatamask must be 0xFF
        self.ccm.adatamask().write(|w| w.set_adatamask(0xFF));
        self.ccm.mode().write(|w| {
            w.set_mode(mode);
            w.set_maclen(vals::Maclen::M8);
            w.set_protocol(vals::Protocol::IEEE802154);
        });
    }

    fn ccm_write_nonce(&mut self, nonce: &[u8]) {
        self.ccm
            .nonce()
            .value(0)
            .write_value(u32::from_be_bytes(nonce[9..].try_into().unwrap()));
        self.ccm
            .nonce()
            .value(1)
            .write_value(u32::from_be_bytes(nonce[5..9].try_into().unwrap()));
        self.ccm
            .nonce()
            .value(2)
            .write_value(u32::from_be_bytes(nonce[1..5].try_into().unwrap()));
        self.ccm
            .nonce()
            .value(3)
            .write_value(u32::from_be_bytes([0, 0, 0, nonce[0]]));
    }

    fn ccm_write_key(&mut self, key: &[u8; 16]) {
        self.ccm
            .key()
            .value(0)
            .write_value(u32::from_be_bytes(key[12..16].try_into().unwrap()));
        self.ccm
            .key()
            .value(1)
            .write_value(u32::from_be_bytes(key[8..12].try_into().unwrap()));
        self.ccm
            .key()
            .value(2)
            .write_value(u32::from_be_bytes(key[4..8].try_into().unwrap()));
        self.ccm
            .key()
            .value(3)
            .write_value(u32::from_be_bytes(key[0..4].try_into().unwrap()));
    }

    fn ccm256_encrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8],
        message: &mut [u8],
        aad: &[u8],
    ) -> [u8; 8] {
        const TAG_LEN: usize = 8;
        let cmd = AES_CMD_CCM_256_ENCRYPT.to_le_bytes();

        // Header = B0 (16 B) + [aad_len_be (2 B) + aad] when AAD present,
        // zero-padded to the next 16-byte multiple.
        // Max size: 16 + 2 + 255 = 273 → pads to 288.
        let b0 = embedded_cal::build_b0(nonce, message.len(), aad.len(), TAG_LEN);
        let mut header_buf = [0u8; 288];
        let header_data_len = if aad.is_empty() {
            header_buf[..16].copy_from_slice(&b0);
            16
        } else {
            header_buf[..16].copy_from_slice(&b0);
            header_buf[16] = (aad.len() >> 8) as u8;
            header_buf[17] = (aad.len() & 0xFF) as u8;
            header_buf[18..18 + aad.len()].copy_from_slice(aad);
            18 + aad.len()
        };
        let header_padded_len = (header_data_len + 15) & !15;
        let header_ign = header_padded_len - header_data_len;

        // Plaintext, zero-padded to 16-byte multiple; max 255 B → 256 B.
        let msg_padded_len = (message.len() + 15) & !15;
        let msg_ign = msg_padded_len - message.len();
        let mut msg_in_buf = [0u8; 256];
        msg_in_buf[..message.len()].copy_from_slice(message);

        let mut ct_buf = [0u8; 256];
        let mut tag_out_buf = [0u8; 16];
        // The BA411E emits one output byte per header input byte (intermediate
        // CBC-MAC state). Absorb those into a scratch buffer so that ct_buf and
        // tag_out_buf receive the correct ciphertext and tag.
        let mut header_out_buf = [0u8; 288];

        let mut input_chain: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        let mut output_chain: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();

        input_chain.push(&cmd, DMATAG_AES_CFG);
        input_chain.push(key, DMATAG_AES_KEY);
        input_chain.push(
            &header_buf[..header_padded_len],
            DMATAG_AES_AAD | dmatag_ign(header_ign),
        );
        if !message.is_empty() {
            input_chain.push(
                &msg_in_buf[..msg_padded_len],
                DMATAG_AES_DATA | dmatag_ign(msg_ign),
            );
        }
        output_chain.push(&mut header_out_buf[..header_padded_len], 0);
        if !message.is_empty() {
            output_chain.push(&mut ct_buf[..msg_padded_len], 0);
        }
        output_chain.push(&mut tag_out_buf, 0);

        self.execute_cryptomaster_dma(&mut input_chain, &mut output_chain);

        message.copy_from_slice(&ct_buf[..message.len()]);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&tag_out_buf[..TAG_LEN]);
        tag
    }

    fn ccm256_decrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8],
        ciphertext: &mut [u8],
        tag_in: &[u8],
        aad: &[u8],
    ) -> bool {
        const TAG_LEN: usize = 8;
        let cmd = AES_CMD_CCM_256_DECRYPT.to_le_bytes();

        let b0 = embedded_cal::build_b0(nonce, ciphertext.len(), aad.len(), TAG_LEN);
        let mut header_buf = [0u8; 288];
        let header_data_len = if aad.is_empty() {
            header_buf[..16].copy_from_slice(&b0);
            16
        } else {
            header_buf[..16].copy_from_slice(&b0);
            header_buf[16] = (aad.len() >> 8) as u8;
            header_buf[17] = (aad.len() & 0xFF) as u8;
            header_buf[18..18 + aad.len()].copy_from_slice(aad);
            18 + aad.len()
        };
        let header_padded_len = (header_data_len + 15) & !15;
        let header_ign = header_padded_len - header_data_len;

        let ct_padded_len = (ciphertext.len() + 15) & !15;
        let ct_ign = ct_padded_len - ciphertext.len();
        let mut ct_in_buf = [0u8; 256];
        ct_in_buf[..ciphertext.len()].copy_from_slice(ciphertext);

        // Expected tag padded to 16 B; engine outputs XOR(computed_tag, expected_tag).
        // All-zero output means the tags match.
        let mut tag_in_buf = [0u8; 16];
        tag_in_buf[..TAG_LEN].copy_from_slice(&tag_in[..TAG_LEN]);

        let mut pt_buf = [0u8; 256];
        let mut xor_tag_buf = [0u8; 16];
        let mut header_out_buf = [0u8; 288];

        let mut input_chain: DescriptorChain<Input, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();
        let mut output_chain: DescriptorChain<Output, { super::MAX_DESCRIPTOR_CHAIN_LEN }> =
            DescriptorChain::new();

        input_chain.push(&cmd, DMATAG_AES_CFG);
        input_chain.push(key, DMATAG_AES_KEY);
        input_chain.push(
            &header_buf[..header_padded_len],
            DMATAG_AES_AAD | dmatag_ign(header_ign),
        );
        if !ciphertext.is_empty() {
            input_chain.push(
                &ct_in_buf[..ct_padded_len],
                DMATAG_AES_DATA | dmatag_ign(ct_ign),
            );
        }
        input_chain.push(&tag_in_buf, DMATAG_AES_DATA | dmatag_ign(16 - TAG_LEN));
        output_chain.push(&mut header_out_buf[..header_padded_len], 0);
        if !ciphertext.is_empty() {
            output_chain.push(&mut pt_buf[..ct_padded_len], 0);
        }
        output_chain.push(&mut xor_tag_buf, 0);

        self.execute_cryptomaster_dma(&mut input_chain, &mut output_chain);

        let mac_ok = xor_tag_buf[..TAG_LEN].iter().all(|&b| b == 0);
        if mac_ok {
            ciphertext.copy_from_slice(&pt_buf[..ciphertext.len()]);
        }
        mac_ok
    }
}

impl embedded_cal::AeadProvider for super::Nrf54l15Cal {
    type Algorithm = AeadAlgorithm;
    type Key = AeadKey;
    type Tag = AeadTag;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        match alg {
            AeadAlgorithm::AesCcm16_64_128 => {
                AeadKey::AesCcm16_64_128(key.try_into().expect("key length mismatch"))
            }
            AeadAlgorithm::AesCcm16_64_256 => {
                AeadKey::AesCcm16_64_256(key.try_into().expect("key length mismatch"))
            }
        }
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        use nrf_pac::ccm::vals;

        match *key {
            AeadKey::AesCcm16_64_128(key) => {
                self.ccm_setup(vals::Mode::ENCRYPTION);

                let (aad_input_buf, aad_len) = collect_aad(aad);

                let alen_input_buf = (aad_len as u32).to_le_bytes();
                let mlen_input_buf = (message.len() as u32).to_le_bytes();

                let mut input_jobs = [
                    EcbJob::new(alen_input_buf.as_ptr(), 2, EcbJobAttr::Alen),
                    EcbJob::new(mlen_input_buf.as_ptr(), 2, EcbJobAttr::Mlen),
                    EcbJob::new(aad_input_buf.as_ptr(), aad_len as u8, EcbJobAttr::Adata),
                    EcbJob::new(message.as_ptr(), message.len() as u8, EcbJobAttr::Mdata),
                    EcbJob::zero(),
                ];

                let alen_output_buf = (aad_len as u32).to_le_bytes();
                let mlen_output_buf = (message.len() as u32).to_le_bytes();
                let aad_output_buf = [0x00; 256];
                let mut output_buf = [0x00; 256];

                let mut output_jobs = [
                    EcbJob::new(alen_output_buf.as_ptr(), 2, EcbJobAttr::Alen),
                    EcbJob::new(mlen_output_buf.as_ptr(), 2, EcbJobAttr::Mlen),
                    EcbJob::new(aad_output_buf.as_ptr(), aad_len as u8, EcbJobAttr::Adata),
                    EcbJob::new(
                        output_buf.as_mut_ptr(),
                        (message.len() + 8) as u8,
                        EcbJobAttr::Mdata,
                    ),
                    EcbJob::zero(),
                ];

                let input_jobs_ptr = core::ptr::addr_of_mut!(input_jobs) as u32;
                let output_jobs_ptr = core::ptr::addr_of_mut!(output_jobs) as u32;

                self.ccm_write_key(&key);
                self.ccm_write_nonce(nonce);

                self.ccm.in_().ptr().write_value(input_jobs_ptr);
                self.ccm.out().ptr().write_value(output_jobs_ptr);

                self.ccm_run();
                self.ccm
                    .enable()
                    .write(|w| w.set_enable(vals::Enable::DISABLED));

                let mut tag = [0u8; 8];
                message.copy_from_slice(&output_buf[..message.len()]);
                tag.copy_from_slice(&output_buf[message.len()..message.len() + 8]);
                AeadTag::AesCcm16_64_128(tag)
            }
            AeadKey::AesCcm16_64_256(key_bytes) => {
                let (aad_buf, aad_len) = collect_aad(aad);
                let tag = self.ccm256_encrypt(&key_bytes, nonce, message, &aad_buf[..aad_len]);
                AeadTag::AesCcm16_64_256(tag)
            }
        }
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        cyphertext: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        use nrf_pac::ccm::vals;

        match *key {
            AeadKey::AesCcm16_64_128(key) => {
                self.ccm_setup(vals::Mode::FAST_DECRYPTION);

                let (aad_buf, aad_len) = collect_aad(aad);

                let alen_input_buf = (aad_len as u32).to_le_bytes();
                let ciphertext_tag_len = cyphertext.len() + 8;
                let mlen_input_buf = (ciphertext_tag_len as u32).to_le_bytes();

                let mut ciphertext_tag_buf = [0u8; 256];
                ciphertext_tag_buf[..cyphertext.len()].copy_from_slice(cyphertext);
                ciphertext_tag_buf[cyphertext.len()..ciphertext_tag_len].copy_from_slice(tag);

                let mut input_jobs: [EcbJob; 5] = [
                    EcbJob::new(alen_input_buf.as_ptr(), 2, EcbJobAttr::Alen),
                    EcbJob::new(mlen_input_buf.as_ptr(), 2, EcbJobAttr::Mlen),
                    EcbJob::new(aad_buf.as_ptr(), aad_len as u8, EcbJobAttr::Adata),
                    EcbJob::new(
                        ciphertext_tag_buf.as_ptr(),
                        ciphertext_tag_len as u8,
                        EcbJobAttr::Mdata,
                    ),
                    EcbJob::zero(),
                ];

                let alen_output_buf = (aad_len as u32).to_le_bytes();
                let mlen_output_buf = (cyphertext.len() as u32).to_le_bytes();
                let aad_out_buf = [0u8; 255];
                let mut plaintext_buf = [0u8; 263];

                // Decrypt output mirrors encrypt INPUT order: Adata=AAD, Mdata=plaintext.
                let mut output_jobs: [EcbJob; 5] = [
                    EcbJob::new(alen_output_buf.as_ptr(), 2, EcbJobAttr::Alen),
                    EcbJob::new(mlen_output_buf.as_ptr(), 2, EcbJobAttr::Mlen),
                    EcbJob::new(aad_out_buf.as_ptr(), aad_len as u8, EcbJobAttr::Adata),
                    EcbJob::new(
                        plaintext_buf.as_mut_ptr(),
                        cyphertext.len() as u8,
                        EcbJobAttr::Mdata,
                    ),
                    EcbJob::zero(),
                ];

                let input_jobs_ptr = core::ptr::addr_of_mut!(input_jobs) as u32;
                let output_jobs_ptr = core::ptr::addr_of_mut!(output_jobs) as u32;

                self.ccm_write_key(&key);
                self.ccm_write_nonce(nonce);

                self.ccm.in_().ptr().write_value(input_jobs_ptr);
                self.ccm.out().ptr().write_value(output_jobs_ptr);

                let mac_ok = self.ccm_run();
                self.ccm
                    .enable()
                    .write(|w| w.set_enable(vals::Enable::DISABLED));

                if !mac_ok {
                    return Err(embedded_cal::DecryptionFailed);
                }

                // Message should only be copied after the verification
                cyphertext.copy_from_slice(&plaintext_buf[..cyphertext.len()]);
                Ok(())
            }
            AeadKey::AesCcm16_64_256(key_bytes) => {
                let (aad_buf, aad_len) = collect_aad(aad);
                if self.ccm256_decrypt(&key_bytes, nonce, cyphertext, tag, &aad_buf[..aad_len]) {
                    Ok(())
                } else {
                    Err(embedded_cal::DecryptionFailed)
                }
            }
        }
    }
}
