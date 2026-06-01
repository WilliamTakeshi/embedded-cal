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
            AeadTag::AesCcm16_64_128(r) => r,
            AeadTag::AesCcm16_64_256(r) => r,
        }
    }
}

impl embedded_cal::AeadProvider for super::Stm32wba55Cal {
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
        use stm32_metapac::aes::vals::{Chmod, Datatype, Gcmph, Mode};

        match key {
            AeadKey::AesCcm16_64_128(key) => {
                // Collect AAD into a contiguous buffer.
                let mut aad_buf = [0u8; 255];
                let mut aad_len = 0usize;
                for chunk in aad.items() {
                    aad_buf[aad_len..aad_len + chunk.len()].copy_from_slice(chunk);
                    aad_len += chunk.len();
                }

                // Build B0 per RFC 3610 §2.2: L=2 (2-byte length field), M=8 (tag length).
                // flags = (has_aad << 6) | ((M-2)/2 << 3) | (L-1) = (has_aad << 6) | 0x19
                let flags = ((aad_len > 0) as u8) << 6 | 0x19;
                let mut b0 = [0u8; 16];
                b0[0] = flags;
                b0[1..14].copy_from_slice(nonce);
                b0[14] = (message.len() >> 8) as u8;
                b0[15] = message.len() as u8;

                // Reset, then configure for CCM encryption.
                self.aes.cr().write(|w| w.set_iprst(true));
                self.aes.cr().write(|w| w.set_iprst(false));
                self.aes.cr().write(|w| {
                    w.set_chmod(Chmod::CCM);
                    w.set_mode(Mode::MODE1); // encrypt
                    w.set_datatype(Datatype::NONE); // 32-bit words, no swap
                    w.set_keysize(false); // 128-bit key
                    w.set_gcmph(Gcmph::INIT_PHASE);
                });

                // Write 128-bit key; keyr[0] = MSW = key[0..4].
                for i in 0..4 {
                    self.aes.keyr(i).write_value(u32::from_be_bytes(
                        key[i * 4..i * 4 + 4].try_into().unwrap(),
                    ));
                }
                while !self.aes.sr().read().keyvalid() {}

                // Phase 0 — Init: write B0 to IVR, trigger.
                for i in 0..4 {
                    self.aes.ivr(i).write_value(u32::from_be_bytes(
                        b0[i * 4..i * 4 + 4].try_into().unwrap(),
                    ));
                }
                self.aes.cr().modify(|w| w.set_en(true));
                while self.aes.sr().read().busy() {}

                // Phase 1 — Header: encode AAD as [len_hi, len_lo, aad...], padded to 16.
                if aad_len > 0 {
                    self.aes.cr().modify(|w| w.set_gcmph(Gcmph::HEADER_PHASE));

                    let header_total = 2 + aad_len;
                    let header_padded = (header_total + 15) / 16 * 16;
                    // max: 2-byte length + 255 bytes AAD + 15 bytes padding = 272
                    let mut header = [0u8; 272];
                    header[0] = (aad_len >> 8) as u8;
                    header[1] = aad_len as u8;
                    header[2..2 + aad_len].copy_from_slice(&aad_buf[..aad_len]);

                    for chunk in header[..header_padded].chunks_exact(4) {
                        self.aes
                            .dinr()
                            .write_value(u32::from_be_bytes(chunk.try_into().unwrap()));
                    }
                    while self.aes.sr().read().busy() {}
                }

                // Phase 2 — Payload: encrypt message in-place, one 16-byte block at a time.
                if !message.is_empty() {
                    self.aes.cr().modify(|w| w.set_gcmph(Gcmph::PAYLOAD_PHASE));

                    let msg_len = message.len();
                    let mut offset = 0usize;
                    while offset < msg_len {
                        let block_end = (offset + 16).min(msg_len);

                        // Set NPBLB before the last partial block so the hardware
                        // pads the CBC-MAC correctly without encrypting the padding.
                        if block_end == msg_len {
                            let remainder = msg_len % 16;
                            if remainder != 0 {
                                self.aes
                                    .cr()
                                    .modify(|w| w.set_npblb((16 - remainder) as u8));
                            }
                        }

                        // Zero-pad plaintext block to 16 bytes and write to DINR.
                        let mut block = [0u8; 16];
                        block[..block_end - offset].copy_from_slice(&message[offset..block_end]);
                        for i in 0..4 {
                            self.aes.dinr().write_value(u32::from_be_bytes(
                                block[i * 4..i * 4 + 4].try_into().unwrap(),
                            ));
                        }
                        while self.aes.sr().read().busy() {}

                        // Read 4 output words; only copy the valid bytes back.
                        for i in 0..4 {
                            let bytes = self.aes.doutr().read().to_be_bytes();
                            let dst_start = offset + i * 4;
                            let dst_end = (dst_start + 4).min(msg_len);
                            if dst_start < dst_end {
                                message[dst_start..dst_end]
                                    .copy_from_slice(&bytes[..dst_end - dst_start]);
                            }
                        }

                        offset = block_end;
                    }
                }

                // Phase 3 — Final: produce tag.
                self.aes.cr().modify(|w| w.set_gcmph(Gcmph::FINAL_PHASE));
                self.aes.cr().modify(|w| w.set_en(true));
                while self.aes.sr().read().busy() {}

                // Tag occupies ivr[0] (bytes 0..4) and ivr[1] (bytes 4..8).
                let mut tag = [0u8; 8];
                tag[0..4].copy_from_slice(&self.aes.ivr(0).read().to_be_bytes());
                tag[4..8].copy_from_slice(&self.aes.ivr(1).read().to_be_bytes());

                self.aes.cr().modify(|w| w.set_en(false));

                AeadTag::AesCcm16_64_128(tag)
            }
            AeadKey::AesCcm16_64_256(_) => todo!(),
        }
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        use stm32_metapac::aes::vals::{Chmod, Datatype, Gcmph, Mode};

        match key {
            AeadKey::AesCcm16_64_128(key) => {
                let mut aad_buf = [0u8; 255];
                let mut aad_len = 0usize;
                for chunk in aad.items() {
                    aad_buf[aad_len..aad_len + chunk.len()].copy_from_slice(chunk);
                    aad_len += chunk.len();
                }

                let flags = ((aad_len > 0) as u8) << 6 | 0x19;
                let mut b0 = [0u8; 16];
                b0[0] = flags;
                b0[1..14].copy_from_slice(nonce);
                b0[14] = (message.len() >> 8) as u8;
                b0[15] = message.len() as u8;

                self.aes.cr().write(|w| w.set_iprst(true));
                self.aes.cr().write(|w| w.set_iprst(false));
                self.aes.cr().write(|w| {
                    w.set_chmod(Chmod::CCM);
                    w.set_mode(Mode::MODE3); // decrypt
                    w.set_datatype(Datatype::NONE);
                    w.set_keysize(false);
                    w.set_gcmph(Gcmph::INIT_PHASE);
                });

                for i in 0..4 {
                    self.aes.keyr(i).write_value(u32::from_be_bytes(
                        key[i * 4..i * 4 + 4].try_into().unwrap(),
                    ));
                }
                while !self.aes.sr().read().keyvalid() {}

                // Phase 0 — Init
                for i in 0..4 {
                    self.aes.ivr(i).write_value(u32::from_be_bytes(
                        b0[i * 4..i * 4 + 4].try_into().unwrap(),
                    ));
                }
                self.aes.cr().modify(|w| w.set_en(true));
                while self.aes.sr().read().busy() {}

                // Phase 1 — Header
                if aad_len > 0 {
                    self.aes.cr().modify(|w| w.set_gcmph(Gcmph::HEADER_PHASE));

                    let header_total = 2 + aad_len;
                    let header_padded = (header_total + 15) / 16 * 16;
                    let mut header = [0u8; 272];
                    header[0] = (aad_len >> 8) as u8;
                    header[1] = aad_len as u8;
                    header[2..2 + aad_len].copy_from_slice(&aad_buf[..aad_len]);

                    for chunk in header[..header_padded].chunks_exact(4) {
                        self.aes
                            .dinr()
                            .write_value(u32::from_be_bytes(chunk.try_into().unwrap()));
                    }
                    while self.aes.sr().read().busy() {}
                }

                // Phase 2 — Payload: decrypt in-place
                if !message.is_empty() {
                    self.aes.cr().modify(|w| w.set_gcmph(Gcmph::PAYLOAD_PHASE));

                    let msg_len = message.len();
                    let mut offset = 0usize;
                    while offset < msg_len {
                        let block_end = (offset + 16).min(msg_len);

                        if block_end == msg_len {
                            let remainder = msg_len % 16;
                            if remainder != 0 {
                                self.aes
                                    .cr()
                                    .modify(|w| w.set_npblb((16 - remainder) as u8));
                            }
                        }

                        let mut block = [0u8; 16];
                        block[..block_end - offset].copy_from_slice(&message[offset..block_end]);
                        for i in 0..4 {
                            self.aes.dinr().write_value(u32::from_be_bytes(
                                block[i * 4..i * 4 + 4].try_into().unwrap(),
                            ));
                        }
                        while self.aes.sr().read().busy() {}

                        for i in 0..4 {
                            let bytes = self.aes.doutr().read().to_be_bytes();
                            let dst_start = offset + i * 4;
                            let dst_end = (dst_start + 4).min(msg_len);
                            if dst_start < dst_end {
                                message[dst_start..dst_end]
                                    .copy_from_slice(&bytes[..dst_end - dst_start]);
                            }
                        }

                        offset = block_end;
                    }
                }

                // Phase 3 — Final: compute tag over the decrypted payload
                self.aes.cr().modify(|w| w.set_gcmph(Gcmph::FINAL_PHASE));
                self.aes.cr().modify(|w| w.set_en(true));
                while self.aes.sr().read().busy() {}

                let mut computed_tag = [0u8; 8];
                computed_tag[0..4].copy_from_slice(&self.aes.ivr(0).read().to_be_bytes());
                computed_tag[4..8].copy_from_slice(&self.aes.ivr(1).read().to_be_bytes());

                self.aes.cr().modify(|w| w.set_en(false));

                // Constant-time comparison to prevent timing side-channels.
                let mut diff = 0u8;
                for (a, b) in computed_tag.iter().zip(tag.iter()) {
                    diff |= a ^ b;
                }
                // Unlike the nRF54 implementation (which decrypts into a temporary
                // buffer and only copies to `message` after verification), plaintext
                // is written directly to `message` during Phase 2. Zero it on failure
                // so unauthenticated plaintext is never visible to the caller.
                if diff != 0 {
                    message.fill(0);
                    return Err(embedded_cal::DecryptionFailed);
                }

                Ok(())
            }
            AeadKey::AesCcm16_64_256(_) => todo!(),
        }
    }
}
