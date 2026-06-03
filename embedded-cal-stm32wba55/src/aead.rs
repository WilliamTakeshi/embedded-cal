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

/// Feed one 16-byte block into the AES DINR and wait for CCF, then clear it.
fn feed_block(aes: &stm32_metapac::aes::Aes, block: &[u8; 16]) {
    for i in 0..4 {
        aes.dinr().write_value(u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]));
    }
    while !aes.isr().read().ccf() {}
    aes.isr().write(|w| w.set_ccf(true));
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
            AeadKey::AesCcm16_64_128(key_bytes) => {
                const TAG_LEN: usize = 8;
                let aes = &self.aes;

                // Total AAD length is needed for B0 Adata flag and B1 length prefix.
                let a_len: usize = aad.items().map(|s| s.len()).sum();

                // --- INIT PHASE ---
                aes.cr().modify(|w| w.set_en(false));
                aes.cr().modify(|w| {
                    w.set_chmod(Chmod::CCM);
                    w.set_datatype(Datatype::NONE);
                    w.set_keysize(false); // false = 128-bit key
                    w.set_mode(Mode::MODE1); // encrypt
                    w.set_kmod(0x00);
                    w.set_gcmph(Gcmph::INIT_PHASE);
                    w.set_npblb(0); // clear stale NPBLB from any previous operation
                });

                // Build B0: flags byte | nonce | Q (message length in L bytes)
                // For AES-CCM-16-64-128: nonce=13 bytes → L=2, M'=3 (tag=8 bytes)
                let mut b0 = [0u8; 16];
                let l = 15 - nonce.len();
                b0[0] = ((l - 1) as u8) | ((((TAG_LEN - 2) / 2) as u8) << 3);
                if a_len > 0 {
                    b0[0] |= 0x40;
                }
                b0[1..1 + nonce.len()].copy_from_slice(nonce);
                let msg_len_bytes = (message.len() as u64).to_be_bytes();
                b0[16 - l..].copy_from_slice(&msg_len_bytes[8 - l..]);

                aes.ivr(3)
                    .write_value(u32::from_be_bytes([b0[0], b0[1], b0[2], b0[3]]));
                aes.ivr(2)
                    .write_value(u32::from_be_bytes([b0[4], b0[5], b0[6], b0[7]]));
                aes.ivr(1)
                    .write_value(u32::from_be_bytes([b0[8], b0[9], b0[10], b0[11]]));
                aes.ivr(0)
                    .write_value(u32::from_be_bytes([b0[12], b0[13], b0[14], b0[15]]));

                aes.keyr(3).write_value(u32::from_be_bytes([
                    key_bytes[0],
                    key_bytes[1],
                    key_bytes[2],
                    key_bytes[3],
                ]));
                aes.keyr(2).write_value(u32::from_be_bytes([
                    key_bytes[4],
                    key_bytes[5],
                    key_bytes[6],
                    key_bytes[7],
                ]));
                aes.keyr(1).write_value(u32::from_be_bytes([
                    key_bytes[8],
                    key_bytes[9],
                    key_bytes[10],
                    key_bytes[11],
                ]));
                aes.keyr(0).write_value(u32::from_be_bytes([
                    key_bytes[12],
                    key_bytes[13],
                    key_bytes[14],
                    key_bytes[15],
                ]));

                while !aes.sr().read().keyvalid() {}
                aes.cr().modify(|w| w.set_en(true));
                while !aes.isr().read().ccf() {}
                aes.isr().write(|w| w.set_ccf(true));

                // --- HEADER PHASE ---
                // B1 = [len_hi, len_lo, aad...] zero-padded to 16-byte blocks.
                if a_len > 0 {
                    aes.cr().modify(|w| w.set_gcmph(Gcmph::HEADER_PHASE));
                    aes.cr().modify(|w| w.set_en(true));

                    let mut block = [0u8; 16];
                    // 2-byte length encoding (covers a_len < 0xFF00)
                    block[0] = (a_len >> 8) as u8;
                    block[1] = (a_len & 0xFF) as u8;
                    let mut pos = 2usize;

                    for slice in aad.items() {
                        let mut slice_offset = 0;
                        while slice_offset < slice.len() {
                            let n = (slice.len() - slice_offset).min(16 - pos);
                            block[pos..pos + n]
                                .copy_from_slice(&slice[slice_offset..slice_offset + n]);
                            pos += n;
                            slice_offset += n;
                            if pos == 16 {
                                feed_block(aes, &block);
                                block = [0u8; 16];
                                pos = 0;
                            }
                        }
                    }
                    if pos > 0 {
                        // Partial last block, already zero-padded by array initialization.
                        feed_block(aes, &block);
                    }
                }

                // --- PAYLOAD PHASE ---
                aes.cr().modify(|w| w.set_gcmph(Gcmph::PAYLOAD_PHASE));
                aes.cr().modify(|w| w.set_en(true));

                let msg_len = message.len();
                let mut msg_offset = 0;
                while msg_offset < msg_len {
                    let mut block = [0u8; 16];
                    let chunk = (msg_len - msg_offset).min(16);
                    block[..chunk].copy_from_slice(&message[msg_offset..msg_offset + chunk]);

                    for i in 0..4 {
                        aes.dinr().write_value(u32::from_be_bytes([
                            block[i * 4],
                            block[i * 4 + 1],
                            block[i * 4 + 2],
                            block[i * 4 + 3],
                        ]));
                    }
                    while !aes.isr().read().ccf() {}

                    for i in 0..4 {
                        let word: u32 = aes.doutr().read();
                        block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
                    }
                    aes.isr().write(|w| w.set_ccf(true));

                    message[msg_offset..msg_offset + chunk].copy_from_slice(&block[..chunk]);
                    msg_offset += chunk;
                }

                // --- FINAL PHASE ---
                aes.cr().modify(|w| w.set_gcmph(Gcmph::FINAL_PHASE));
                while !aes.isr().read().ccf() {}

                let mut tag_full = [0u8; 16];
                for i in 0..4 {
                    let word: u32 = aes.doutr().read();
                    tag_full[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
                }
                aes.isr().write(|w| w.set_ccf(true));
                aes.cr().modify(|w| w.set_en(false));

                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&tag_full[..TAG_LEN]);
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
            AeadKey::AesCcm16_64_128(key_bytes) => {
                const TAG_LEN: usize = 8;
                let aes = &self.aes;

                let a_len: usize = aad.items().map(|s| s.len()).sum();

                // --- INIT PHASE ---
                aes.cr().modify(|w| w.set_en(false));
                aes.cr().modify(|w| {
                    w.set_chmod(Chmod::CCM);
                    w.set_datatype(Datatype::NONE);
                    w.set_keysize(false);
                    w.set_mode(Mode::MODE3); // decrypt
                    w.set_kmod(0x00);
                    w.set_gcmph(Gcmph::INIT_PHASE);
                    w.set_npblb(0); // clear stale NPBLB from any previous operation
                });

                let mut b0 = [0u8; 16];
                let l = 15 - nonce.len();
                b0[0] = ((l - 1) as u8) | ((((TAG_LEN - 2) / 2) as u8) << 3);
                if a_len > 0 {
                    b0[0] |= 0x40;
                }
                b0[1..1 + nonce.len()].copy_from_slice(nonce);
                let msg_len_bytes = (message.len() as u64).to_be_bytes();
                b0[16 - l..].copy_from_slice(&msg_len_bytes[8 - l..]);

                aes.ivr(3).write_value(u32::from_be_bytes([b0[0], b0[1], b0[2], b0[3]]));
                aes.ivr(2).write_value(u32::from_be_bytes([b0[4], b0[5], b0[6], b0[7]]));
                aes.ivr(1).write_value(u32::from_be_bytes([b0[8], b0[9], b0[10], b0[11]]));
                aes.ivr(0).write_value(u32::from_be_bytes([b0[12], b0[13], b0[14], b0[15]]));

                aes.keyr(3).write_value(u32::from_be_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]));
                aes.keyr(2).write_value(u32::from_be_bytes([key_bytes[4], key_bytes[5], key_bytes[6], key_bytes[7]]));
                aes.keyr(1).write_value(u32::from_be_bytes([key_bytes[8], key_bytes[9], key_bytes[10], key_bytes[11]]));
                aes.keyr(0).write_value(u32::from_be_bytes([key_bytes[12], key_bytes[13], key_bytes[14], key_bytes[15]]));

                while !aes.sr().read().keyvalid() {}
                aes.cr().modify(|w| w.set_en(true));
                while !aes.isr().read().ccf() {}
                aes.isr().write(|w| w.set_ccf(true));

                // --- HEADER PHASE ---
                if a_len > 0 {
                    aes.cr().modify(|w| w.set_gcmph(Gcmph::HEADER_PHASE));
                    aes.cr().modify(|w| w.set_en(true));

                    let mut block = [0u8; 16];
                    block[0] = (a_len >> 8) as u8;
                    block[1] = (a_len & 0xFF) as u8;
                    let mut pos = 2usize;

                    for slice in aad.items() {
                        let mut slice_offset = 0;
                        while slice_offset < slice.len() {
                            let n = (slice.len() - slice_offset).min(16 - pos);
                            block[pos..pos + n].copy_from_slice(&slice[slice_offset..slice_offset + n]);
                            pos += n;
                            slice_offset += n;
                            if pos == 16 {
                                feed_block(aes, &block);
                                block = [0u8; 16];
                                pos = 0;
                            }
                        }
                    }
                    if pos > 0 {
                        feed_block(aes, &block);
                    }
                }

                // --- PAYLOAD PHASE ---
                aes.cr().modify(|w| w.set_gcmph(Gcmph::PAYLOAD_PHASE));
                aes.cr().modify(|w| w.set_en(true));

                let msg_len = message.len();
                let mut msg_offset = 0;
                while msg_offset < msg_len {
                    let mut block = [0u8; 16];
                    let chunk = (msg_len - msg_offset).min(16);
                    block[..chunk].copy_from_slice(&message[msg_offset..msg_offset + chunk]);

                    // NPBLB tells the hardware how many padding bytes to ignore in the
                    // CBC-MAC so the tag is not corrupted by the zero-padded CTR output.
                    let is_last = msg_offset + chunk >= msg_len;
                    if is_last && chunk < 16 {
                        aes.cr().modify(|w| w.set_npblb((16 - chunk) as u8));
                    }

                    for i in 0..4 {
                        aes.dinr().write_value(u32::from_be_bytes([
                            block[i * 4],
                            block[i * 4 + 1],
                            block[i * 4 + 2],
                            block[i * 4 + 3],
                        ]));
                    }
                    while !aes.isr().read().ccf() {}

                    for i in 0..4 {
                        let word: u32 = aes.doutr().read();
                        block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
                    }
                    aes.isr().write(|w| w.set_ccf(true));

                    message[msg_offset..msg_offset + chunk].copy_from_slice(&block[..chunk]);
                    msg_offset += chunk;
                }

                // --- FINAL PHASE ---
                aes.cr().modify(|w| w.set_gcmph(Gcmph::FINAL_PHASE));
                while !aes.isr().read().ccf() {}

                let mut tag_full = [0u8; 16];
                for i in 0..4 {
                    let word: u32 = aes.doutr().read();
                    tag_full[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
                }
                aes.isr().write(|w| w.set_ccf(true));
                aes.cr().modify(|w| w.set_en(false));

                let computed = &tag_full[..TAG_LEN];
                let tags_match = computed.len() == tag.len()
                    && computed.iter().zip(tag.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;

                if tags_match {
                    Ok(())
                } else {
                    Err(embedded_cal::DecryptionFailed)
                }
            }
            AeadKey::AesCcm16_64_256(_) => todo!(),
        }
    }
}
