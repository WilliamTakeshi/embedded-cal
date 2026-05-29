// FIXME: ADD DOCS
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct EcbJob {
    ptr: u32,
    attr_and_len: [u8; 4], // [len_lo, len_mid, len_hi, attr]
}

#[repr(u8)]
enum EcbJobAttr {
    Alen = 11,
    Mlen = 12,
    Adata = 13,
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
                self.ccm
                    .enable()
                    .write(|w| w.set_enable(vals::Enable::ENABLED));
                // For non-BT protocols, adatamask must be 0xFF
                self.ccm.adatamask().write(|w| w.set_adatamask(0xFF));
                self.ccm.mode().write(|w| {
                    w.set_mode(vals::Mode::ENCRYPTION);
                    w.set_maclen(vals::Maclen::M8);
                    w.set_protocol(vals::Protocol::IEEE802154);
                });

                // Collect AAD and compute its actual length
                let mut aad_input_buf = [0u8; 255];
                let mut aad_len: usize = 0;
                for chunk in aad.items() {
                    aad_input_buf[aad_len..aad_len + chunk.len()].copy_from_slice(chunk);
                    aad_len += chunk.len();
                }

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

                self.ccm.in_().ptr().write_value(input_jobs_ptr);
                self.ccm.out().ptr().write_value(output_jobs_ptr);

                self.ccm.tasks_start().write_value(1);

                while self.ccm.events_end().read() == 0 {}
                self.ccm.events_end().write_value(0); // clear event

                self.ccm
                    .enable()
                    .write(|w| w.set_enable(vals::Enable::DISABLED));

                let mut tag = [0u8; 8];
                message.copy_from_slice(&output_buf[..message.len()]);
                tag.copy_from_slice(&output_buf[message.len()..message.len() + 8]);
                AeadTag::AesCcm16_64_128(tag)
            }
            AeadKey::AesCcm16_64_256(_) => todo!(),
        }
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _tag: &[u8],
        _aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        match *key {
            AeadKey::AesCcm16_64_128(_) => todo!(),
            AeadKey::AesCcm16_64_256(_) => todo!(),
        }
    }
}
