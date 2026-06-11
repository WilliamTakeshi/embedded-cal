mod aead;
mod dh;
mod hash;
mod rng;

use digest::Digest;

pub struct RustcryptoCal {
    #[cfg(not(feature = "alloc"))]
    aead_buffer: [u8; 1024],
    _private: (),
    empty: embedded_cal::empty::EmptyCal<false>,
}

impl RustcryptoCal {
    pub const fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            aead_buffer: [0; _],
            _private: (),
            empty: embedded_cal::empty::EmptyCal,
        }
    }

    fn collect_aad(&mut self, aad: impl embedded_cal::AadGenerator) -> impl AsRef<[u8]> {
        #[cfg(feature = "alloc")]
        {
            aad.items().flatten().copied().collect::<Vec<_>>()
        }

        #[cfg(not(feature = "alloc"))]
        {
            let mut cursor = 0;
            for slice in aad.items() {
                self.aead_buffer[cursor..][..slice.len()].copy_from_slice(slice);
                cursor += slice.len();
            }
            &self.aead_buffer[..cursor]
        }
    }
}

impl Default for RustcryptoCal {
    fn default() -> Self {
        Self::new()
    }
}

impl embedded_cal::Cal for RustcryptoCal {
    type DhProvider = Self;
    type AeadProvider = Self;
    type HashProvider = Self;
    type HmacProvider = embedded_cal::empty::EmptyCal<false>;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self
    }
    fn aead(&mut self) -> &mut Self::AeadProvider {
        self
    }
    fn hash(&mut self) -> &mut Self::HashProvider {
        self
    }
    fn hmac(&mut self) -> &mut Self::HmacProvider {
        &mut self.empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_sha256() {
        let mut cal = RustcryptoCal::new();

        embedded_cal::test_hash_algorithm_sha256::<
            <RustcryptoCal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut cal);
    }

    #[test]
    fn test_aead_aesccm_16_64_128() {
        let mut cal = RustcryptoCal::new();

        testvectors::test_aead_aesccm_16_64_128(&mut cal);
    }

    #[test]
    fn test_dh() {
        use embedded_cal::DhAlgorithm;

        let mut cal = RustcryptoCal::new();

        embedded_cal::test_dh_algorithm_ecdh_p256::<RustcryptoCal>();

        // For lack of loading, we only run a live test

        let p256 = DhAlgorithm::from_cose_ecdh(1).unwrap();
        let x25519 = DhAlgorithm::from_cose_ecdh(4).unwrap();

        embedded_cal::test_dh_selftest(&mut cal, p256);
        embedded_cal::test_dh_selftest(&mut cal, x25519);

        for vec in testvectors::dh::RFC7748_X25519 {
            vec.test_with(&mut cal);
        }

        for vec in testvectors::dh::RFC5903_P256 {
            vec.test_with(&mut cal);
        }
    }

    #[test]
    fn test_aead_aesccm_16_64_256() {
        let mut cal = RustcryptoCal::new();

        testvectors::test_aead_aesccm_16_64_256(&mut cal);
    }
}
