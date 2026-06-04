use digest::Digest;

pub struct RustcryptoCal {
    #[cfg(not(feature = "alloc"))]
    aead_buffer: [u8; 1024],
    _private: (),
}

impl RustcryptoCal {
    pub const fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            aead_buffer: [0; _],
            _private: (),
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

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HashAlgorithm {
    Sha256,
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
        }
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            -16 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub enum HashState {
    Sha256(sha2::Sha256),
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

impl embedded_cal::HashProvider for RustcryptoCal {
    type Algorithm = HashAlgorithm;
    type HashState = HashState;
    type HashResult = HashResult;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {
            // Same for any, really
            HashAlgorithm::Sha256 => HashState::Sha256(Default::default()),
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        match instance {
            // Same for any, really
            HashState::Sha256(s) => s.update(data),
        }
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {
            // Same for any, really
            HashState::Sha256(s) => HashResult::Sha256(s.finalize().into()),
        }
    }
}

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    AesCcm16_64_128,
}

impl embedded_cal::AeadAlgorithm for AeadAlgorithm {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 16,
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 8,
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 13,
        }
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            10 => Some(AeadAlgorithm::AesCcm16_64_128),
            _ => None,
        }
    }
}

pub enum AeadKey {
    AesCcm16_64_128([u8; 16]),
}

pub enum AeadTag {
    AesCcm16_128_128([u8; 8]),
}

impl AsRef<[u8]> for AeadTag {
    fn as_ref(&self) -> &[u8] {
        match self {
            AeadTag::AesCcm16_128_128(t) => t,
        }
    }
}

impl embedded_cal::AeadProvider for RustcryptoCal {
    type Algorithm = AeadAlgorithm;
    type Key = AeadKey;
    type Tag = AeadTag;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        match alg {
            AeadAlgorithm::AesCcm16_64_128 => {
                AeadKey::AesCcm16_64_128(key.try_into().expect("key length mismatch"))
            }
        }
    }

    #[allow(
        clippy::unnecessary_fallible_conversions,
        reason = "GenericArray has infallible conversions but they panic"
    )]
    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        use ccm::{AeadInPlace, KeyInit};
        let aad_linear = self.collect_aad(aad);
        match key {
            AeadKey::AesCcm16_64_128(key) => AeadTag::AesCcm16_128_128(
                AesCcm16_64_128::new(key.into())
                    .encrypt_in_place_detached(
                        nonce.try_into().expect("nonce length mismatch"),
                        aad_linear.as_ref(),
                        message,
                    )
                    .expect("Preconfigured sizes should not allow encryption to fail")
                    .into(),
            ),
        }
    }

    #[allow(
        clippy::unnecessary_fallible_conversions,
        reason = "GenericArray has infallible conversions but they panic"
    )]
    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        use ccm::{AeadInPlace, KeyInit};
        let aad_linear = self.collect_aad(aad);
        match key {
            AeadKey::AesCcm16_64_128(key) => AesCcm16_64_128::new(key.into())
                .decrypt_in_place_detached(
                    nonce.try_into().expect("nonce length mismatch"),
                    aad_linear.as_ref(),
                    message,
                    tag.try_into().expect("tag length mismatch"),
                )
                .map_err(|_| embedded_cal::DecryptionFailed),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DhAlgorithm {
    EcdhP256,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::EcdhP256 => 32,
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        match curve.into() {
            1 => Some(DhAlgorithm::EcdhP256),
            _ => None,
        }
    }
}

pub struct DhSecretKey {
    alg: DhAlgorithm,
    bytes: [u8; 32],
}

pub struct DhPublicKey {
    alg: DhAlgorithm,
    x: [u8; 32],
    y: [u8; 32],
}

pub struct DhSharedSecret([u8; 32]);

impl embedded_cal::SharedSecret for DhSharedSecret {
    fn raw_secret_bytes<C>(&self, _cal: &mut C) -> impl AsRef<[u8]>
    where
        C: embedded_cal::DhProvider<SharedSecret = Self>,
    {
        &self.0
    }
}

impl embedded_cal::DhProvider for RustcryptoCal {
    type DhAlgorithm = DhAlgorithm;
    type SecretKey = DhSecretKey;
    type PublicKey = DhPublicKey;
    type SharedSecret = DhSharedSecret;

    fn load_secret_key(&mut self, alg: Self::DhAlgorithm, bytes: &[u8]) -> Self::SecretKey {
        DhSecretKey {
            alg,
            bytes: bytes.try_into().expect("secret key must be 32 bytes for P-256"),
        }
    }

    fn load_public_key(
        &mut self,
        alg: Self::DhAlgorithm,
        x: &[u8],
        y: &[u8],
    ) -> Self::PublicKey {
        DhPublicKey {
            alg,
            x: x.try_into().expect("public key x must be 32 bytes for P-256"),
            y: y.try_into().expect("public key y must be 32 bytes for P-256"),
        }
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        if private.alg != public.alg {
            return Err(embedded_cal::IncompatibleKeys);
        }
        let secret = p256::SecretKey::from_bytes((&private.bytes).into())
            .expect("secret key bytes are a valid P-256 scalar");
        // Uncompressed point: 0x04 || x || y
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..33].copy_from_slice(&public.x);
        uncompressed[33..65].copy_from_slice(&public.y);
        let peer = p256::PublicKey::from_sec1_bytes(&uncompressed)
            .expect("public key coordinates are a valid P-256 point");
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(DhSharedSecret(
            shared.raw_secret_bytes().as_slice().try_into().unwrap(),
        ))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let secret = p256::SecretKey::from_bytes((&private.bytes).into())
            .expect("secret key bytes are a valid P-256 scalar");
        let point = secret.public_key();
        let encoded = p256::EncodedPoint::from(&point);
        DhPublicKey {
            alg: private.alg.clone(),
            x: encoded.x().expect("not the identity point").as_slice().try_into().unwrap(),
            y: encoded.y().expect("not the identity point and not compressed").as_slice().try_into().unwrap(),
        }
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
    fn test_dh_ecdh_p256() {
        embedded_cal::test_dh_algorithm_ecdh_p256::<RustcryptoCal>();
        let mut cal = RustcryptoCal::new();
        testvectors::test_dh_ecdh_p256(&mut cal);
    }
}
