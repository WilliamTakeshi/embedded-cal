use super::RustcryptoCal;
use zeroize::{Zeroize, ZeroizeOnDrop};

impl embedded_cal::DhProvider for RustcryptoCal {
    type DhAlgorithm = DhAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_visible(&mut self, alg: Self::DhAlgorithm) -> Option<Self::VisibleSecretKey> {
        // We're not wrapping anything, so no point in deferring to the self RNG.
        Some(VisibleSecretKey(match alg {
            DhAlgorithm::P256 => SecretKey::P256(p256::SecretKey::random(&mut OldRng(self))),
        }))
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        Ok(SharedSecret(match (private, public) {
            (SecretKey::P256(secret_key), PublicKey::P256(public_key)) => {
                p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine())
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()
                    .expect("MAX_SHARED_SECRET_LENGTH is long enough")
            }
            _ => return Err(embedded_cal::IncompatibleKeys),
        }))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        match private {
            SecretKey::P256(secret_key) => PublicKey::P256(secret_key.public_key()),
        }
    }

    fn raw_secret_bytes(&mut self, secret: &Self::SharedSecret) -> impl AsRef<[u8]> {
        &secret.0
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DhAlgorithm {
    P256,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::P256 => 32,
        }
    }
}

pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(value: VisibleSecretKey) -> Self {
        value.0
    }
}

pub enum SecretKey {
    P256(p256::SecretKey),
}

pub enum PublicKey {
    P256(p256::PublicKey),
}

const MAX_SHARED_SECRET_LENGTH: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(heapless::Vec<u8, MAX_SHARED_SECRET_LENGTH>);

struct OldRng<'c, C: embedded_cal::Cal>(&'c mut C);

impl<'c, C: embedded_cal::Cal + rand_core::TryCryptoRng> rand_core_06::CryptoRng for OldRng<'c, C> {}
impl<'c, C: embedded_cal::Cal + rand_core::TryCryptoRng> rand_core_06::RngCore for OldRng<'c, C> {
    fn next_u32(&mut self) -> u32 {
        self.0.try_next_u32().unwrap()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.try_next_u64().unwrap()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.try_fill_bytes(dest).map_err(|_| {
            rand_core_06::Error::from(
                core::num::NonZero::try_from(rand_core_06::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}
