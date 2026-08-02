// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::{
    HashProvider, ImportError, SignProvider, SignatureInvalid, plumbing::sign::EcdsaP256,
};

use crate::hash::{HashAlgorithm, HashResult};

use super::{Extender, ExtenderConfig};

/// Signature algorithm identifier for software-composed ECDSA over [`Extender`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SignAlgorithm {
    EcdsaP256,
}

impl embedded_cal::SignAlgorithm for SignAlgorithm {
    fn signature_length(&self) -> usize {
        match self {
            SignAlgorithm::EcdsaP256 => 64,
        }
    }

    #[inline]
    fn from_cose_number(alg: impl Into<i128>) -> Option<Self> {
        match alg.into() {
            -7 => Some(SignAlgorithm::EcdsaP256),
            _ => None,
        }
    }
}

impl<EC: ExtenderConfig> Extender<EC> {
    fn sha256_digest(&mut self, message: &[u8]) -> [u8; 32] {
        match HashProvider::hash(self, HashAlgorithm::Sha256, message) {
            HashResult::Sha256(digest) => digest,
            _ => unreachable!("Sha256 hash produces Sha256 result"),
        }
    }
}

/// Composes [`SignProvider`] from `Extender`'s own [`HashProvider`] (for hashing the message)
/// plus `EC::Base`'s [`EcdsaP256`] plumbing (for the digest-level EC math) -- the same
/// hash-then-delegate pattern [`HmacProvider`][embedded_cal::HmacProvider] already uses.
///
/// `EC::Base: EcdsaP256` is guaranteed by `ExtenderConfig::Base: Cal + Plumbing`
/// (`Plumbing: EcdsaP256`), so this impl needs no extra bound -- boards without hardware ECDSA
/// support simply have `EcdsaP256::SUPPORTED = false` and panic if actually invoked, same as
/// `Sha2Short` does for hashing.
impl<EC: ExtenderConfig> SignProvider for Extender<EC> {
    type Algorithm = SignAlgorithm;
    type VisibleSecretKey = <EC::Base as EcdsaP256>::VisibleSecretKey;
    type SecretKey = <EC::Base as EcdsaP256>::SecretKey;
    type PublicKey = <EC::Base as EcdsaP256>::PublicKey;
    type Signature = <EC::Base as EcdsaP256>::Signature;

    fn generate_visible(&mut self, _alg: Self::Algorithm) -> Self::VisibleSecretKey {
        self.0.generate_visible()
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        self.0.export_secretkey_bytes(secretkey)
    }

    fn import_secretkey_bytes(
        &mut self,
        _alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        self.0.import_secretkey_bytes(secret)
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, EC> {
        self.0.export_publickey_bytes(public)
    }

    fn import_publickey_bytes(
        &mut self,
        _alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, ImportError> {
        self.0.import_publickey_bytes(data)
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        self.0.public_key(private)
    }

    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        let digest = self.sha256_digest(message);
        self.0.sign_digest(private, &digest)
    }

    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid> {
        let digest = self.sha256_digest(message);
        self.0.verify_digest(public, &digest, signature)
    }

    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        self.0.export_signature_bytes(signature)
    }

    fn import_signature_bytes(
        &mut self,
        _alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, ImportError> {
        self.0.import_signature_bytes(data)
    }
}
