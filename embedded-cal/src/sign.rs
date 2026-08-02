// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

/// Digital signature creation and verification.
///
/// This trait does not distinguish between different signature schemes (eg. ECDSA on various
/// curves, or EdDSA); it describes the general interface.
///
/// It takes inspiration from [`DhProvider`][super::DhProvider], and shares its rationale for
/// splitting [`VisibleSecretKey`][Self::VisibleSecretKey] from [`SecretKey`][Self::SecretKey].
///
/// Unlike [`DhProvider`], `sign` and `verify` take a raw message rather than a pre-computed
/// digest: hashing is part of the algorithm (eg. ECDSA over SHA-256 for ES256), so implementers
/// are expected to hash internally. On hardware where the signing engine itself only knows how to
/// operate on a digest, this trait is typically composed from a lower-level, digest-based
/// primitive plus a [`HashProvider`][super::HashProvider] -- see
/// `embedded-cal-software-demo`'s `Extender` for that composition.
pub trait SignProvider {
    type Algorithm: SignAlgorithm;
    /// A secret key that is intended to be exported.
    ///
    /// See [`DhProvider::VisibleSecretKey`][super::DhProvider::VisibleSecretKey] for the
    /// rationale of splitting this from [`SecretKey`][Self::SecretKey].
    type VisibleSecretKey: Sized + Into<Self::SecretKey>;
    type SecretKey: Sized;
    type PublicKey: Sized;
    type Signature: Sized;

    /// Generates a secret key that is intended to be exported / shared (e.g. to be persisted
    /// across program executions).
    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey;

    /// Generates a secret key.
    fn generate(&mut self, alg: Self::Algorithm) -> Self::SecretKey {
        self.generate_visible(alg).into()
    }

    /// Exposes a visible secret key's secret.
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, Self>;

    /// Inverse operation of [`.export_secretkey_bytes()`][Self::export_secretkey_bytes()].
    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, super::ImportError>;

    /// Exposes a public key's key data bytes.
    ///
    /// For EC signature schemes, this is defined as the compact representation.
    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, Self>;

    /// Inverse operation of [`.export_publickey_bytes()`][Self::export_publickey_bytes()].
    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, super::ImportError>;

    /// Produces the public key corresponding to a private key.
    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey;

    /// Signs a message. The message is hashed internally, per `Self::Algorithm`.
    fn sign(&mut self, private: &Self::SecretKey, message: &[u8]) -> Self::Signature;

    /// Verifies a signature over a message.
    fn verify(
        &mut self,
        public: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid>;

    /// Exposes a signature's bytes.
    ///
    /// For ECDSA, this is the raw `r || s` representation.
    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, Self>;

    /// Inverse operation of [`.export_signature_bytes()`][Self::export_signature_bytes()].
    fn import_signature_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::Signature, super::ImportError>;
}

/// Error indicating that a signature did not verify against the given public key and message.
#[derive(Debug)]
pub struct SignatureInvalid;

impl core::fmt::Display for SignatureInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("signature is not valid for the given public key and message")
    }
}

impl core::error::Error for SignatureInvalid {}

/// A signature algorithm.
///
/// This not only encodes the cryptographic algorithm, but also the curve and hash (where
/// applicable).
pub trait SignAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Length of signatures produced by keys of this algorithm.
    fn signature_length(&self) -> usize;

    /// Selects a signature algorithm from its COSE "alg" number.
    ///
    /// The algorithm number comes from the ["COSE Algorithms"
    /// registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) maintained by IANA.
    #[inline]
    #[allow(
        unused_variables,
        reason = "Argument names are part of the documentation"
    )]
    fn from_cose_number(alg: impl Into<i128>) -> Option<Self> {
        None
    }
}

pub fn test_sign_algorithm_ecdsa_p256<SP: SignProvider>() {
    let es256 = SP::Algorithm::from_cose_number(-7i8).expect(
        "test for type claiming ECDSA on P-256 compatibility did not recognize COSE alg ES256 (-7)",
    );
    assert_eq!(es256.signature_length(), 64);
}
