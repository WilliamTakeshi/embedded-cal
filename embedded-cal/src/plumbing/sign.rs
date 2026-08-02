// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

/// Trait indicating that there is hardware (or otherwise low-level) support for ECDSA on P-256.
///
/// Unlike the top-level [`SignProvider`][crate::SignProvider], this operates on a pre-computed
/// SHA-256 digest rather than a raw message: it models what a signing engine (hardware or
/// software) does once hashing is out of the way. [`crate::SignProvider`] is typically built on
/// top of this plus a [`HashProvider`][crate::HashProvider] -- see `embedded-cal-software-demo`'s
/// `Extender` for that composition.
///
/// Fixed to P-256/SHA-256, the only pairing currently in scope; a curve-agile version of this
/// trait can be introduced later if and when a second curve is added.
pub trait EcdsaP256 {
    /// Whether this trait is actually supported. See [`Plumbing`][super::Plumbing] docs for
    /// rationale.
    const SUPPORTED: bool;

    /// A secret key that is intended to be exported.
    type VisibleSecretKey: Sized + Into<Self::SecretKey>;
    type SecretKey: Sized;
    type PublicKey: Sized;
    type Signature: Sized;

    /// Generates a secret key that is intended to be exported / shared.
    fn generate_visible(&mut self) -> Self::VisibleSecretKey;

    /// Generates a secret key.
    fn generate(&mut self) -> Self::SecretKey {
        self.generate_visible().into()
    }

    /// Exposes a visible secret key's secret.
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, Self>;

    /// Inverse operation of [`.export_secretkey_bytes()`][Self::export_secretkey_bytes()].
    fn import_secretkey_bytes(
        &mut self,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, super::super::ImportError>;

    /// Exposes a public key's key data bytes, in compact representation.
    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p, Self>;

    /// Inverse operation of [`.export_publickey_bytes()`][Self::export_publickey_bytes()].
    fn import_publickey_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<Self::PublicKey, super::super::ImportError>;

    /// Produces the public key corresponding to a private key.
    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey;

    /// Signs a SHA-256 digest.
    fn sign_digest(&mut self, private: &Self::SecretKey, digest: &[u8; 32]) -> Self::Signature;

    /// Verifies a signature over a SHA-256 digest.
    fn verify_digest(
        &mut self,
        public: &Self::PublicKey,
        digest: &[u8; 32],
        signature: &Self::Signature,
    ) -> Result<(), super::super::SignatureInvalid>;

    /// Exposes a signature's bytes, as raw `r || s`.
    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s, Self>;

    /// Inverse operation of [`.export_signature_bytes()`][Self::export_signature_bytes()].
    fn import_signature_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<Self::Signature, super::super::ImportError>;
}
