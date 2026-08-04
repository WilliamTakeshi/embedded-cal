// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::p256::{
    P256_GX, P256_GY, P256_ORDER, bytes_to_words, ge, p256_recover_y, words_to_bytes,
};
use embedded_cal::{ImportError, SignatureInvalid};
use rand_core::Rng as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    scalar: [u8; 32],
}

#[derive(Zeroize)]
pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

pub struct PublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl embedded_cal::plumbing::sign::EcdsaP256 for super::Stm32wba55Cal {
    const SUPPORTED: bool = true;

    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn generate_visible(&mut self) -> Self::VisibleSecretKey {
        loop {
            let mut scalar = [0u8; 32];
            // Error = Infallible
            self.fill_bytes(&mut scalar);
            let w = bytes_to_words(&scalar);
            if w != [0u32; 8] && !ge(&w, &P256_ORDER) {
                return VisibleSecretKey(SecretKey { scalar });
            }
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secretkey.0.scalar[..]
    }

    fn import_secretkey_bytes(
        &mut self,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, ImportError> {
        let scalar = secret.try_into().map_err(|_| ImportError)?;
        Ok(VisibleSecretKey(SecretKey { scalar }))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        &public.x[..]
    }

    fn import_publickey_bytes(&mut self, data: &[u8]) -> Result<Self::PublicKey, ImportError> {
        let x: [u8; 32] = data.try_into().map_err(|_| ImportError)?;
        let y = p256_recover_y(&x)?;
        Ok(PublicKey { x, y })
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let scalar_words = bytes_to_words(&private.scalar);
        let (rx, ry) = self.pka_ecc_mult(&scalar_words, &P256_GX, &P256_GY);
        PublicKey {
            x: words_to_bytes(&rx),
            y: words_to_bytes(&ry),
        }
    }

    fn sign_digest(&mut self, private: &Self::SecretKey, digest: &[u8; 32]) -> Self::Signature {
        let d = bytes_to_words(&private.scalar);
        let h = bytes_to_words(digest);
        loop {
            let mut k_bytes = [0u8; 32];
            loop {
                self.fill_bytes(&mut k_bytes);
                let kw = bytes_to_words(&k_bytes);
                if kw != [0u32; 8] && !ge(&kw, &P256_ORDER) {
                    break;
                }
            }
            let k = bytes_to_words(&k_bytes);

            if let Some((r, s)) = self.pka_ecdsa_sign(&d, &k, &h) {
                return Signature {
                    r: words_to_bytes(&r),
                    s: words_to_bytes(&s),
                };
            }
        }
    }

    fn verify_digest(
        &mut self,
        public: &Self::PublicKey,
        digest: &[u8; 32],
        signature: &Self::Signature,
    ) -> Result<(), SignatureInvalid> {
        let r = bytes_to_words(&signature.r);
        let s = bytes_to_words(&signature.s);
        if r == [0u32; 8] || ge(&r, &P256_ORDER) || s == [0u32; 8] || ge(&s, &P256_ORDER) {
            return Err(SignatureInvalid);
        }

        let qx = bytes_to_words(&public.x);
        let qy = bytes_to_words(&public.y);
        let h = bytes_to_words(digest);
        self.pka_ecdsa_verify(&qx, &qy, &h, &r, &s)
    }

    fn export_signature_bytes<'s>(
        &mut self,
        signature: &'s Self::Signature,
    ) -> impl AsRef<[u8]> + use<'s> {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&signature.r);
        bytes[32..].copy_from_slice(&signature.s);
        bytes
    }

    fn import_signature_bytes(&mut self, data: &[u8]) -> Result<Self::Signature, ImportError> {
        if data.len() != 64 {
            return Err(ImportError);
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&data[..32]);
        s.copy_from_slice(&data[32..]);
        Ok(Signature { r, s })
    }
}
