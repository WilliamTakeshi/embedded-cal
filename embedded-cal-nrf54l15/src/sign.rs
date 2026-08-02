// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::p256::{
    P256_GX_BYTES, P256_GY_BYTES, P256_ORDER, add_mod_n, bytes_to_words, ge, inv_mod_n, mul_mod_n,
    p256_recover_y, point_add, words_to_bytes,
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

// Reduces any 256-bit value mod the P-256 order `n` in one step: `add_mod_n(x, 0)` reuses
// `add_mod_n`'s single-subtraction reduction, which is valid for any x < 2^256 here because n is
// close enough to 2^256 that 2^256 - 1 < 2n.
fn reduce_mod_n(x: &[u32; 8]) -> [u32; 8] {
    add_mod_n(x, &[0u32; 8])
}

impl embedded_cal::plumbing::sign::EcdsaP256 for super::Nrf54l15Cal {
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
        let (x, y) = self.cracen_p256_mult(&private.scalar, &P256_GX_BYTES, &P256_GY_BYTES);
        PublicKey { x, y }
    }

    fn sign_digest(&mut self, private: &Self::SecretKey, digest: &[u8; 32]) -> Self::Signature {
        let z = reduce_mod_n(&bytes_to_words(digest));
        let d = bytes_to_words(&private.scalar);

        loop {
            let mut k_bytes = [0u8; 32];
            loop {
                self.fill_bytes(&mut k_bytes);
                let kw = bytes_to_words(&k_bytes);
                if kw != [0u32; 8] && !ge(&kw, &P256_ORDER) {
                    break;
                }
            }

            let (rx, _ry) = self.cracen_p256_mult(&k_bytes, &P256_GX_BYTES, &P256_GY_BYTES);
            let r = reduce_mod_n(&bytes_to_words(&rx));
            if r == [0u32; 8] {
                continue;
            }

            let k = bytes_to_words(&k_bytes);
            let k_inv = inv_mod_n(&k);
            let rd = mul_mod_n(&r, &d);
            let z_plus_rd = add_mod_n(&z, &rd);
            let s = mul_mod_n(&k_inv, &z_plus_rd);
            if s == [0u32; 8] {
                continue;
            }

            return Signature {
                r: words_to_bytes(&r),
                s: words_to_bytes(&s),
            };
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

        let z = reduce_mod_n(&bytes_to_words(digest));
        let w = inv_mod_n(&s);
        let u1 = mul_mod_n(&z, &w);
        let u2 = mul_mod_n(&r, &w);

        let (p1x, p1y) =
            self.cracen_p256_mult(&words_to_bytes(&u1), &P256_GX_BYTES, &P256_GY_BYTES);
        let (p2x, p2y) = self.cracen_p256_mult(&words_to_bytes(&u2), &public.x, &public.y);

        let sum = point_add(
            (&bytes_to_words(&p1x), &bytes_to_words(&p1y)),
            (&bytes_to_words(&p2x), &bytes_to_words(&p2y)),
        );

        match sum {
            Some((x, _y)) if reduce_mod_n(&x) == r => Ok(()),
            _ => Err(SignatureInvalid),
        }
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
