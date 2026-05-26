use embedded_cal::{HkdfError, HkdfProvider, HmacProvider};

use crate::{Extender, ExtenderConfig, HmacAlgorithm};

/// HKDF algorithm identifier for software HKDF over [`Extender`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HkdfAlgorithm {
    HkdfSha256,
}

impl embedded_cal::HkdfAlgorithm for HkdfAlgorithm {
    fn hash_len(&self) -> usize {
        match self {
            HkdfAlgorithm::HkdfSha256 => 32,
        }
    }

    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            // EDHOC uses -13 for HKDF-SHA-256 (RFC 9528 §A.2)
            -13 => Some(HkdfAlgorithm::HkdfSha256),
            _ => None,
        }
    }
}

/// PRK returned by `hkdf_extract`.
pub enum PrkResult {
    HkdfSha256([u8; 32]),
}

impl AsRef<[u8]> for PrkResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            PrkResult::HkdfSha256(data) => data.as_slice(),
        }
    }
}

/// Opaque state produced by extract operations; passed to `hkdf_expand`.
pub struct HkdfState {
    prk: [u8; 32],
}

impl<EC: ExtenderConfig> HkdfProvider for Extender<EC> {
    type Algorithm = HkdfAlgorithm;
    type HkdfState = HkdfState;
    type PrkResult = PrkResult;

    fn hkdf_new(
        &mut self,
        algorithm: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Self::HkdfState {
        let (_, state) = self.hkdf_extract(algorithm, salt, ikm);
        state
    }

    fn hkdf_extract(
        &mut self,
        _algorithm: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> (Self::PrkResult, Self::HkdfState) {
        let default_salt = [0u8; 32];
        let salt = salt.unwrap_or(&default_salt);
        let prk = HmacProvider::hmac(self, HmacAlgorithm::HmacSha256, salt, ikm);
        let prk_bytes: [u8; 32] = prk
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 always produces 32 bytes");
        (
            PrkResult::HkdfSha256(prk_bytes),
            HkdfState { prk: prk_bytes },
        )
    }

    fn hkdf_from_prk(
        &mut self,
        _algorithm: Self::Algorithm,
        prk: &[u8],
    ) -> Result<Self::HkdfState, HkdfError> {
        if prk.len() < 32 {
            return Err(HkdfError::InvalidPrkLength);
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&prk[..32]);
        Ok(HkdfState { prk: buf })
    }

    fn hkdf_expand(
        &mut self,
        state: &Self::HkdfState,
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        if okm.len() > 255 * 32 {
            return Err(HkdfError::OutputTooLong);
        }

        let mut t_prev = [0u8; 32];
        let mut t_prev_len = 0usize; // T(0) is the empty string
        let mut offset = 0usize;
        let mut counter = 1u8;

        while offset < okm.len() {
            let mut hmac_state = HmacProvider::init(self, HmacAlgorithm::HmacSha256, &state.prk);
            HmacProvider::update(self, &mut hmac_state, &t_prev[..t_prev_len]);
            HmacProvider::update(self, &mut hmac_state, info);
            HmacProvider::update(self, &mut hmac_state, &[counter]);
            let t = HmacProvider::finalize(self, hmac_state);

            t_prev.copy_from_slice(t.as_ref());
            t_prev_len = 32;

            let take = (okm.len() - offset).min(32);
            okm[offset..offset + take].copy_from_slice(&t_prev[..take]);
            offset += take;
            counter += 1;
        }
        Ok(())
    }
}
