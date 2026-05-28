use embedded_cal::{HkdfError, HkdfProvider};
use embedded_cal_software::hkdf::{
    HkdfAlgorithm, HkdfState, PrkResult, hkdf_expand_impl, hkdf_extract_impl,
};

use super::{HmacAlgorithm, Stm32wba55Cal};

impl HkdfProvider for Stm32wba55Cal {
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
        let prk = hkdf_extract_impl(self, HmacAlgorithm::HmacSha256, salt, ikm);
        (PrkResult::HkdfSha256(prk), HkdfState::new(prk))
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
        Ok(HkdfState::new(buf))
    }

    fn hkdf_expand(
        &mut self,
        state: &Self::HkdfState,
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        hkdf_expand_impl(self, HmacAlgorithm::HmacSha256, state.prk(), info, okm)
    }
}
