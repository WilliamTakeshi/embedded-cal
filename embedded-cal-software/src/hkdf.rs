use embedded_cal::{HkdfError, HkdfProvider, HmacAlgorithm as _, HmacProvider};

use crate::hmac::HmacAlgorithm;

use crate::{Extender, ExtenderConfig};

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
            -10 => Some(HkdfAlgorithm::HkdfSha256),
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
    pub(crate) prk: [u8; 32],
}

impl HkdfState {
    /// Construct from a raw PRK.
    ///
    /// Intended for use by back-end crates that delegate to [`hkdf_extract_impl`] /
    /// [`hkdf_expand_impl`] but implement [`HkdfProvider`] themselves.
    pub fn new(prk: [u8; 32]) -> Self {
        Self { prk }
    }

    /// Access the raw PRK bytes.
    pub fn prk(&self) -> &[u8; 32] {
        &self.prk
    }
}

/// HKDF-Extract over any [`HmacProvider`].
///
/// Computes `PRK = HMAC-Hash(salt, IKM)` (RFC 5869).
/// If `salt` is `None`, defaults to a zero string of `algo.len()` bytes.
///
/// # Panics
/// Panics if `algo.len() > 64` (no standard hash is that wide) or if the
/// HMAC output is not exactly `algo.len()` bytes (implementation bug).
pub fn hkdf_extract_impl<H: HmacProvider>(
    hmac: &mut H,
    algo: H::Algorithm,
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> [u8; 32] {
    let default_salt = [0u8; 64];
    let hash_len = algo.len().min(64);
    let salt = salt.unwrap_or(&default_salt[..hash_len]);
    let prk = hmac.hmac_with_keydata(algo, salt, ikm);
    prk.as_ref()
        .try_into()
        .expect("HMAC output must be 32 bytes for HKDF-SHA-256")
}

/// HKDF-Expand over any [`HmacProvider`].
///
/// Fills `okm` with up to `255 * HashLen` bytes derived from `prk` and `info`
/// (RFC 5869).
pub fn hkdf_expand_impl<H: HmacProvider>(
    hmac: &mut H,
    algo: H::Algorithm,
    prk: &[u8; 32],
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
        let mut hmac_state = hmac.init_with_keydata(algo.clone(), prk);
        hmac.update(&mut hmac_state, &t_prev[..t_prev_len]);
        hmac.update(&mut hmac_state, info);
        hmac.update(&mut hmac_state, &[counter]);
        let t = hmac.finalize(hmac_state);

        t_prev.copy_from_slice(t.as_ref());
        t_prev_len = 32;

        let take = (okm.len() - offset).min(32);
        okm[offset..offset + take].copy_from_slice(&t_prev[..take]);
        offset += take;
        counter += 1;
    }
    Ok(())
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
        let prk = hkdf_extract_impl(self, HmacAlgorithm::HmacSha256, salt, ikm);
        (PrkResult::HkdfSha256(prk), HkdfState { prk })
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
        hkdf_expand_impl(self, HmacAlgorithm::HmacSha256, &state.prk, info, okm)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::dummy_sha256;

    struct ImplementSha256Short;

    impl ExtenderConfig for ImplementSha256Short {
        const IMPLEMENT_SHA2SHORT: bool = true;
        type Base = dummy_sha256::DummySha256;
    }

    #[test]
    fn test_hkdf_sha256_on_dummy() {
        let mut cal = Extender::<ImplementSha256Short>(dummy_sha256::DummySha256);

        testvectors::test_hkdf_sha256(&mut cal);
    }
}
