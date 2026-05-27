pub trait HkdfProvider {
    type Algorithm: HkdfAlgorithm;
    /// Holds the PRK after extraction; passed to `hkdf_expand`.
    type HkdfState: Sized;
    /// PRK output returned by `hkdf_extract` (always `hash_len()` bytes).
    type PrkResult: AsRef<[u8]>;

    /// Extract only — discards the PRK, returns a state ready for `hkdf_expand`.
    fn hkdf_new(
        &mut self,
        algorithm: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Self::HkdfState;

    /// Full Extract: returns both the PRK and a ready-to-expand state.
    fn hkdf_extract(
        &mut self,
        algorithm: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> (Self::PrkResult, Self::HkdfState);

    /// Build a state from an already-derived PRK (e.g. received from a peer).
    fn hkdf_from_prk(
        &mut self,
        algorithm: Self::Algorithm,
        prk: &[u8],
    ) -> Result<Self::HkdfState, HkdfError>;

    /// HKDF-Expand.  `okm.len()` controls output length (up to 255 * HashLen).
    fn hkdf_expand(
        &mut self,
        state: &Self::HkdfState,
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError>;
}

pub trait HkdfAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// HMAC output length in bytes (= PRK length).
    fn hash_len(&self) -> usize;

    fn from_cose_number(number: impl Into<i128>) -> Option<Self>;
}

#[derive(Debug)]
pub enum HkdfError {
    /// Requested output length exceeds 255 * HashLen.
    OutputTooLong,
    /// PRK supplied to `hkdf_from_prk` is shorter than the hash length.
    InvalidPrkLength,
}
