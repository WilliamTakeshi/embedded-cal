use crate::{HmacAlgorithm, HmacProvider};

#[derive(Debug, PartialEq, Eq)]
pub enum HkdfError {
    /// Requested OKM length exceeds 255 × HashLen bytes (RFC 5869).
    OutputTooLong,
    /// The underlying HMAC produced an unexpected output length.
    InvalidOutputLength,
}

pub trait HkdfProvider {
    type Algorithm: HmacAlgorithm;
    /// Opaque input keying material. May be constructed from a DH shared secret
    /// without the raw bytes ever being user-visible.
    type Ikm: ?Sized;
    /// Opaque pseudorandom key — output of Extract, input to Expand.
    type Prk;
    /// Opaque output keying material — output of Expand.
    type Okm: ?Sized;

    /// HKDF-Extract (RFC 5869): returns a pseudorandom key.
    ///
    /// When `salt` is `None`, a zero-filled byte string of `HashLen` bytes is used
    /// as the HMAC key (RFC 5869).
    fn hkdf_extract(
        &mut self,
        alg: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &Self::Ikm,
    ) -> Result<Self::Prk, HkdfError>;

    /// HKDF-Expand (RFC 5869): fills `okm` with derived key material.
    fn hkdf_expand(
        &mut self,
        alg: Self::Algorithm,
        prk: &Self::Prk,
        info: &[u8],
        okm: &mut Self::Okm,
    ) -> Result<(), HkdfError>;

    /// Extract then expand in one call.
    fn hkdf(
        &mut self,
        alg: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &Self::Ikm,
        info: &[u8],
        okm: &mut Self::Okm,
    ) -> Result<(), HkdfError> {
        let prk = self.hkdf_extract(alg.clone(), salt, ikm)?;
        self.hkdf_expand(alg, &prk, info, okm)
    }
}

impl<H: HmacProvider> HkdfProvider for H {
    type Algorithm = H::Algorithm;
    type Ikm = [u8];
    type Prk = H::HmacResult;
    type Okm = [u8];

    fn hkdf_extract(
        &mut self,
        alg: Self::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Result<Self::Prk, HkdfError> {
        // When salt is absent, RFC 5869 uses HashLen zero bytes as the HMAC key.
        // Buffer covers standard algorithms up to SHA-512 (64 bytes).
        let zero_salt = [0u8; 64];
        let hash_len = alg.len();
        if hash_len > zero_salt.len() {
            return Err(HkdfError::InvalidOutputLength);
        }
        let salt_bytes = salt.unwrap_or(&zero_salt[..hash_len]);
        // PRK = HMAC-Hash(salt, IKM)
        Ok(self.hmac_with_keydata(alg, salt_bytes, ikm))
    }

    fn hkdf_expand(
        &mut self,
        alg: Self::Algorithm,
        prk: &Self::Prk,
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let hash_len = alg.len();
        if okm.len() > 255 * hash_len {
            return Err(HkdfError::OutputTooLong);
        }
        let prk_bytes = prk.as_ref();
        // T buffer covers standard algorithms up to SHA-512 (64 bytes).
        let mut t = [0u8; 64];
        if hash_len > t.len() {
            return Err(HkdfError::InvalidOutputLength);
        }
        let mut t_len = 0usize;
        let mut pos = 0usize;

        while pos < okm.len() {
            // counter is 1-based block index; pos/hash_len+1 <= 255 enforced above
            let counter = (pos / hash_len + 1) as u8;
            // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
            let mut state = self.init_with_keydata(alg.clone(), prk_bytes);
            if t_len > 0 {
                HmacProvider::update(self, &mut state, &t[..t_len]);
            }
            HmacProvider::update(self, &mut state, info);
            HmacProvider::update(self, &mut state, &[counter]);
            let result = HmacProvider::finalize(self, state);
            let result_bytes = result.as_ref();
            if result_bytes.len() != hash_len {
                return Err(HkdfError::InvalidOutputLength);
            }
            t[..hash_len].copy_from_slice(result_bytes);
            t_len = hash_len;

            let take = (okm.len() - pos).min(hash_len);
            okm[pos..pos + take].copy_from_slice(&t[..take]);
            pos += take;
        }
        Ok(())
    }
}
