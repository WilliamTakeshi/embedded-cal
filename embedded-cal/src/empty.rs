//! Implementations of the various traits of embedded-cal that implemnt the empty set of
//! algorithms.
//!
//! The types are ZST or uninhabited as suitable for the type.

use super::*;

/// An implementation of [`Cal`] that provides no single algorithm (or, for the random number
/// aspect that has no algorithms, never succeeds in doing anything).
pub struct EmptyCal;

impl Cal for EmptyCal {}

// Those should all be shorter when <https://github.com/lake-rs/embedded-cal/issues/40> is
// resolved; then again, the implementations that do make it short will live here. Until then, feel
// free to copy those out into your Cal implementations.

impl HashProvider for EmptyCal {
    type Algorithm = NoHashAlgorithms;
    type HashState = NoHashAlgorithms;
    type HashResult = NoHashAlgorithms;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {}
    }

    fn update(&mut self, instance: &mut Self::HashState, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {}
    }
}

impl HmacProvider for EmptyCal {
    type Algorithm = NoHmacAlgorithms;
    type Key = NoHmacAlgorithms;
    type HmacState = NoHmacAlgorithms;
    type HmacResult = NoHmacAlgorithms;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match algorithm {}
    }

    fn init(&mut self, key: Self::Key) -> Self::HmacState {
        match key {}
    }

    fn update(&mut self, state: &mut Self::HmacState, _data: &[u8]) {
        match *state {}
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        match state {}
    }
}

impl AeadProvider for EmptyCal {
    type Algorithm = NoAeadAlgorithms;
    type Key = NoAeadAlgorithms;
    type Tag = NoAeadAlgorithms;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, _key: &[u8]) -> Self::Key {
        match alg {}
    }

    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _aad: impl AadGenerator,
    ) -> Self::Tag {
        match *key {}
    }

    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        _nonce: &[u8],
        _message: &mut [u8],
        _tag: &[u8],
        _aad: impl AadGenerator,
    ) -> Result<(), DecryptionFailed> {
        match *key {}
    }
}

impl rand_core::TryCryptoRng for EmptyCal {}

impl rand_core::TryRng for EmptyCal {
    type Error = NoRng;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(NoRng)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(NoRng)
    }

    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
        Err(NoRng)
    }
}

/// Error type returned by [`EmtpyCal`] when trying to obtain random numbers.
#[derive(Debug)]
pub struct NoRng;

impl core::fmt::Display for NoRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no RNG available in empty Cal implementation")
    }
}

impl core::error::Error for NoRng {}
