// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::*;
use embedded_cal::{AeadProvider, Cal};

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;
type AesCcm16_64_256 = ccm::Ccm<aes::Aes256, ccm::consts::U8, ccm::consts::U13>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm<BA> {
    AesCcm16_64_128,
    AesCcm16_64_256,
    Direct(BA),
}

impl<BA: embedded_cal::AeadAlgorithm> embedded_cal::AeadAlgorithm for AeadAlgorithm<BA> {
    fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 16,
            AeadAlgorithm::AesCcm16_64_256 => 32,
            AeadAlgorithm::Direct(a) => a.key_length(),
        }
    }

    fn tag_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 8,
            AeadAlgorithm::AesCcm16_64_256 => 8,
            AeadAlgorithm::Direct(a) => a.tag_length(),
        }
    }

    fn nonce_length(&self) -> usize {
        match self {
            AeadAlgorithm::AesCcm16_64_128 => 13,
            AeadAlgorithm::AesCcm16_64_256 => 13,
            AeadAlgorithm::Direct(a) => a.nonce_length(),
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();
        if let Some(a) = BA::from_cose_number(number) {
            return Some(AeadAlgorithm::Direct(a));
        }
        match number {
            10 => Some(AeadAlgorithm::AesCcm16_64_128),
            11 => Some(AeadAlgorithm::AesCcm16_64_256),
            _ => None,
        }
    }
}

pub enum AeadKey<BK> {
    AesCcm16_64_128([u8; 16]),
    AesCcm16_64_256([u8; 32]),
    Direct(BK),
}

pub enum AeadTag<BT> {
    AesCcm16_64_128([u8; 8]),
    AesCcm16_64_256([u8; 8]),
    Direct(BT),
}

impl<BT: AsRef<[u8]>> AsRef<[u8]> for AeadTag<BT> {
    fn as_ref(&self) -> &[u8] {
        match self {
            AeadTag::AesCcm16_64_128(t) => t,
            AeadTag::AesCcm16_64_256(t) => t,
            AeadTag::Direct(t) => t.as_ref(),
        }
    }
}

impl<Base: Cal> AeadProvider for RustcryptoCalExtender<Base> {
    type Algorithm = AeadAlgorithm<AeadAlgorithmOf<Base>>;
    type Key = AeadKey<AeadKeyOf<Base>>;
    type Tag = AeadTag<AeadTagOf<Base>>;

    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key {
        match alg {
            AeadAlgorithm::AesCcm16_64_128 => {
                AeadKey::AesCcm16_64_128(key.try_into().expect("key length mismatch"))
            }
            AeadAlgorithm::AesCcm16_64_256 => {
                AeadKey::AesCcm16_64_256(key.try_into().expect("key length mismatch"))
            }
            AeadAlgorithm::Direct(alg) => {
                AeadKey::Direct(self.base.aead().load_from_keydata(alg, key))
            }
        }
    }

    #[allow(
        clippy::unnecessary_fallible_conversions,
        reason = "GenericArray has infallible conversions but they panic"
    )]
    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Self::Tag {
        use ccm::{AeadInPlace, KeyInit};

        if let AeadKey::Direct(key) = key {
            return AeadTag::Direct(self.base.aead().encrypt_in_place(key, nonce, message, aad));
        }

        let aad_linear = self.collect_aad(aad);

        match key {
            AeadKey::AesCcm16_64_128(key) => AeadTag::AesCcm16_64_128(
                AesCcm16_64_128::new(key.into())
                    .encrypt_in_place_detached(
                        nonce.try_into().expect("nonce length mismatch"),
                        aad_linear.as_ref(),
                        message,
                    )
                    .expect("Preconfigured sizes should not allow encryption to fail")
                    .into(),
            ),
            AeadKey::AesCcm16_64_256(key) => AeadTag::AesCcm16_64_256(
                AesCcm16_64_256::new(key.into())
                    .encrypt_in_place_detached(
                        nonce.try_into().expect("nonce length mismatch"),
                        aad_linear.as_ref(),
                        message,
                    )
                    .expect("Preconfigured sizes should not allow encryption to fail")
                    .into(),
            ),
            AeadKey::Direct(_) => {
                unreachable!("Code path without common AAD collection was checked earlier")
            }
        }
    }

    #[allow(
        clippy::unnecessary_fallible_conversions,
        reason = "GenericArray has infallible conversions but they panic"
    )]
    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl embedded_cal::AadGenerator,
    ) -> Result<(), embedded_cal::DecryptionFailed> {
        use ccm::{AeadInPlace, KeyInit};

        if let AeadKey::Direct(key) = key {
            return self
                .base
                .aead()
                .decrypt_in_place(key, nonce, message, tag, aad);
        }

        let aad_linear = self.collect_aad(aad);

        match key {
            AeadKey::AesCcm16_64_128(key) => AesCcm16_64_128::new(key.into())
                .decrypt_in_place_detached(
                    nonce.try_into().expect("nonce length mismatch"),
                    aad_linear.as_ref(),
                    message,
                    tag.try_into().expect("tag length mismatch"),
                )
                .map_err(|_| embedded_cal::DecryptionFailed),
            AeadKey::AesCcm16_64_256(key) => AesCcm16_64_256::new(key.into())
                .decrypt_in_place_detached(
                    nonce.try_into().expect("nonce length mismatch"),
                    aad_linear.as_ref(),
                    message,
                    tag.try_into().expect("tag length mismatch"),
                )
                .map_err(|_| embedded_cal::DecryptionFailed),
            AeadKey::Direct(_) => {
                unreachable!("Code path without common AAD collection was checked earlier")
            }
        }
    }
}
