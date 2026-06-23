// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::*;
use embedded_cal::{Cal, HashProvider};

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HashAlgorithm<BA> {
    Sha256,
    Direct(BA),
}

impl<BA: embedded_cal::HashAlgorithm> embedded_cal::HashAlgorithm for HashAlgorithm<BA> {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Direct(a) => a.len(),
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();
        if let Some(a) = BA::from_cose_number(number) {
            return Some(HashAlgorithm::Direct(a));
        }
        match number.into() {
            -16 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_id(number: u8) -> Option<Self> {
        if let Some(a) = BA::from_ni_id(number) {
            return Some(HashAlgorithm::Direct(a));
        }
        match number {
            1 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        if let Some(a) = BA::from_ni_name(name) {
            return Some(HashAlgorithm::Direct(a));
        }
        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub enum HashState<BHS> {
    Sha256(sha2::Sha256),
    Direct(BHS),
}

pub enum HashResult<BHR> {
    Sha256([u8; 32]),
    Direct(BHR),
}

impl<BHR: AsRef<[u8]>> AsRef<[u8]> for HashResult<BHR> {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(r) => &r[..],
            HashResult::Direct(r) => r.as_ref(),
        }
    }
}

impl<Base: Cal> HashProvider for RustcryptoCalExtender<Base> {
    type Algorithm = HashAlgorithm<HashAlgorithmOf<Base>>;
    type State = HashState<HashStateOf<Base>>;
    type Output = HashResult<HashOutputOf<Base>>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::State {
        match algorithm {
            // Same for any, really
            HashAlgorithm::Sha256 => HashState::Sha256(Default::default()),
            HashAlgorithm::Direct(a) => HashState::Direct(self.base.hash().init(a)),
        }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        match instance {
            // Same for any, really
            HashState::Sha256(s) => s.update(data),
            HashState::Direct(i) => self.base.hash().update(i, data),
        }
    }

    fn finalize(&mut self, instance: Self::State) -> Self::Output {
        match instance {
            // Same for any, really
            HashState::Sha256(s) => HashResult::Sha256(s.finalize().into()),
            HashState::Direct(i) => HashResult::Direct(self.base.hash().finalize(i)),
        }
    }

    fn hash(&mut self, algorithm: Self::Algorithm, data: &[u8]) -> Self::Output {
        if let HashAlgorithm::Direct(a) = algorithm {
            return HashResult::Direct(self.base.hash().hash(a, data));
        };

        // FIXME: Is there any sensible deduplication to be done with the provided impl?
        let mut state = self.init(algorithm);
        self.update(&mut state, data);
        self.finalize(state)
    }
}
