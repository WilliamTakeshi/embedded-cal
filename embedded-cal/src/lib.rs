#![no_std]

mod hash;
// FIXME: Once we start API stability, this should be a dedicated crate.
pub mod plumbing;

pub use hash::{HashAlgorithm, HashProvider, test_hash_algorithm_sha256};

pub trait Cal: HashProvider {}
