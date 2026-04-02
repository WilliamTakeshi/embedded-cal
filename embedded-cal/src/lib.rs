#![no_std]

mod hash;
mod rng;
// FIXME: Once we start API stability, this should be a dedicated crate.
pub mod plumbing;

pub use hash::{HashAlgorithm, HashProvider, NoHashAlgorithms, test_hash_algorithm_sha256};
pub use rng::{RngError, RngProvider, test_fill_bytes};

pub trait Cal: HashProvider + RngProvider {}
