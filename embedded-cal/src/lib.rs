#![no_std]

mod hash;

pub use hash::{HashProvider, HashAlgorithm, test_hash_algorithm_sha256};

pub trait Cal: HashProvider {}
