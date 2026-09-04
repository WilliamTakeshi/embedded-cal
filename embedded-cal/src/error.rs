// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Common error types.
//!
//! Errors here are exclusively zero-sized, as they are not generally actionable.

/// Error indicating that a imported key's size does not match the given algorithm, or that the data
/// was otherwise found flawed.
#[derive(Debug)]
pub struct ImportError;

impl core::fmt::Display for ImportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("data not valid for algorithm")
    }
}

impl core::error::Error for ImportError {}
