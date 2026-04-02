/// Error returned by [`RngProvider::try_fill_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// The hardware noise source failed its internal health test too many times.
    ///
    /// This indicates the entropy source may be untrustworthy (degraded oscillator,
    /// power instability, or a silicon fault).
    HardwareFailure,
}

/// Trait for cryptographically secure random number generation.
///
/// The interface mirrors rand_core::RngCore to allow zero-cost adaptation:
/// a future optional `rand_core` feature can add a blanket
/// `impl<T: RngCore> RngProvider for T` without API changes.
pub trait RngProvider {
    #[must_use = "ignoring RNG failure means the buffer may not contain random bytes"]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError>;

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).expect("RNG failure");
    }

    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

pub fn test_fill_bytes<R: RngProvider>(rng: &mut R) {
    // Zero-length fill must not panic
    rng.fill_bytes(&mut []);

    // Single-byte fill exercises the take=1 path
    let mut one = [0u8; 1];
    rng.fill_bytes(&mut one);

    // Basic fill: output should not be all zeros
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    assert!(buf.iter().any(|&b| b != 0));

    // Two consecutive fills should differ
    let mut buf2 = [0u8; 32];
    rng.fill_bytes(&mut buf2);
    assert_ne!(buf, buf2);

    // Non-multiple-of-4 length exercises the partial last word path
    let mut buf3 = [0u8; 15];
    rng.fill_bytes(&mut buf3);
    assert!(buf3.iter().any(|&b| b != 0));

    // Fill larger than a typical FIFO depth (>64 bytes) exercises multi-iteration draining
    let mut large = [0u8; 128];
    rng.fill_bytes(&mut large);
    assert!(large.iter().any(|&b| b != 0));

    let _ = rng.next_u32();
    let _ = rng.next_u64();
}
