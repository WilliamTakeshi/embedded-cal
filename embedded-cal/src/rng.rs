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
