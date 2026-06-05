use super::RustcryptoCal;

/// An implementation based on `getrandom`.
///
/// Unlike lakers, we just require that getrandom is provided; Ariel OS's random module shows that
/// this can be done also on embedded platforms.
// FIXME: We should probably have some fast CSPRNG in self that is just seeded from getrandom.
impl rand_core::TryCryptoRng for RustcryptoCal {}

impl rand_core::TryRng for RustcryptoCal {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        getrandom::u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        getrandom::u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}
