//! Module that provides an [`embedded-cal::Cal`] instance like Ariel OS should on the long term.

/// Instanciates a Cal instance.
///
/// The current implementation is the most trivial possible, and just returns the software
/// implementation. Once this should support hardware, it'll grow an autostartable peripherals
/// argument (that'll vanish again once moved into Ariel OS itself).
pub fn cal() -> impl embedded_cal::Cal {
    embedded_cal_rustcrypto::RustcryptoCal
}
