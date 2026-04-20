//! Module that provides an [`embedded-cal::Cal`] instance like Ariel OS should on the long term.

#[allow(unused, reason = "just the non-empty peripherals need this")]
use ariel_os::hal::peripherals;

cfg_select! {
    feature = "embedded-cal-stm32wba55" => {ariel_os::hal::define_peripherals!(Peripherals {
        hash: HASH,
        rcc: RCC,
    });}
    _ => {ariel_os::hal::define_peripherals!(Peripherals {});}
}

/// Instanciates a Cal instance.
///
/// The current implementation is the most trivial possible, and just returns the software
/// implementation. Once this should support hardware, it'll grow an autostartable peripherals
/// argument (that'll vanish again once moved into Ariel OS itself).
pub fn cal(peripherals: Peripherals) -> impl embedded_cal::Cal {
    cfg_select! {
        feature = "embedded-cal-stm32wba55" => {
            // These are owned
            drop(peripherals.hash);
            drop(peripherals.rcc);
            // SAFETY: We just dropped an owned Embassy hash peripheral that is based on this
            // underlying one, so we're exclusive users.
            let hash = unsafe { stm32_metapac::HASH };
            // SAFETY: We just dropped an owned Embassy rcc peripheral that is based on this
            // underlying one, so we're exclusive users.
            let rcc = unsafe { stm32_metapac::RCC };
            embedded_cal_stm32wba55::Stm32wba55Cal::new(hash, &rcc)
        },
        _ => {
            let _ = peripherals;
            embedded_cal_rustcrypto::RustcryptoCal
        }
    }
}
