#![no_std]
#![no_main]

use defmt_rtt as _;
use panic_probe as _;

struct ImplementSha256Short;
impl embedded_cal_software_demo::ExtenderConfig for ImplementSha256Short {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = embedded_cal_nrf54l15::Nrf54l15Cal;
}
struct TestState {
    cal: embedded_cal_software_demo::Extender<ImplementSha256Short>,
    raw: embedded_cal_nrf54l15::Nrf54l15Cal,
}

#[defmt_test::tests]
mod tests {
    use super::ImplementSha256Short;
    use embedded_cal_nrf54l15::Nrf54l15Cal;

    #[init]
    fn init() -> super::TestState {
        let raw = embedded_cal_nrf54l15::Nrf54l15Cal::new(
            nrf_pac::CRACEN_S,
            nrf_pac::CRACENCORE_S,
            nrf_pac::CCM00_S,
        );
        // FIXME: How to make sure there is a exclusive reference for CRACEN_S?
        let base = embedded_cal_nrf54l15::Nrf54l15Cal::new(
            nrf_pac::CRACEN_S,
            nrf_pac::CRACENCORE_S,
            nrf_pac::CCM00_S,
        );

        let cal = embedded_cal_software_demo::Extender::<ImplementSha256Short>::new(base);

        super::TestState { cal, raw }
    }

    // #[test]
    // fn test_hash_algorithm_sha256(state: &mut super::TestState) {
    //     embedded_cal::test_hash_algorithm_sha256::<
    //         <Nrf54l15Cal as embedded_cal::HashProvider>::Algorithm,
    //     >();
    //     testvectors::test_hash_algorithm_sha256(&mut state.cal);
    // }

    // #[test]
    // fn test_hmac_sha256(state: &mut super::TestState) {
    //     embedded_cal::test_hmac_algorithm_hmacsha256::<
    //         <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HmacProvider>::Algorithm,
    //     >();
    //     testvectors::test_hmac_sha256(&mut state.cal);
    // }

    // #[test]
    // fn test_tryrng(state: &mut super::TestState) {
    //     embedded_cal::test_tryrng(&mut state.cal);
    // }

    // #[test]
    // fn test_aead_aesccm_16_64_128(state: &mut super::TestState) {
    //     testvectors::test_aead_aesccm_16_64_128(&mut state.raw);
    // }

    // #[test]
    // fn test_aead_aesccm_16_64_256(state: &mut super::TestState) {
    //     testvectors::test_aead_aesccm_16_64_256(&mut state.raw);
    // }

    #[test]
    fn bench_aead(state: &mut super::TestState) {
        const ITERS: u32 = 10_000;

        // Enable DWT cycle counter (Cortex-M33): set DEMCR.TRCENA, reset CYCCNT, set CTRL.CYCCNTENA
        unsafe {
            let demcr = 0xE000_EDFC as *mut u32;
            demcr.write_volatile(demcr.read_volatile() | (1 << 24));
            (0xE000_1004 as *mut u32).write_volatile(0);
            let ctrl = 0xE000_1000 as *mut u32;
            ctrl.write_volatile(ctrl.read_volatile() | 1);
        }

        fn cyccnt() -> u32 {
            unsafe { (0xE000_1004 as *const u32).read_volatile() }
        }

        use embedded_cal::AeadProvider;
        use embedded_cal_nrf54l15::AeadAlgorithm;

        let key128 = state
            .raw
            .load_from_keydata(AeadAlgorithm::AesCcm16_64_128, &[0xABu8; 16]);
        let nonce = [0x01u8; 13];
        let aad = [0x02u8; 8];

        // Just to make sure everything is working
        testvectors::test_aead_aesccm_16_64_128(&mut state.raw);

        // AesCcm16_64_128 encrypt
        {
            let mut msg = [0x42u8; 64];
            let t0 = cyccnt();
            for _ in 0..ITERS {
                state
                    .raw
                    .encrypt_in_place(&key128, &nonce, &mut msg, aad.as_slice());
            }
            defmt::info!(
                "AesCcm16_64_128 encrypt 64B: {} cycles/op",
                (cyccnt() - t0) / ITERS
            );
        }

        // AesCcm16_64_128 decrypt
        {
            let mut msg = [0x42u8; 64];
            let tag = state
                .raw
                .encrypt_in_place(&key128, &nonce, &mut msg, aad.as_slice());
            let ct = msg;
            let t0 = cyccnt();
            for _ in 0..ITERS {
                let mut buf = ct;
                let _ = state.raw.decrypt_in_place(
                    &key128,
                    &nonce,
                    &mut buf,
                    tag.as_ref(),
                    aad.as_slice(),
                );
            }
            defmt::info!(
                "AesCcm16_64_128 decrypt 64B: {} cycles/op",
                (cyccnt() - t0) / ITERS
            );
        }
    }
}
