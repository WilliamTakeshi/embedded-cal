// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
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
}

/// A failed `decrypt_in_place` must not leave (unauthenticated) plaintext in the caller's buffer:
/// the nRF54 back-end decrypts in place during the DMA, then zeroizes the buffer when the tag check
/// fails. Vector: RFC3610 Packet Vector #1 (AES-CCM-16-64-128; 23-byte payload exercises the
/// sub-word padding path).
fn assert_decrypt_zeroizes_on_auth_failure<AP: embedded_cal::AeadProvider>(cal: &mut AP) {
    use embedded_cal::AeadAlgorithm;

    const KEY: [u8; 16] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf,
    ];
    const NONCE: [u8; 13] = [
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    ];
    const AAD: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const CIPHERTEXT: [u8; 23] = [
        0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89,
        0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
    ];
    const PLAINTEXT: [u8; 23] = [
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    ];
    const TAG: [u8; 8] = [0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0];

    let alg = AP::Algorithm::from_cose_number(10i16)
        .expect("AES-CCM-16-64-128 (COSE 10) not supported");
    let key = cal.load_from_keydata(alg, &KEY);

    // Positive control: with the correct tag the buffer decrypts to the plaintext (i.e. the vector
    // is valid and the zeroize path does not fire on success).
    let mut buf = CIPHERTEXT;
    cal.decrypt_in_place(&key, &NONCE, &mut buf, &TAG, &AAD[..])
        .expect("valid tag should decrypt");
    assert_eq!(buf, PLAINTEXT, "decryption mismatch: {:02x?}", buf);

    // Corrupt one tag byte: authentication must fail and the buffer must be fully zeroized rather
    // than holding the (unauthenticated) plaintext.
    let mut buf = CIPHERTEXT;
    let mut bad_tag = TAG;
    bad_tag[0] ^= 0x01;
    let res = cal.decrypt_in_place(&key, &NONCE, &mut buf, &bad_tag, &AAD[..]);
    assert!(res.is_err(), "corrupted tag must fail authentication");
    assert!(
        buf.iter().all(|&b| b == 0),
        "buffer must be zeroized on auth failure, got {:02x?}",
        buf
    );
}

#[defmt_test::tests]
mod tests {
    use super::ImplementSha256Short;
    use embedded_cal::Cal;
    use embedded_cal_nrf54l15::Nrf54l15Cal;

    #[init]
    fn init() -> super::TestState {
        // FIXME: How to make sure there is a exclusive reference for CRACEN_S?
        let base =
            embedded_cal_nrf54l15::Nrf54l15Cal::new(nrf_pac::CRACEN_S, nrf_pac::CRACENCORE_S);

        let cal = embedded_cal_software_demo::Extender::<ImplementSha256Short>::new(base);

        super::TestState { cal }
    }

    #[test]
    fn test_hash_algorithm_sha256(state: &mut super::TestState) {
        embedded_cal::test_hash_algorithm_sha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut state.cal);
    }

    #[test]
    fn test_hmac_sha256(state: &mut super::TestState) {
        embedded_cal::test_hmac_algorithm_hmacsha256::<
            <embedded_cal_software_demo::Extender<ImplementSha256Short> as embedded_cal::HmacProvider>::Algorithm,
        >();
        testvectors::test_hmac_sha256(&mut state.cal);
    }

    #[test]
    fn test_hkdf_sha256(state: &mut super::TestState) {
        testvectors::test_hkdf_sha256(&mut state.cal);
    }

    #[test]
    fn test_tryrng(state: &mut super::TestState) {
        embedded_cal::test_tryrng(&mut state.cal);
    }

    #[test]
    fn test_aead_aesccm_16_64_128(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_128(state.cal.aead());
    }

    #[test]
    fn test_aead_aesccm_decrypt_zeroizes_on_auth_failure(state: &mut super::TestState) {
        super::assert_decrypt_zeroizes_on_auth_failure(state.cal.aead());
    }

    #[test]
    fn test_aead_aesccm_16_64_256(state: &mut super::TestState) {
        testvectors::test_aead_aesccm_16_64_256(state.cal.aead());
    }

    #[test]
    fn test_dh_ecdh_p256(state: &mut super::TestState) {
        embedded_cal::test_dh_algorithm_ecdh_p256::<Nrf54l15Cal>();
        for v in testvectors::dh::RFC5903_P256 {
            v.test_with(state.cal.dh());
        }
    }

    #[test]
    fn test_dh_x25519(state: &mut super::TestState) {
        for v in testvectors::dh::RFC7748_X25519 {
            v.test_with(state.cal.dh());
        }
    }

    #[test]
    fn test_dh_x448(state: &mut super::TestState) {
        for v in testvectors::dh::RFC7748_X448 {
            v.test_with(state.cal.dh());
        }
    }
}
