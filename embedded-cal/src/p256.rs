// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

// P-256 field arithmetic shared by hardware DH back-ends.
//
// All [u32; 8] arrays use little-endian word order: index 0 is the least-significant word.
// Big-endian byte arrays (as used in COSE / CBOR) are converted via `bytes_to_words` /
// `words_to_bytes`.

// p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
pub const P: [u32; 8] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0xFFFF_FFFF,
];

pub const P256_ORDER: [u32; 8] = [
    0xFC63_2551,
    0xF3B9_CAC2,
    0xA717_9E84,
    0xBCE6_FAAD,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0xFFFF_FFFF,
];

pub const B: [u32; 8] = [
    0x27D2_604B,
    0x3BCE_3C3E,
    0xCC53_B0F6,
    0x651D_06B0,
    0x7698_86BC,
    0xB3EB_BD55,
    0xAA3A_93E7,
    0x5AC6_35D8,
];

// P-256 generator point G = (Gx, Gy) in big-endian bytes (NIST FIPS 186-4 D.1.2.3).
pub const P256_GX_BYTES: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
pub const P256_GY_BYTES: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

// Same in little-endian word order (index 0 = least-significant word), matching P, P256_ORDER, B.
pub const P256_GX: [u32; 8] = bytes_to_words(&P256_GX_BYTES);
pub const P256_GY: [u32; 8] = bytes_to_words(&P256_GY_BYTES);

// Exponent (p+1)/4 for modular square root (P-256: p ≡ 3 mod 4)
const SQRT_EXP: [u32; 8] = [
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0xC000_0000,
    0x3FFF_FFFF,
];

pub const fn bytes_to_words(b: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        w[7 - i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        i += 1;
    }
    w
}

pub fn words_to_bytes(w: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[7 - i].to_be_bytes());
    }
    out
}

pub fn ge(a: &[u32; 8], b: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn sub256(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut borrow: i64 = 0;
    for i in 0..8 {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        r[i] = d as u32;
        borrow = if d < 0 { 1 } else { 0 };
    }
    r
}

fn add_mod(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut carry: u64 = 0;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        r[i] = s as u32;
        carry = s >> 32;
    }
    if carry > 0 || ge(&r, &P) {
        sub256(&r, &P)
    } else {
        r
    }
}

fn mul_mod(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..8 {
            let cur = t[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
            t[i + j] = cur as u32;
            carry = cur >> 32;
        }
        t[i + 8] = carry as u32;
    }
    reduce_p256(&t)
}

// NIST FIPS 186-4 Appendix D.2.3 fast reduction for P-256.
fn reduce_p256(t: &[u32; 16]) -> [u32; 8] {
    let c = |i: usize| t[i] as i64;

    let mut acc = [0i64; 8];
    acc[0] = c(0) + c(8) + c(9) - c(11) - c(12) - c(13) - c(14);
    acc[1] = c(1) + c(9) + c(10) - c(12) - c(13) - c(14) - c(15);
    acc[2] = c(2) + c(10) + c(11) - c(13) - c(14) - c(15);
    acc[3] = c(3) + 2 * c(11) + 2 * c(12) + c(13) - c(15) - c(8) - c(9);
    acc[4] = c(4) + 2 * c(12) + 2 * c(13) + c(14) - c(9) - c(10);
    acc[5] = c(5) + 2 * c(13) + 2 * c(14) + c(15) - c(10) - c(11);
    acc[6] = c(6) + 3 * c(14) + 2 * c(15) + c(13) - c(8) - c(9);
    acc[7] = c(7) + 3 * c(15) + c(8) - c(10) - c(11) - c(12) - c(13);

    let mut r = [0u32; 8];
    let mut carry: i64 = 0;
    for i in 0..8 {
        let v = acc[i] + carry;
        r[i] = v as u32;
        carry = v >> 32;
    }

    // Absorb residual carry: 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p).
    for _ in 0..4 {
        if carry == 0 {
            break;
        }
        let adj = carry;
        let mut acc2 = [0i64; 8];
        for i in 0..8 {
            acc2[i] = r[i] as i64;
        }
        acc2[0] += adj;
        acc2[3] -= adj;
        acc2[6] -= adj;
        acc2[7] += adj;
        carry = 0;
        for i in 0..8 {
            let v = acc2[i] + carry;
            r[i] = v as u32;
            carry = v >> 32;
        }
    }

    for _ in 0..2 {
        if ge(&r, &P) {
            r = sub256(&r, &P);
        } else {
            break;
        }
    }
    r
}

fn pow_mod(base: &[u32; 8], exp: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    result[0] = 1;
    let mut base = *base;
    for mut word in exp.iter().copied() {
        for _ in 0..32 {
            if word & 1 != 0 {
                result = mul_mod(&result, &base);
            }
            base = mul_mod(&base, &base);
            word >>= 1;
        }
    }
    result
}

fn sub_mod(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    if ge(a, b) {
        sub256(a, b)
    } else {
        sub256(&P, &sub256(b, a))
    }
}

/// Adds two scalars mod the P-256 curve order `n`.
pub fn add_mod_n(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut r = [0u32; 8];
    let mut carry: u64 = 0;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        r[i] = s as u32;
        carry = s >> 32;
    }
    if carry > 0 || ge(&r, &P256_ORDER) {
        sub256(&r, &P256_ORDER)
    } else {
        r
    }
}

// Reduces a 512-bit value mod the P-256 curve order `n`, bit by bit (long division).
//
// `n` does not have `p`'s special form, so `reduce_p256`'s fast reduction does not apply here;
// this is only called O(1) times per sign/verify, not in a hot loop.
fn reduce_mod_n(t: &[u32; 16]) -> [u32; 8] {
    let mut r = [0u32; 8];
    for word in t.iter().rev() {
        for bit in (0..32).rev() {
            let overflow = r[7] >> 31;
            for i in (1..8).rev() {
                r[i] = (r[i] << 1) | (r[i - 1] >> 31);
            }
            r[0] = (r[0] << 1) | ((word >> bit) & 1);
            if overflow != 0 || ge(&r, &P256_ORDER) {
                r = sub256(&r, &P256_ORDER);
            }
        }
    }
    r
}

/// Multiplies two scalars mod the P-256 curve order `n`.
pub fn mul_mod_n(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..8 {
            let cur = t[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
            t[i + j] = cur as u32;
            carry = cur >> 32;
        }
        t[i + 8] = carry as u32;
    }
    reduce_mod_n(&t)
}

fn pow_mod_n(base: &[u32; 8], exp: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    result[0] = 1;
    let mut base = *base;
    for mut word in exp.iter().copied() {
        for _ in 0..32 {
            if word & 1 != 0 {
                result = mul_mod_n(&result, &base);
            }
            base = mul_mod_n(&base, &base);
            word >>= 1;
        }
    }
    result
}

/// Computes the modular inverse of `a` mod the P-256 curve order `n`, via Fermat's little
/// theorem (`n` is prime).
pub fn inv_mod_n(a: &[u32; 8]) -> [u32; 8] {
    let n_minus_2 = sub256(&P256_ORDER, &[2, 0, 0, 0, 0, 0, 0, 0]);
    pow_mod_n(a, &n_minus_2)
}

/// Adds two P-256 points in affine coordinates.
///
/// Returns `None` if the result is the point at infinity (i.e. `p2 == -p1`); P-256 has prime
/// order, so no valid curve point has `y == 0`, and the caller-visible cases that would produce
/// infinity (e.g. an ECDSA verification combining `u1·G + u2·Q`) are legitimately "no valid
/// result" rather than a computation to recover from.
pub fn point_add(
    p1: (&[u32; 8], &[u32; 8]),
    p2: (&[u32; 8], &[u32; 8]),
) -> Option<([u32; 8], [u32; 8])> {
    let (x1, y1) = p1;
    let (x2, y2) = p2;

    let lambda = if x1 == x2 {
        if y1 != y2 {
            return None;
        }
        // Doubling: lambda = (3*x1^2 + a) / (2*y1), with a = -3 for P-256.
        let three_x1_sq = {
            let x1_sq = mul_mod(x1, x1);
            add_mod(&add_mod(&x1_sq, &x1_sq), &x1_sq)
        };
        let numerator = sub_mod(&three_x1_sq, &[3, 0, 0, 0, 0, 0, 0, 0]);
        let two_y1 = add_mod(y1, y1);
        mul_mod(&numerator, &inv_mod_p(&two_y1))
    } else {
        // lambda = (y2 - y1) / (x2 - x1)
        let numerator = sub_mod(y2, y1);
        let denominator = sub_mod(x2, x1);
        mul_mod(&numerator, &inv_mod_p(&denominator))
    };

    let x3 = sub_mod(&sub_mod(&mul_mod(&lambda, &lambda), x1), x2);
    let y3 = sub_mod(&mul_mod(&lambda, &sub_mod(x1, &x3)), y1);
    Some((x3, y3))
}

/// Computes the modular inverse of `a` mod the P-256 field prime `p`, via Fermat's little
/// theorem (`p` is prime).
fn inv_mod_p(a: &[u32; 8]) -> [u32; 8] {
    let p_minus_2 = sub256(&P, &[2, 0, 0, 0, 0, 0, 0, 0]);
    pow_mod(a, &p_minus_2)
}

// Recover a y coordinate from the compact (x-only) P-256 representation.
// Either square root is accepted because for ECDH the shared secret is the
// x-coordinate of the result point, which is the same for both roots.
pub fn p256_recover_y(x_bytes: &[u8; 32]) -> Result<[u8; 32], crate::ImportError> {
    let x = bytes_to_words(x_bytes);

    if ge(&x, &P) {
        return Err(crate::ImportError);
    }

    // a = p - 3 (since P-256 coefficient a = -3)
    let a = sub256(&P, &[3, 0, 0, 0, 0, 0, 0, 0]);
    let x2 = mul_mod(&x, &x);
    let x3 = mul_mod(&x2, &x);
    let ax = mul_mod(&a, &x);
    let rhs = add_mod(&add_mod(&x3, &ax), &B);

    // y = rhs^((p+1)/4) mod p
    let y = pow_mod(&rhs, &SQRT_EXP);

    if mul_mod(&y, &y) != rhs {
        return Err(crate::ImportError);
    }

    Ok(words_to_bytes(&y))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2G and 3G, independently computed (Python's `cryptography` library, SECP256R1,
    // derive_private_key(k).public_key() for k = 2, 3) rather than hand-derived, so these are a
    // genuine cross-check on `point_add` rather than a restatement of its own formulas.
    const TWO_G_X: [u8; 32] = [
        0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a,
        0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66,
        0x99, 0x78,
    ];
    const TWO_G_Y: [u8; 32] = [
        0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30,
        0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78,
        0x73, 0xd1,
    ];
    const THREE_G_X: [u8; 32] = [
        0x5e, 0xcb, 0xe4, 0xd1, 0xa6, 0x33, 0x0a, 0x44, 0xc8, 0xf7, 0xef, 0x95, 0x1d, 0x4b, 0xf1,
        0x65, 0xe6, 0xc6, 0xb7, 0x21, 0xef, 0xad, 0xa9, 0x85, 0xfb, 0x41, 0x66, 0x1b, 0xc6, 0xe7,
        0xfd, 0x6c,
    ];
    const THREE_G_Y: [u8; 32] = [
        0x87, 0x34, 0x64, 0x0c, 0x49, 0x98, 0xff, 0x7e, 0x37, 0x4b, 0x06, 0xce, 0x1a, 0x64, 0xa2,
        0xec, 0xd8, 0x2a, 0xb0, 0x36, 0x38, 0x4f, 0xb8, 0x3d, 0x9a, 0x79, 0xb1, 0x27, 0xa2, 0x7d,
        0x50, 0x32,
    ];

    #[test]
    fn doubling_g_matches_known_2g() {
        let gx = P256_GX;
        let gy = P256_GY;
        let (x, y) = point_add((&gx, &gy), (&gx, &gy)).expect("G + G is not the point at infinity");
        assert_eq!(words_to_bytes(&x), TWO_G_X);
        assert_eq!(words_to_bytes(&y), TWO_G_Y);
    }

    #[test]
    fn adding_g_and_2g_matches_known_3g() {
        let gx = P256_GX;
        let gy = P256_GY;
        let two_g = (bytes_to_words(&TWO_G_X), bytes_to_words(&TWO_G_Y));
        let (x, y) = point_add((&gx, &gy), (&two_g.0, &two_g.1))
            .expect("G + 2G is not the point at infinity");
        assert_eq!(words_to_bytes(&x), THREE_G_X);
        assert_eq!(words_to_bytes(&y), THREE_G_Y);

        // Addition should be commutative.
        let (x2, y2) = point_add((&two_g.0, &two_g.1), (&gx, &gy))
            .expect("2G + G is not the point at infinity");
        assert_eq!(x, x2);
        assert_eq!(y, y2);
    }

    #[test]
    fn point_add_of_a_point_and_its_negation_is_infinity() {
        let gx = P256_GX;
        let gy = P256_GY;
        let neg_gy = sub256(&P, &gy);
        assert_eq!(point_add((&gx, &gy), (&gx, &neg_gy)), None);
    }

    #[test]
    fn mod_n_inverse_matches_independently_computed_value() {
        // a = 123456789, inv = pow(a, -1, n), both computed independently via Python's `pow`.
        let a = bytes_to_words(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x5b, 0xcd, 0x15,
        ]);
        let expected_inv = bytes_to_words(&[
            0xc4, 0x56, 0xe6, 0x57, 0xee, 0x50, 0x46, 0xdb, 0x78, 0xc1, 0xb3, 0xdd, 0x12, 0x1c,
            0x76, 0xa6, 0x05, 0xcc, 0x12, 0xf9, 0x67, 0xc7, 0xfb, 0x51, 0xe5, 0x14, 0x33, 0xaa,
            0xb9, 0x86, 0xb2, 0xef,
        ]);

        let inv = inv_mod_n(&a);
        assert_eq!(inv, expected_inv);

        let one = [1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mul_mod_n(&a, &inv), one);
    }

    #[test]
    fn mod_n_addition_wraps_around_the_order() {
        let order_minus_1 = sub256(&P256_ORDER, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let one = [1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(add_mod_n(&order_minus_1, &one), [0; 8]);
    }
}
