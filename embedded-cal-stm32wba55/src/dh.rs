// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::p256::{
    B, P, P256_COEF_A, P256_GX, P256_GY, P256_ORDER, SQRT_EXP, bytes_to_words, ge, words_to_bytes,
};
use rand_core::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// P-256 curve constants (little-endian word order: LSW at index 0)

const P256_COEF_A_MAGNITUDE: [u32; 8] = [0x0000_0003, 0, 0, 0, 0, 0, 0, 0];
#[repr(u32)]
enum CoefSign {
    _Positive = 0, // unused: P-256 coefficient a is always negative
    Negative = 1,
}

// PKA RAM slot indices for ECC scalar multiplication (STM32WBA55 RM0493)

const RAM_N_LEN: usize = 0;
const RAM_P_LEN: usize = 2;
const RAM_A_SIGN: usize = 4;
const RAM_A: usize = 6;
const RAM_B: usize = 72;
const RAM_P: usize = 802;
const RAM_POINT_X: usize = 94;
const RAM_POINT_Y: usize = 28;
const RAM_N: usize = 738;
const RAM_K: usize = 936;
const RAM_RESULT_Y: usize = 116;

const PKA_MODE_ECC_MULT: u8 = 0b10_0000;
const PKA_RAM_WORDS: usize = 667;

// PKA RAM slot indices for the generic modular-arithmetic modes (RM0493 section 28.4.2-28.4.6).
// This is a *different* RAM layout than the ECC-mult slots above (section 28.4.15) --
// addresses come straight from RM0493's per-mode tables (given there in bytes; divided by 4
// for the word-indexed `pka.ram()` accessor) and are reused across modes the way the manual
// itself reuses them (e.g. RAM@0xC68 is "Operand B" for add/mul but "Operand A" for exponentiation).
const RAM_ARITH_EXP_LEN: usize = 0x400 / 4; // exponent length in bits (mode 0x02 only)
const RAM_ARITH_OPERAND_LEN: usize = 0x408 / 4; // operand/modulus length in bits (all modes)
const RAM_ARITH_OPERAND_A: usize = 0xA50 / 4;
const RAM_ARITH_OPERAND_B: usize = 0xC68 / 4; // also: modexp base operand (IN/OUT)
const RAM_ARITH_MODULUS: usize = 0x1088 / 4;
const RAM_ARITH_RESULT: usize = 0xE78 / 4; // also: modexp exponent (IN)
const RAM_ARITH_MONT_R2: usize = 0x620 / 4; // Montgomery parameter R^2 mod n
const RAM_ARITH_EXP_RESULT: usize = 0x838 / 4; // modexp result

const PKA_MODE_MONT_PARAM: u8 = 0b00_0001;
const PKA_MODE_MOD_ADD: u8 = 0b00_1110;
const PKA_MODE_MOD_MUL: u8 = 0b01_0000;
const PKA_MODE_MOD_EXP_FAST: u8 = 0b00_0010;

#[derive(PartialEq, Eq, Debug, Clone, Zeroize)]
pub enum DhAlgorithm {
    EcdhP256,
}

impl embedded_cal::DhAlgorithm for DhAlgorithm {
    fn output_length(&self) -> usize {
        match self {
            DhAlgorithm::EcdhP256 => 32,
        }
    }

    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        match curve.into() {
            1 => Some(DhAlgorithm::EcdhP256),
            _ => None,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    alg: DhAlgorithm,
    scalar: [u8; 32],
}

#[derive(Zeroize)]
pub struct VisibleSecretKey(SecretKey);

impl From<VisibleSecretKey> for SecretKey {
    fn from(v: VisibleSecretKey) -> Self {
        v.0
    }
}

pub struct PublicKey {
    alg: DhAlgorithm,
    x: [u8; 32],
    y: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl super::Stm32wba55Cal {
    fn pka_zero_ram(&mut self) {
        for i in 0..PKA_RAM_WORDS {
            self.pka.ram(i).write_value(0);
        }
    }

    // Write a 256-bit value (LE word order, LSW first) to PKA RAM.
    fn pka_write_field(&mut self, start: usize, words: &[u32; 8]) {
        for (i, &word) in words.iter().enumerate() {
            self.pka.ram(start + i).write_value(word);
        }
    }

    // Read a 256-bit value from PKA RAM into LE word order.
    fn pka_read_field(&mut self, start: usize) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (i, w) in words.iter_mut().enumerate() {
            *w = self.pka.ram(start + i).read();
        }
        words
    }

    pub(super) fn pka_ecc_mult(
        &mut self,
        scalar: &[u32; 8],
        point_x: &[u32; 8],
        point_y: &[u32; 8],
    ) -> ([u32; 8], [u32; 8]) {
        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_N_LEN).write_value(256);
        self.pka.ram(RAM_P_LEN).write_value(256);
        self.pka
            .ram(RAM_A_SIGN)
            .write_value(CoefSign::Negative as u32);
        self.pka_write_field(RAM_A, &P256_COEF_A_MAGNITUDE);
        self.pka_write_field(RAM_B, &B);
        self.pka_write_field(RAM_P, &P);
        self.pka_write_field(RAM_N, &P256_ORDER);
        self.pka_write_field(RAM_POINT_X, point_x);
        self.pka_write_field(RAM_POINT_Y, point_y);
        self.pka_write_field(RAM_K, scalar);

        self.pka.cr().write(|w| {
            w.set_en(true);
            w.set_mode(PKA_MODE_ECC_MULT);
            w.set_start(true);
        });

        while self.pka.sr().read().busy() {}

        let sr = self.pka.sr().read();
        // addrerrf / ramerrf indicate address or RAM access faults.
        // Do NOT check pka.ram(160): that word is only valid for the point-check
        // opcode (0b101000), not for scalar multiplication.
        debug_assert!(
            !sr.addrerrf() && !sr.ramerrf(),
            "PKA ECC scalar multiplication failed (SR error flags set)"
        );

        let result_x = self.pka_read_field(RAM_POINT_X);
        let result_y = self.pka_read_field(RAM_RESULT_Y);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });

        // Zero PKA RAM to clear the private scalar (RAM_K) and result coordinates.
        self.pka_zero_ram();

        (result_x, result_y)
    }

    // Starts a PKA operation in the given mode, waits for completion, and asserts no
    // error flags were raised. Caller writes operands into RAM before calling this, and
    // is responsible for clearing flags/RAM before/after around the whole operation.
    fn pka_run(&mut self, mode: u8) {
        self.pka.cr().write(|w| {
            w.set_en(true);
            w.set_mode(mode);
            w.set_start(true);
        });

        while self.pka.sr().read().busy() {}

        let sr = self.pka.sr().read();
        debug_assert!(
            !sr.addrerrf() && !sr.ramerrf(),
            "PKA operation (mode {mode:#04x}) failed (SR error flags set)"
        );
    }

    // Modular addition (a + b) mod P on the PKA (RM0493 section 28.4.3, mode 0x0E).
    fn pka_add_mod(&mut self, a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_ARITH_OPERAND_LEN).write_value(256);
        self.pka_write_field(RAM_ARITH_OPERAND_A, a);
        self.pka_write_field(RAM_ARITH_OPERAND_B, b);
        self.pka_write_field(RAM_ARITH_MODULUS, &P);

        self.pka_run(PKA_MODE_MOD_ADD);

        let result = self.pka_read_field(RAM_ARITH_RESULT);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        result
    }

    // Computes the Montgomery parameter R^2 mod P (RM0493 section 28.4.2, mode 0x01),
    // needed to bring an operand into the Montgomery domain before a Montgomery
    // multiplication (mode 0x10, see `pka_mont_mul`).
    fn pka_mont_param(&mut self) -> [u32; 8] {
        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_ARITH_OPERAND_LEN).write_value(256);
        self.pka_write_field(RAM_ARITH_MODULUS, &P);

        self.pka_run(PKA_MODE_MONT_PARAM);

        let r2 = self.pka_read_field(RAM_ARITH_MONT_R2);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        r2
    }

    // One raw Montgomery-multiplication hardware call (RM0493 section 28.4.5, mode 0x10):
    // computes (a * b) mod P. Whether the result lands in the Montgomery or natural domain
    // depends on which domain `a`/`b` are in -- see `pka_mul_mod`'s two-call use of this.
    fn pka_mont_mul(&mut self, a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_ARITH_OPERAND_LEN).write_value(256);
        self.pka_write_field(RAM_ARITH_OPERAND_A, a);
        self.pka_write_field(RAM_ARITH_OPERAND_B, b);
        self.pka_write_field(RAM_ARITH_MODULUS, &P);

        self.pka_run(PKA_MODE_MOD_MUL);

        let result = self.pka_read_field(RAM_ARITH_RESULT);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        result
    }

    // Modular multiplication (a * b) mod P, entirely on PKA hardware. Per RM0493 section
    // 28.4.5's "simple modular multiplication" recipe: bring `a` into the Montgomery
    // domain (multiply by R^2 mod P), then multiply that by `b` -- the second Montgomery
    // multiplication naturally yields the result back in the natural domain.
    fn pka_mul_mod(&mut self, a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
        let r2 = self.pka_mont_param();
        let a_mont = self.pka_mont_mul(a, &r2);
        self.pka_mont_mul(&a_mont, b)
    }

    // Modular exponentiation base^exp mod P on the PKA (RM0493 section 28.4.6, fast mode
    // 0x02). `exp` is public here (the fixed square-root exponent), so the side-channel
    // protected mode 0x03 is unnecessary.
    fn pka_pow_mod(&mut self, base: &[u32; 8], exp: &[u32; 8]) -> [u32; 8] {
        let r2 = self.pka_mont_param();

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        self.pka.ram(RAM_ARITH_EXP_LEN).write_value(256);
        self.pka.ram(RAM_ARITH_OPERAND_LEN).write_value(256);
        self.pka_write_field(RAM_ARITH_OPERAND_B, base);
        self.pka_write_field(RAM_ARITH_RESULT, exp);
        self.pka_write_field(RAM_ARITH_MODULUS, &P);
        self.pka_write_field(RAM_ARITH_MONT_R2, &r2);

        self.pka_run(PKA_MODE_MOD_EXP_FAST);

        let result = self.pka_read_field(RAM_ARITH_EXP_RESULT);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });
        self.pka_zero_ram();

        result
    }

    // Recovers the y-coordinate of a P-256 point from its x-coordinate, entirely on PKA
    // hardware: computes rhs = x^3 + A*x + B mod P via pka_add_mod/pka_mul_mod, then
    // y = rhs^((p+1)/4) mod P via pka_pow_mod (valid since p = 3 mod 4), and verifies
    // y^2 == rhs. Mirrors the software `p256_recover_y` composition, just hardware-backed.
    pub(super) fn pka_recover_y(
        &mut self,
        x_bytes: &[u8; 32],
    ) -> Result<[u8; 32], embedded_cal::ImportError> {
        let x = bytes_to_words(x_bytes);

        if ge(&x, &P) {
            return Err(embedded_cal::ImportError);
        }

        let x2 = self.pka_mul_mod(&x, &x);
        let x3 = self.pka_mul_mod(&x2, &x);
        let ax = self.pka_mul_mod(&P256_COEF_A, &x);
        let sum = self.pka_add_mod(&x3, &ax);
        let rhs = self.pka_add_mod(&sum, &B);

        let y = self.pka_pow_mod(&rhs, &SQRT_EXP);

        if self.pka_mul_mod(&y, &y) != rhs {
            return Err(embedded_cal::ImportError);
        }

        Ok(words_to_bytes(&y))
    }
}

impl embedded_cal::DhProvider for super::Stm32wba55Cal {
    type Algorithm = DhAlgorithm;
    type VisibleSecretKey = VisibleSecretKey;
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_visible(&mut self, alg: Self::Algorithm) -> Self::VisibleSecretKey {
        match alg {
            DhAlgorithm::EcdhP256 => loop {
                let mut scalar = [0u8; 32];
                // Error = Infallible for this RNG
                self.fill_bytes(&mut scalar);
                let w = bytes_to_words(&scalar);
                if w != [0u32; 8] && !ge(&w, &P256_ORDER) {
                    return VisibleSecretKey(SecretKey { alg, scalar });
                }
            },
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secretkey.0.scalar
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let scalar: [u8; 32] = secret.try_into().map_err(|_| embedded_cal::ImportError)?;
        Ok(VisibleSecretKey(SecretKey { alg, scalar }))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        &public.x
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        let x: [u8; 32] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
        let y = self.pka_recover_y(&x)?;
        Ok(PublicKey { alg, x, y })
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        if private.alg != public.alg {
            return Err(embedded_cal::IncompatibleKeys);
        }
        let mut scalar_words = bytes_to_words(&private.scalar);
        let (result_x, _) = self.pka_ecc_mult(
            &scalar_words,
            &bytes_to_words(&public.x),
            &bytes_to_words(&public.y),
        );
        scalar_words.zeroize();
        Ok(SharedSecret(words_to_bytes(&result_x)))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let mut scalar_words = bytes_to_words(&private.scalar);
        let (result_x, result_y) = self.pka_ecc_mult(&scalar_words, &P256_GX, &P256_GY);
        scalar_words.zeroize();
        PublicKey {
            alg: private.alg.clone(),
            x: words_to_bytes(&result_x),
            y: words_to_bytes(&result_y),
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secret.0
    }
}
