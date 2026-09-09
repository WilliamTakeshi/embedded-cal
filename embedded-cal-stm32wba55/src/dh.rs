// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use crate::dh_plumbing::{StmPoint, StmScalar};
use embedded_cal::p256::{
    B, P, P256_GX_BYTES, P256_GY_BYTES, P256_ORDER, bytes_to_words, ge, p256_recover_y,
};
use embedded_cal::plumbing::ec::{Ec, EcPrimitives};
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
// Full extent of the PKA RAM. This has to cover every slot the operation touches, in particular
// RAM_K at 936 where the private scalar goes -- a smaller bound leaves the scalar in RAM.
const PKA_RAM_WORDS: usize = 1334;

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
    scalar: StmScalar,
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
    point: StmPoint,
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
                    let scalar = self
                        .p256()
                        .import_scalar_bytes(&scalar)
                        .expect("32 bytes is the P-256 scalar length");
                    return VisibleSecretKey(SecretKey { alg, scalar });
                }
            },
        }
    }

    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s> {
        // Owned rather than borrowed: the plumbing's scalars are not stored in the exported byte
        // order, so there is nothing to hand out a reference to.
        to_array(
            self.p256()
                .export_scalar_bytes(&secretkey.0.scalar)
                .as_ref(),
        )
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::Algorithm,
        secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        let scalar = self.p256().import_scalar_bytes(secret)?;
        Ok(VisibleSecretKey(SecretKey { alg, scalar }))
    }

    fn export_publickey_bytes<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> impl AsRef<[u8]> + use<'p> {
        let x = self.p256().x_coord(&public.point);
        to_array(self.p256().export_scalar_bytes(&x).as_ref())
    }

    fn import_publickey_bytes(
        &mut self,
        alg: Self::Algorithm,
        data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        let x: &[u8; 32] = data.try_into().map_err(|_| embedded_cal::ImportError)?;
        let y = p256_recover_y(x)?;
        let x = self.p256().import_scalar_bytes(x)?;
        let y = self.p256().import_scalar_bytes(&y)?;
        let point = self.p256().point(x, y);
        Ok(PublicKey { alg, point })
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        if private.alg != public.alg {
            return Err(embedded_cal::IncompatibleKeys);
        }
        let result = self
            .p256()
            .multiply_scalar_point(&private.scalar, &public.point);
        Ok(SharedSecret(self.x_coord_bytes(&result)))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let base = self.base_point();
        PublicKey {
            alg: private.alg.clone(),
            point: self.p256().multiply_scalar_point(&private.scalar, &base),
        }
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s> {
        &secret.0
    }
}

impl super::Stm32wba55Cal {
    /// Builds the P-256 generator as a plumbing point.
    fn base_point(&mut self) -> StmPoint {
        let x = self
            .p256()
            .import_scalar_bytes(&P256_GX_BYTES)
            .expect("generator x is a valid scalar");
        let y = self
            .p256()
            .import_scalar_bytes(&P256_GY_BYTES)
            .expect("generator y is a valid scalar");
        self.p256().point(x, y)
    }

    /// Extracts a point's x coordinate into owned bytes.
    fn x_coord_bytes(&mut self, point: &StmPoint) -> [u8; 32] {
        let x = self.p256().x_coord(point);
        to_array(self.p256().export_scalar_bytes(&x).as_ref())
    }
}

/// Copies an exported scalar into an owned array.
///
/// Exports are handed out as slices, but the `DhProvider` return types have to outlive the
/// borrow of the CAL, so the bytes are copied out.
fn to_array(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("P-256 scalars are 32 bytes")
}
