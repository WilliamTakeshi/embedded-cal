// P-256 curve constants (big-endian u32 words, most-significant word first).
// Source: SEC 2 / NIST FIPS 186-4.
const P256_COEF_A: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000003,
];
const P256_COEF_A_SIGN: u32 = 1; // a = -3, sign = 1 (negative)
const P256_COEF_B: [u32; 8] = [
    0x5ac635d8, 0xaa3a93e7, 0xb3ebbd55, 0x769886bc, 0x651d06b0, 0xcc53b0f6, 0x3bce3c3e, 0x27d2604b,
];
const P256_MODULUS: [u32; 8] = [
    0xffffffff, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff,
];
const P256_PRIME_ORDER: [u32; 8] = [
    0xffffffff, 0x00000000, 0xffffffff, 0xffffffff, 0xbce6faad, 0xa7179e84, 0xf3b9cac2, 0xfc632551,
];
const P256_GX: [u32; 8] = [
    0x6b17d1f2, 0xe12c4247, 0xf8bce6e5, 0x63a440f2, 0x77037d81, 0x2deb33a0, 0xf4a13945, 0xd898c296,
];
const P256_GY: [u32; 8] = [
    0x4fe342e2, 0xfe1a7f9b, 0x8ee7eb4a, 0x7c0f9e16, 0x2bce3357, 0x6b315ece, 0xcbb64068, 0x37bf51f5,
];

// PKA RAM word indices for ECC scalar multiplication.
// pka.ram(n) is at PKA_BASE + 0x400 + n * 4.
// Source: STM32WBA55 RM0493, ECC scalar multiplication parameter table.
const RAM_N_LEN: usize = 0; // prime order bit length
const RAM_P_LEN: usize = 2; // modulus bit length
const RAM_A_SIGN: usize = 4; // coefficient a sign (0 = positive, 1 = negative)
const RAM_A: usize = 6; // coefficient |a|
const RAM_B: usize = 72; // coefficient b
const RAM_P: usize = 802; // field prime p
const RAM_POINT_X: usize = 94; // input point x (result x overwrites this)
const RAM_POINT_Y: usize = 28; // input point y
const RAM_N: usize = 738; // prime order n
const RAM_K: usize = 936; // scalar k
const RAM_RESULT_Y: usize = 116; // result point y (separate from input y)

const PKA_MODE_ECC_MULT: u8 = 0b10_0000; // Montgomery parameter + ECC scalar multiplication
const PKA_RAM_WORDS: usize = 667;

#[derive(PartialEq, Eq, Debug, Clone)]
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

pub struct DhSecretKey {
    alg: DhAlgorithm,
    bytes: [u8; 32],
}

pub struct DhPublicKey {
    alg: DhAlgorithm,
    x: [u8; 32],
    y: [u8; 32],
}

pub struct DhSharedSecret([u8; 32]);

impl embedded_cal::SharedSecret for DhSharedSecret {
    fn raw_secret_bytes<C>(&self, _cal: &mut C) -> impl AsRef<[u8]>
    where
        C: embedded_cal::DhProvider<SharedSecret = Self>,
    {
        &self.0
    }
}

impl super::Stm32wba55Cal {
    fn pka_zero_ram(&mut self) {
        for i in 0..PKA_RAM_WORDS {
            self.pka.ram(i).write_value(0);
        }
    }

    // Write a 256-bit field element (8 u32 big-endian words) to PKA RAM.
    // PKA stores values in little-endian word order (least-significant word first),
    // so the input array (most-significant word first) is written in reverse.
    fn pka_write_field(&mut self, start: usize, words: &[u32; 8]) {
        for (i, &word) in words.iter().rev().enumerate() {
            self.pka.ram(start + i).write_value(word);
        }
    }

    // Read a 256-bit field element from PKA RAM into big-endian word order.
    fn pka_read_field(&mut self, start: usize) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (i, w) in words.iter_mut().rev().enumerate() {
            *w = self.pka.ram(start + i).read();
        }
        words
    }

    // Perform a P-256 ECC scalar multiplication k * (x, y) using the PKA hardware.
    // Returns (result_x, result_y) in big-endian u32 word order.
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
        self.pka.ram(RAM_A_SIGN).write_value(P256_COEF_A_SIGN);
        self.pka_write_field(RAM_A, &P256_COEF_A);
        self.pka_write_field(RAM_B, &P256_COEF_B);
        self.pka_write_field(RAM_P, &P256_MODULUS);
        self.pka_write_field(RAM_N, &P256_PRIME_ORDER);
        self.pka_write_field(RAM_POINT_X, point_x);
        self.pka_write_field(RAM_POINT_Y, point_y);
        self.pka_write_field(RAM_K, scalar);

        self.pka.cr().write(|w| {
            w.set_en(true);
            w.set_mode(PKA_MODE_ECC_MULT);
            w.set_start(true);
        });

        while self.pka.sr().read().busy() {}

        // Check hardware error flags in SR; these indicate address/RAM access faults.
        // The RAM word previously used as an "error indicator" is only valid for the
        // point-check opcode (0b101000), not for scalar multiplication.
        let sr = self.pka.sr().read();
        let hw_error = sr.addrerrf() || sr.ramerrf();

        let result_x = self.pka_read_field(RAM_POINT_X);
        let result_y = self.pka_read_field(RAM_RESULT_Y);

        self.pka.clrfr().write(|w| {
            w.set_procendfc(true);
            w.set_ramerrfc(true);
            w.set_addrerrfc(true);
            w.set_operrfc(true);
        });

        assert!(!hw_error, "PKA ECC scalar multiplication failed (SR error flags set)");

        (result_x, result_y)
    }
}

fn bytes_to_words(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    words
}

fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    bytes
}

impl embedded_cal::DhProvider for super::Stm32wba55Cal {
    type DhAlgorithm = DhAlgorithm;
    type SecretKey = DhSecretKey;
    type PublicKey = DhPublicKey;
    type SharedSecret = DhSharedSecret;

    fn load_secret_key(&mut self, alg: Self::DhAlgorithm, bytes: &[u8]) -> Self::SecretKey {
        DhSecretKey {
            alg,
            bytes: bytes
                .try_into()
                .expect("secret key must be 32 bytes for P-256"),
        }
    }

    fn load_public_key(&mut self, alg: Self::DhAlgorithm, x: &[u8], y: &[u8]) -> Self::PublicKey {
        DhPublicKey {
            alg,
            x: x.try_into()
                .expect("public key x must be 32 bytes for P-256"),
            y: y.try_into()
                .expect("public key y must be 32 bytes for P-256"),
        }
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        if private.alg != public.alg {
            return Err(embedded_cal::IncompatibleKeys);
        }
        let (result_x, _) = self.pka_ecc_mult(
            &bytes_to_words(&private.bytes),
            &bytes_to_words(&public.x),
            &bytes_to_words(&public.y),
        );
        Ok(DhSharedSecret(words_to_bytes(&result_x)))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        let (result_x, result_y) =
            self.pka_ecc_mult(&bytes_to_words(&private.bytes), &P256_GX, &P256_GY);
        DhPublicKey {
            alg: private.alg.clone(),
            x: words_to_bytes(&result_x),
            y: words_to_bytes(&result_y),
        }
    }
}
