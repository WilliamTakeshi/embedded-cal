use nrf_pac::cracencore::vals::{Selcurve, Swapbytes};

// CRACEN PK slot layout.
// Each slot is 0x200 bytes. For P-256 (32-byte operands) data sits at the
// end of each slot: slot_base + 0x200 - 32 = slot_base + 0x1E0.
const CRACEN_PKE_RAM_BASE: u32 = 0x5180_8000;
const SLOT_SIZE: u32 = 0x200;
const P256_SLOT_OFFSET: u32 = SLOT_SIZE - 32; // 0x1E0

// Slot assignments for P-256 scalar multiplication (opeaddr = 0x22).
const SLOT_SCALAR: u32 = 8; // k
const SLOT_POINT_X: u32 = 12; // input Px / output Rx
const SLOT_POINT_Y: u32 = 13; // input Py
const SLOT_RESULT_X: u32 = 10; // output Rx
const SLOT_RESULT_Y: u32 = 11; // output Ry

const PKE_OPCODE_ECC_MULT: u8 = 0x22;
const P256_BYTES_M1: u16 = 31; // 32 bytes - 1

#[inline(always)]
fn slot_addr(slot: u32) -> u32 {
    CRACEN_PKE_RAM_BASE + slot * SLOT_SIZE + P256_SLOT_OFFSET
}

// Write 32 bytes to a CRACEN RAM slot as little-endian u32 words.
// With swapbytes = SWAPPED in the PK command, the hardware interprets
// each word in big-endian order, preserving the standard crypto byte order.
unsafe fn write_slot(addr: u32, data: &[u8; 32]) {
    let mut p = addr as *mut u32;
    for chunk in data.chunks_exact(4) {
        let v = u32::from_le_bytes(chunk.try_into().unwrap());
        unsafe { core::ptr::write_volatile(p, v) };
        p = unsafe { p.add(1) };
    }
}

// Read 32 bytes from a CRACEN RAM slot, reversing the LE→BE swap done on write.
unsafe fn read_slot(addr: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut p = addr as *const u32;
    for i in 0..8 {
        let v = unsafe { core::ptr::read_volatile(p) };
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        p = unsafe { p.add(1) };
    }
    out
}


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

impl super::Nrf54l15Cal {
    // Perform a P-256 ECC scalar multiplication k * (px, py) using the CRACEN PKE.
    // Returns (result_x, result_y) in big-endian byte order.
    pub(super) fn cracen_ecc_mult(
        &mut self,
        scalar: &[u8; 32],
        px: &[u8; 32],
        py: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        // Wait for PKE and IKG to be idle before configuring
        while self.cracen_core.pk().status().read().pkbusy() {}
        while self.cracen_core.ikg().status().read().ctrdrbgbusy() {}

        unsafe {
            // Configure: ECC scalar multiplication, 32 bytes, P-256, big-endian input
            self.cracen_core.pk().command().write(|w| {
                w.set_opeaddr(PKE_OPCODE_ECC_MULT);
                w.set_opbytesm1(P256_BYTES_M1);
                w.set_selcurve(Selcurve::P256);
                w.set_swapbytes(Swapbytes::SWAPPED);
            });

            while self.cracen_core.pk().status().read().pkbusy() {}
            while self.cracen_core.ikg().status().read().ctrdrbgbusy() {}

            // Load operands into CRACEN RAM
            write_slot(slot_addr(SLOT_SCALAR), scalar);
            write_slot(slot_addr(SLOT_POINT_X), px);
            write_slot(slot_addr(SLOT_POINT_Y), py);

            // Set operand pointers: A = point (slots 12/13), B = scalar (8), C = output (10/11)
            self.cracen_core.pk().pointers().write(|w| {
                w.set_opptra(SLOT_POINT_X as u8);
                w.set_opptrb(SLOT_SCALAR as u8);
                w.set_opptrc(SLOT_RESULT_X as u8);
            });

            // Start
            self.cracen_core.pk().control().write(|w| {
                w.set_start(true);
                w.set_clearirq(true);
            });
        }

        while self.cracen_core.pk().status().read().pkbusy() {}
        while self.cracen_core.ikg().status().read().ctrdrbgbusy() {}

        let status = self.cracen_core.pk().status().read();
        assert!(
            status.errorflags() == 0 && status.failptr() == 0,
            "CRACEN PKE ECC scalar multiplication failed (errorflags={:#x}, failptr={:#x})",
            status.errorflags(),
            status.failptr(),
        );

        let rx = unsafe { read_slot(slot_addr(SLOT_RESULT_X)) };
        let ry = unsafe { read_slot(slot_addr(SLOT_RESULT_Y)) };

        (rx, ry)
    }
}

impl embedded_cal::DhProvider for super::Nrf54l15Cal {
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
        let (result_x, _) = self.cracen_ecc_mult(&private.bytes, &public.x, &public.y);
        Ok(DhSharedSecret(result_x))
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        const P256_GX: [u8; 32] = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ];
        const P256_GY: [u8; 32] = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ];
        let (result_x, result_y) = self.cracen_ecc_mult(&private.bytes, &P256_GX, &P256_GY);
        DhPublicKey {
            alg: private.alg.clone(),
            x: result_x,
            y: result_y,
        }
    }
}

