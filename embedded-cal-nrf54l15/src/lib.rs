#![no_std]
mod descriptor;
mod inner;
mod try_rng;

use inner::Nrf54l15CalInner;

pub struct DefaultConfig;

impl embedded_cal_software::ExtenderConfig for DefaultConfig {
    const IMPLEMENT_SHA2SHORT: bool = true;
    type Base = Nrf54l15CalInner;
}

pub struct Nrf54l15Cal(embedded_cal_software::Extender<DefaultConfig>);

impl Nrf54l15Cal {
    pub fn new(
        cracen: nrf_pac::cracen::Cracen,
        cracen_core: nrf_pac::cracencore::Cracencore,
    ) -> Self {
        Self(embedded_cal_software::Extender::new(
            Nrf54l15CalInner::new_inner(cracen, cracen_core),
        ))
    }
}

impl embedded_cal::Cal for Nrf54l15Cal {}

impl rand_core::TryCryptoRng for Nrf54l15Cal {}
impl rand_core::TryRng for Nrf54l15Cal {
    type Error = try_rng::RngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dst)
    }
}

impl embedded_cal::HashProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal_software::HashAlgorithm<DefaultConfig>;
    type HashState = embedded_cal_software::HashState<DefaultConfig>;
    type HashResult = embedded_cal_software::HashResult<DefaultConfig>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        embedded_cal::HashProvider::init(&mut self.0, algorithm)
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        embedded_cal::HashProvider::update(&mut self.0, instance, data)
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        embedded_cal::HashProvider::finalize(&mut self.0, instance)
    }
}

impl embedded_cal::HmacProvider for Nrf54l15Cal {
    type Algorithm = embedded_cal_software::HmacAlgorithm;
    type HmacState = embedded_cal_software::HmacState<DefaultConfig>;
    type HmacResult = embedded_cal_software::HmacResult;

    fn init(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState {
        embedded_cal::HmacProvider::init(&mut self.0, algorithm, key)
    }

    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]) {
        embedded_cal::HmacProvider::update(&mut self.0, state, data)
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        embedded_cal::HmacProvider::finalize(&mut self.0, state)
    }
}
