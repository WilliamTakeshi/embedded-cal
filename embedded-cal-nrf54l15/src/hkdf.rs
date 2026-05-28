// HKDF is not directly supported by the nRF54L15 hardware.
//
// Use `embedded_cal_software::Extender` wrapping this type to get a
// software HKDF-SHA-256 implementation built on top of the hardware SHA-256.

impl embedded_cal::HkdfProvider for super::Nrf54l15Cal {
    type Algorithm = embedded_cal::empty::NoAlgorithms;
    type HkdfState = embedded_cal::empty::NoAlgorithms;
    type PrkResult = embedded_cal::empty::NoAlgorithms;

    fn hkdf_new(
        &mut self,
        algorithm: Self::Algorithm,
        _salt: Option<&[u8]>,
        _ikm: &[u8],
    ) -> Self::HkdfState {
        match algorithm {}
    }

    fn hkdf_extract(
        &mut self,
        algorithm: Self::Algorithm,
        _salt: Option<&[u8]>,
        _ikm: &[u8],
    ) -> (Self::PrkResult, Self::HkdfState) {
        match algorithm {}
    }

    fn hkdf_from_prk(
        &mut self,
        algorithm: Self::Algorithm,
        _prk: &[u8],
    ) -> Result<Self::HkdfState, embedded_cal::HkdfError> {
        match algorithm {}
    }

    fn hkdf_expand(
        &mut self,
        state: &Self::HkdfState,
        _info: &[u8],
        _okm: &mut [u8],
    ) -> Result<(), embedded_cal::HkdfError> {
        match *state {}
    }
}
