use embedded_cal::DhProvider;

use super::{Extender, ExtenderConfig};

/// Right now, this is just forwarding, as there is no plumbing yet to build on.
impl<EC: ExtenderConfig> DhProvider for Extender<EC> {
    type DhAlgorithm = <EC::Base as DhProvider>::DhAlgorithm;
    type VisibleSecretKey = <EC::Base as DhProvider>::VisibleSecretKey;
    type SecretKey = <EC::Base as DhProvider>::SecretKey;
    type PublicKey = <EC::Base as DhProvider>::PublicKey;
    type SharedSecret = <EC::Base as DhProvider>::SharedSecret;

    fn generate_visible(&mut self, alg: Self::DhAlgorithm) -> Option<Self::VisibleSecretKey>
    where
        Self: rand_core::TryRng,
    {
        todo!()
    }

    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, embedded_cal::IncompatibleKeys> {
        todo!()
    }

    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey {
        todo!()
    }

    fn raw_secret_bytes<'s>(
        &mut self,
        secret: &'s Self::SharedSecret,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        todo!();
        &[]
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_secretkey_bytes<'s>(
        &mut self,
        secretkey: &'s Self::VisibleSecretKey,
    ) -> impl AsRef<[u8]> + use<'s, EC> {
        todo!();
        &[]
    }

    fn import_secretkey_bytes(
        &mut self,
        alg: Self::DhAlgorithm,
        _secret: &[u8],
    ) -> Result<Self::VisibleSecretKey, embedded_cal::ImportError> {
        todo!();
    }

    #[allow(unreachable_code, reason = "needed to satisfy RPIT")]
    fn export_publickey_okp<'p>(
        &mut self,
        public: &'p Self::PublicKey,
    ) -> Result<impl AsRef<[u8]> + use<'p, EC>, embedded_cal::ExportError> {
        todo!();
        Ok(&[])
    }

    fn import_publickey_okp(
        &mut self,
        alg: Self::DhAlgorithm,
        _data: &[u8],
    ) -> Result<Self::PublicKey, embedded_cal::ImportError> {
        todo!()
    }
}
