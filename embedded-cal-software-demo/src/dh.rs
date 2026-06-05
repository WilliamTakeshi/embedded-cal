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
}
