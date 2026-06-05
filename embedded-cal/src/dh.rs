/// Diffie-Hellman style key establishment.
///
/// This trait does not distinguish between prime factor DH and Elliptic Curve DH (ECDH); it
/// describes the general interface, and many embedded systems likely only implement the latter.
///
/// This trait takes inspiration from the
/// [`elliptic_curve`](https://docs.rs/elliptic-curve/latest/elliptic_curve/) crate, but does not
/// use it directly because
/// - `embedded-cal` passes around an exclusive reference to its engine,
/// - its operation is cryptographically agile rather than monomorphized over algorithms,
/// - only the user visible parts are modelled here (corresponding to
///   [`SecretKey`](https://docs.rs/elliptic-curve/latest/elliptic_curve/struct.SecretKey.html),
///   [`PublicKey`](https://docs.rs/elliptic-curve/latest/elliptic_curve/struct.PublicKey.html) and
///   a [`SharedSecret`](https://docs.rs/elliptic-curve/latest/elliptic_curve/ecdh/struct.SharedSecret.html), and
/// - it does not distinguish, on the type level, between an `EphemeralSecret` and a `SecretKey`,
///   as some protocols such as [Group OSCORE](https://www.ietf.org/archive/id/draft-ietf-core-oscore-groupcomm-28.html)
///   have legitimate use cases for static-static key derivations.
pub trait DhProvider {
    type DhAlgorithm: DhAlgorithm;
    /// A secret key that is intended to be exported.
    ///
    /// It is recommended (but not required) that this is not just [`SecretKey`][Self::SecretKey]
    /// but at least a newtype around it; otherwise, users with knowledge of the concrete
    /// [`Cal`][super::Cal] type (or who require that `C::SecretKey` is identical to or convertible
    /// from a `C::VisibleSecretKey`) could just swap them around.
    ///
    /// ## Rationale
    ///
    /// Visible secret keys are a dedicated type here, compared to the AEAD and HMAC types where
    /// keys are merely loadable because secret keys have more diverse forms of serialization (eg.
    /// raw bytes, DER or COSE keys), and because key need generation (and not "just" a fixed
    /// number of uniformly random bytes that is trivial to generate once and store as part of it).
    type VisibleSecretKey: Sized + Into<Self::SecretKey>;
    type SecretKey: Sized;
    type PublicKey: Sized;
    type SharedSecret: Sized;

    /// Generates a secret key that is intended to be exported / shared (e.g. to be persisted
    /// across program executions).
    fn generate_visible(&mut self, alg: Self::DhAlgorithm) -> Option<Self::VisibleSecretKey>
    where
        // FIXME: https://github.com/lake-rs/embedded-cal/issues/51
        Self: rand_core::TryRng;

    /// Generates a secret key.
    fn generate(&mut self, alg: Self::DhAlgorithm) -> Option<Self::SecretKey>
    where
        // FIXME: https://github.com/lake-rs/embedded-cal/issues/51
        Self: rand_core::TryRng,
    {
        Some(self.generate_visible(alg)?.into())
    }

    /// Derives a shared secret from a public and a private key.
    ///
    /// # Errors
    ///
    /// … are produced only if the private and the public key are for different algorithms.
    // FIXME: Is this really an error we should raise? People who don't check algorithms will also
    // reach into nonexistent offsets in output material, and that too is punishable by panics.
    fn shared_secret(
        &mut self,
        private: &Self::SecretKey,
        public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, IncompatibleKeys>;

    /// Produces the public key corresponding to a private key.
    fn public_key(&mut self, private: &Self::SecretKey) -> Self::PublicKey;

    /// Produces the bytes of the shared secret, in the algorithm's
    /// [`.output_length()`][DhAlgorithm::output_length()].
    ///
    /// The [`SharedSecret`][Self::SharedSecret] itself is *not* `AsRef` itself because the
    /// implementation may want to not pass out this secret by default (expecting it to be used as
    /// input to a KDF).
    // Should we name the return type? That'd enable users to store it -- but *should* it be stored
    // in the first place?
    fn raw_secret_bytes(&mut self, secret: &Self::SharedSecret) -> impl AsRef<[u8]>;
}

/// Error indicating that the public and the private key are incompatible.
#[derive(Debug)]
pub struct IncompatibleKeys;

impl core::fmt::Display for IncompatibleKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("keys are incompatible")
    }
}

impl core::error::Error for IncompatibleKeys {}

/// An algorithm for diffie-hellman style key establishment.
///
/// This not only encodes the cryptographic algorithm, but also the curve, but not post-processing
/// such as the KDF.
///
/// Note that while JOSE and COSE have [not switched their identifiers](https://datatracker.ietf.org/doc/html/rfc9864#name-ecdh-key-agreement-algorith)
/// to fully-specified for ECDH, it makes sense to group algorithm (practically always ECDH so far)
/// and curve, as it helps making illegal states unrepresentable.
///
/// The current constructors do not cover the breadth of what the interface can do, as COSE does
/// not have entries for non-EC DH (or ony other) key agreement.
// FIXME: We *could* encode the KDF and then make the shared secret only available through that
// KDF, but that'd make this overly COSE specific, and constraints like
// <https://github.com/lake-rs/embedded-cal/issues/60> could be added later.
pub trait DhAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Length of the shared secret produced by keys of this algorithm.
    fn output_length(&self) -> usize;

    /// Selects a DH algorithm from its COSE numbers.
    ///
    /// The curve number comes from the ["COSE Elliptic Curves"](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves)
    /// registry maintained by IANA.
    #[inline]
    #[allow(
        unused_variables,
        reason = "Argument names are part of the documentation"
    )]
    fn from_cose_ecdh(curve: impl Into<i128>) -> Option<Self> {
        None
    }
}

pub fn test_dh_algorithm_ecdh_p256<DP: DhProvider>() {
    let cose_ecdh_1 = DP::DhAlgorithm::from_cose_ecdh(1i8).expect(
        "test for type claiming ECDH on P-256 compatibility did not recognize COSE curve 1",
    );
    assert_eq!(cose_ecdh_1.output_length(), 32)
}
