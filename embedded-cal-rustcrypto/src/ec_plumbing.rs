// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

//! Software implementation of the [EC plumbing][embedded_cal::plumbing::ec].
//!
//! This exists so that the plumbing layer -- and the test vector runners built on it -- can be
//! exercised on the host, where no hardware accelerator is available. It is deliberately *not*
//! wired into [`RustcryptoCalExtender`][crate::RustcryptoCalExtender]: that type forwards `Ec` to
//! whatever it extends, and shadowing a hardware back-end's accelerated primitives with a software
//! implementation would defeat the purpose of the extender.

use embedded_cal::empty::EmptyCal;
use embedded_cal::plumbing::ec::{Ec, EcPrimitives, P256, X25519};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};

/// Software provider of [`EcPrimitives`] for P-256 and X25519.
pub struct RustcryptoEc {
    /// X448 is not implemented here; see [`Ec::x448()`].
    empty: EmptyCal,
}

impl RustcryptoEc {
    pub const fn new() -> Self {
        Self { empty: EmptyCal }
    }
}

impl Default for RustcryptoEc {
    fn default() -> Self {
        Self::new()
    }
}

impl Ec for RustcryptoEc {
    const MAX_SCALAR_LENGTH: usize = 32;

    type PrimitivesP256 = Self;
    type PrimitivesX25519 = Self;
    /// X448 is not provided: `x25519-dalek` has no counterpart for it.
    type PrimitivesX448 = EmptyCal;

    fn p256(&mut self) -> &mut Self::PrimitivesP256 {
        self
    }

    fn x25519(&mut self) -> &mut Self::PrimitivesX25519 {
        self
    }

    fn x448(&mut self) -> &mut Self::PrimitivesX448 {
        &mut self.empty
    }
}

/// A 32-byte value in the curve's native encoding.
///
/// This stands in both for scalars proper and for point coordinates, which is why it is stored
/// uninterpreted: a coordinate can exceed the group order, so it is only converted into a
/// `p256::Scalar` where one is actually needed.
#[derive(Clone)]
pub struct Scalar32([u8; 32]);

pub struct P256Point(p256::ProjectivePoint);

impl EcPrimitives<P256> for RustcryptoEc {
    const HAS_MULTIPLY_SCALAR_POINT: bool = true;

    type Scalar = Scalar32;
    type Point = P256Point;

    fn multiply_scalar_point(&mut self, a: &Self::Scalar, b: &Self::Point) -> Self::Point {
        let scalar = Option::<p256::Scalar>::from(p256::Scalar::from_repr(a.0.into()))
            .expect("scalar is not reduced modulo the group order");
        P256Point(b.0 * scalar)
    }

    fn import_scalar_bytes(
        &mut self,
        scalar: &[u8],
    ) -> Result<Self::Scalar, embedded_cal::ImportError> {
        Ok(Scalar32(
            scalar.try_into().map_err(|_| embedded_cal::ImportError)?,
        ))
    }

    fn point(&mut self, x: Self::Scalar, y: Self::Scalar) -> Self::Point {
        let encoded = p256::EncodedPoint::from_affine_coordinates(&x.0.into(), &y.0.into(), false);
        let affine =
            Option::<p256::AffinePoint>::from(p256::AffinePoint::from_encoded_point(&encoded))
                .expect("caller is required to pass coordinates that are on the curve");
        P256Point(affine.into())
    }

    fn export_scalar_bytes<'s>(&mut self, scalar: &'s Self::Scalar) -> impl AsRef<[u8]> + use<'s> {
        &scalar.0
    }

    fn x_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        Scalar32(coordinates(point).0)
    }

    fn y_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        Scalar32(coordinates(point).1)
    }
}

/// Splits a point into its affine coordinates.
fn coordinates(point: &P256Point) -> ([u8; 32], [u8; 32]) {
    let affine = point.0.to_affine();
    let encoded = affine.to_encoded_point(false);
    let x = encoded.x().expect("point is not the identity");
    let y = encoded.y().expect("point is not the identity");
    ((*x).into(), (*y).into())
}

/// A u coordinate on Curve25519.
///
/// RFC 7748 operations run on the u coordinate alone, so this doubles as the point type; the `y`
/// coordinate that [`EcPrimitives::point()`] demands is discarded.
pub struct X25519Point([u8; 32]);

impl EcPrimitives<X25519> for RustcryptoEc {
    const HAS_MULTIPLY_SCALAR_POINT: bool = true;

    type Scalar = Scalar32;
    type Point = X25519Point;

    fn multiply_scalar_point(&mut self, a: &Self::Scalar, b: &Self::Point) -> Self::Point {
        // `x25519_dalek::x25519` clamps the scalar itself. The plumbing layer does not promise to
        // clamp, but clamping is idempotent, so pre-clamped callers are unaffected.
        X25519Point(x25519_dalek::x25519(a.0, b.0))
    }

    fn import_scalar_bytes(
        &mut self,
        scalar: &[u8],
    ) -> Result<Self::Scalar, embedded_cal::ImportError> {
        Ok(Scalar32(
            scalar.try_into().map_err(|_| embedded_cal::ImportError)?,
        ))
    }

    fn point(&mut self, x: Self::Scalar, _y: Self::Scalar) -> Self::Point {
        X25519Point(x.0)
    }

    fn export_scalar_bytes<'s>(&mut self, scalar: &'s Self::Scalar) -> impl AsRef<[u8]> + use<'s> {
        &scalar.0
    }

    fn x_coord(&mut self, point: &Self::Point) -> Self::Scalar {
        Scalar32(point.0)
    }

    fn y_coord(&mut self, _point: &Self::Point) -> Self::Scalar {
        panic!("X25519 operates on u coordinates only")
    }
}
