//! Debugging utilities for [curve25519_dalek::ristretto]

use std::{
    borrow::Borrow,
    fmt::{self, Debug},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint as DalekRistrettoPoint},
    scalar::Scalar as DalekScalar,
    traits::Identity,
};

#[cfg(feature = "digest")]
use digest::{typenum::U64, Digest};
#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;
use subtle::{Choice, ConstantTimeEq};

use crate::{
    expr::Tree,
    scalar::{Scalar, TestScalar},
    Named,
};

pub trait RistrettoPoint: Sized + Named {
    type Scalar: Scalar;

    fn compress(&self) -> CompressedRistretto;
    fn double_and_compress_batch<'a, I>(points: I) -> Vec<CompressedRistretto>
    where
        Self: 'a,
        I: IntoIterator<Item = &'a Self>;

    #[cfg(feature = "rand_core")]
    fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self;

    #[cfg(feature = "digest")]
    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default;
    #[cfg(feature = "digest")]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default;
    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self;

    fn mul_base(scalar: &Self::Scalar) -> Self;

    #[allow(non_snake_case)]
    fn vartime_double_scalar_mul_basepoint(a: &Self::Scalar, A: &Self, b: &Self::Scalar) -> Self;
}

impl Named for DalekRistrettoPoint {
    fn named<S>(self, _name: S) -> Self
    where
        String: From<S>,
    {
        self
    }
}

impl RistrettoPoint for DalekRistrettoPoint {
    type Scalar = DalekScalar;

    fn compress(&self) -> CompressedRistretto {
        self.compress()
    }

    fn double_and_compress_batch<'a, I>(points: I) -> Vec<CompressedRistretto>
    where
        Self: 'a,
        I: IntoIterator<Item = &'a Self>,
    {
        Self::double_and_compress_batch(points)
    }

    #[cfg(feature = "rand_core")]
    fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self::random(rng)
    }

    #[cfg(feature = "digest")]
    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self::hash_from_bytes::<D>(input)
    }

    #[cfg(feature = "digest")]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self::from_hash(hash)
    }

    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self::from_uniform_bytes(bytes)
    }

    fn mul_base(scalar: &Self::Scalar) -> Self {
        Self::mul_base(scalar)
    }

    #[allow(non_snake_case)]
    fn vartime_double_scalar_mul_basepoint(a: &Self::Scalar, A: &Self, b: &Self::Scalar) -> Self {
        Self::vartime_double_scalar_mul_basepoint(a, A, b)
    }
}

#[derive(Clone)]
pub struct TestRistrettoPoint {
    value: DalekRistrettoPoint,
    tree: Tree,
}

impl PartialEq for TestRistrettoPoint {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for TestRistrettoPoint {}

impl Debug for TestRistrettoPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Scalar").field(&self.tree).finish()
    }
}

impl Named for TestRistrettoPoint {
    fn named<S>(self, name: S) -> Self
    where
        String: From<S>,
    {
        TestRistrettoPoint {
            tree: Tree::Name(name.into()),
            ..self
        }
    }
}
impl RistrettoPoint for TestRistrettoPoint {
    type Scalar = TestScalar;

    fn compress(&self) -> CompressedRistretto {
        self.value.compress()
    }

    fn double_and_compress_batch<'a, I>(points: I) -> Vec<CompressedRistretto>
    where
        Self: 'a,
        I: IntoIterator<Item = &'a Self>,
    {
        DalekRistrettoPoint::double_and_compress_batch(points.into_iter().map(|p| &p.value))
    }

    #[cfg(feature = "rand_core")]
    fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        DalekRistrettoPoint::random(rng).into()
    }

    #[cfg(feature = "digest")]
    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        DalekRistrettoPoint::hash_from_bytes::<D>(input).into()
    }

    #[cfg(feature = "digest")]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        DalekRistrettoPoint::from_hash(hash).into()
    }

    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        DalekRistrettoPoint::from_uniform_bytes(bytes).into()
    }

    fn mul_base(scalar: &Self::Scalar) -> Self {
        DalekRistrettoPoint::mul_base(&scalar.value).into()
    }

    #[allow(non_snake_case)]
    fn vartime_double_scalar_mul_basepoint(a: &Self::Scalar, A: &Self, b: &Self::Scalar) -> Self {
        DalekRistrettoPoint::vartime_double_scalar_mul_basepoint(&a.value, &A.value, &b.value)
            .into()
    }
}

impl From<DalekRistrettoPoint> for TestRistrettoPoint {
    fn from(value: DalekRistrettoPoint) -> Self {
        Self {
            value,
            tree: Tree::Unnamed,
        }
    }
}

impl<'a, 'b> Add<&'b TestRistrettoPoint> for &'a TestRistrettoPoint {
    type Output = TestRistrettoPoint;

    fn add(self, rhs: &'b TestRistrettoPoint) -> Self::Output {
        Self::Output {
            value: self.value + rhs.value,
            tree: Tree::Add(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_add_variants!(
    LHS = TestRistrettoPoint,
    RHS = TestRistrettoPoint,
    Output = TestRistrettoPoint
);

impl<'b> AddAssign<&'b TestRistrettoPoint> for TestRistrettoPoint {
    fn add_assign(&mut self, rhs: &'b TestRistrettoPoint) {
        self.value += rhs.value;
        self.tree = Tree::Add(Box::new(self.tree.clone()), Box::new(rhs.tree.clone()))
    }
}
define_add_assign_variants!(LHS = TestRistrettoPoint, RHS = TestRistrettoPoint);

impl<'a, 'b> Sub<&'b TestRistrettoPoint> for &'a TestRistrettoPoint {
    type Output = TestRistrettoPoint;

    fn sub(self, rhs: &'b TestRistrettoPoint) -> Self::Output {
        Self::Output {
            value: self.value - rhs.value,
            tree: Tree::Sub(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_sub_variants!(
    LHS = TestRistrettoPoint,
    RHS = TestRistrettoPoint,
    Output = TestRistrettoPoint
);

impl<'b> SubAssign<&'b TestRistrettoPoint> for TestRistrettoPoint {
    fn sub_assign(&mut self, rhs: &'b TestRistrettoPoint) {
        self.value += rhs.value;
        self.tree = Tree::Add(Box::new(self.tree.clone()), Box::new(rhs.tree.clone()))
    }
}
define_sub_assign_variants!(LHS = TestRistrettoPoint, RHS = TestRistrettoPoint);

// TODO: ConditionallySelectable

impl ConstantTimeEq for TestRistrettoPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl Default for TestRistrettoPoint {
    fn default() -> Self {
        Self {
            value: DalekRistrettoPoint::default(),
            tree: Tree::One,
        }
    }
}

impl Identity for TestRistrettoPoint {
    fn identity() -> Self {
        Self {
            value: DalekRistrettoPoint::identity(),
            tree: Tree::One,
        }
    }
}

impl<'b> MulAssign<&'b TestScalar> for TestRistrettoPoint {
    fn mul_assign(&mut self, rhs: &'b TestScalar) {
        self.value *= rhs.value;
        self.tree = Tree::Mul(Box::new(self.tree.clone()), Box::new(rhs.tree.clone()))
    }
}
define_mul_assign_variants!(LHS = TestRistrettoPoint, RHS = TestScalar);

impl<'a, 'b> Mul<&'b TestScalar> for &'a TestRistrettoPoint {
    type Output = TestRistrettoPoint;

    fn mul(self, rhs: &'b TestScalar) -> Self::Output {
        Self::Output {
            value: self.value * rhs.value,
            tree: Tree::Mul(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_mul_variants!(
    LHS = TestRistrettoPoint,
    RHS = TestScalar,
    Output = TestRistrettoPoint
);

impl<'a, 'b> Mul<&'b TestRistrettoPoint> for &'a TestScalar {
    type Output = TestRistrettoPoint;

    fn mul(self, rhs: &'b TestRistrettoPoint) -> Self::Output {
        Self::Output {
            value: self.value * rhs.value,
            tree: Tree::Mul(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_mul_variants!(
    LHS = TestScalar,
    RHS = TestRistrettoPoint,
    Output = TestRistrettoPoint
);

impl<'a> Neg for &'a TestRistrettoPoint {
    type Output = TestRistrettoPoint;

    fn neg(self) -> Self::Output {
        Self::Output {
            value: self.value.neg(),
            tree: Tree::Neg(Box::new(self.tree.clone())),
        }
    }
}
impl Neg for TestRistrettoPoint {
    type Output = TestRistrettoPoint;

    fn neg(self) -> Self::Output {
        Self::Output {
            value: self.value.neg(),
            tree: Tree::Neg(Box::new(self.tree)),
        }
    }
}

impl<T> Sum<T> for TestRistrettoPoint
where
    T: Borrow<TestRistrettoPoint>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        DalekRistrettoPoint::sum(iter.map(|x| x.borrow().value)).into() // TODO trees are lost
    }
}

// impl VartimeMultiscalarMul for RistrettoPoint
// impl Zeroize for RistrettoPoint
// Available on
// crate feature zeroize
//  only.
// impl Copy for RistrettoPoint

#[test]
fn test() {
    let rng = &mut rand::thread_rng();
    let x = TestRistrettoPoint::random(rng).named("x");
    let y = TestRistrettoPoint::random(rng).named("y");
    let z = TestScalar::random(rng).named("z");

    assert_eq!(&x * &z, x + y * z);
}
