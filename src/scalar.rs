//! Debugging utilities for [curve25519_dalek::scalar]

use std::{
    borrow::Borrow,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
};

use curve25519_dalek::scalar::Scalar as DalekScalar;
use subtle::{Choice, ConstantTimeEq, CtOption};

#[cfg(feature = "digest")]
use digest::{typenum::U64, Digest};
#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;

use crate::{expr::Tree, Named};

pub trait Scalar: Sized + Named {
    fn from_bytes_mod_order(bytes: [u8; 32]) -> Self;
    fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Self;
    fn from_canonical_bytes(bytes: [u8; 32]) -> CtOption<Self>;

    const ZERO: Self;
    const ONE: Self;

    #[cfg(feature = "rand_core")]
    fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self;

    #[cfg(feature = "digest")]
    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default;
    #[cfg(feature = "digest")]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64>;

    fn to_bytes(&self) -> [u8; 32];
    fn as_bytes(&self) -> &[u8; 32];
    fn invert(&self) -> Self;
    fn batch_invert(inputs: &mut [Self]) -> Self;
}

impl Named for DalekScalar {
    fn named<S>(self, _name: S) -> Self
    where
        String: From<S>,
    {
        self
    }
}

impl Scalar for DalekScalar {
    fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self::from_bytes_mod_order(bytes)
    }

    fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Self {
        Self::from_bytes_mod_order_wide(input)
    }

    fn from_canonical_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        Self::from_canonical_bytes(bytes)
    }

    const ZERO: Self = Self::ZERO;

    const ONE: Self = Self::ONE;

    #[cfg(feature = "rand_core")]
    fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self::random(rng)
    }

    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        Self::hash_from_bytes::<D>(input)
    }

    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64>,
    {
        Self::from_hash(hash)
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }

    fn as_bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }

    fn invert(&self) -> Self {
        self.invert()
    }

    fn batch_invert(inputs: &mut [Self]) -> Self {
        Self::batch_invert(inputs)
    }
}

#[derive(Clone)]
pub struct TestScalar {
    pub(crate) value: DalekScalar,
    pub(crate) tree: Tree,
}

impl PartialEq for TestScalar {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for TestScalar {}

impl Debug for TestScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Scalar").field(&self.tree).finish()
    }
}

impl Named for TestScalar {
    fn named<S>(self, name: S) -> Self
    where
        String: From<S>,
    {
        TestScalar {
            tree: Tree::Name(name.into()),
            ..self
        }
    }
}
impl Scalar for TestScalar {
    fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        DalekScalar::from_bytes_mod_order(bytes).into()
    }

    fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Self {
        DalekScalar::from_bytes_mod_order_wide(input).into()
    }

    fn from_canonical_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        DalekScalar::from_canonical_bytes(bytes).map(Into::into)
    }

    const ZERO: Self = Self {
        value: DalekScalar::ZERO,
        tree: Tree::Zero,
    };

    const ONE: Self = Self {
        value: DalekScalar::ONE,
        tree: Tree::One,
    };

    fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        DalekScalar::random(rng).into()
    }

    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        DalekScalar::hash_from_bytes::<D>(input).into()
    }

    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64>,
    {
        DalekScalar::from_hash(hash).into()
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.value.to_bytes()
    }

    fn as_bytes(&self) -> &[u8; 32] {
        self.value.as_bytes()
    }

    fn invert(&self) -> Self {
        Self {
            value: self.value.invert(),
            tree: Tree::Inv(Box::new(self.tree.clone())),
        }
    }

    fn batch_invert(inputs: &mut [Self]) -> Self {
        let mut values: Vec<_> = inputs.iter().map(|s| s.value).collect();
        let value = DalekScalar::batch_invert(values.as_mut());
        Iterator::zip(inputs.iter_mut(), values.iter()).for_each(|(a, b)| a.value = *b);
        value.into()
    }
}

impl From<DalekScalar> for TestScalar {
    fn from(value: DalekScalar) -> Self {
        Self {
            value,
            tree: Tree::Unnamed,
        }
    }
}

impl<'b> MulAssign<&'b TestScalar> for TestScalar {
    fn mul_assign(&mut self, rhs: &'b TestScalar) {
        self.value *= rhs.value;
        self.tree = Tree::Mul(Box::new(self.tree.clone()), Box::new(rhs.tree.clone()))
    }
}
define_mul_assign_variants!(LHS = TestScalar, RHS = TestScalar);

impl<'a, 'b> Mul<&'b TestScalar> for &'a TestScalar {
    type Output = TestScalar;
    fn mul(self, rhs: &'b TestScalar) -> TestScalar {
        Self::Output {
            value: self.value * rhs.value,
            tree: Tree::Mul(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_mul_variants!(LHS = TestScalar, RHS = TestScalar, Output = TestScalar);

impl<'b> AddAssign<&'b TestScalar> for TestScalar {
    fn add_assign(&mut self, rhs: &'b TestScalar) {
        self.value += rhs.value;
        self.tree = Tree::Add(Box::new(self.tree.clone()), Box::new(rhs.tree.clone()))
    }
}
define_add_assign_variants!(LHS = TestScalar, RHS = TestScalar);

impl<'a, 'b> Add<&'b TestScalar> for &'a TestScalar {
    type Output = TestScalar;

    fn add(self, rhs: &'b TestScalar) -> Self::Output {
        Self::Output {
            value: self.value + rhs.value,
            tree: Tree::Add(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_add_variants!(LHS = TestScalar, RHS = TestScalar, Output = TestScalar);

impl<'b> SubAssign<&'b TestScalar> for TestScalar {
    fn sub_assign(&mut self, rhs: &'b TestScalar) {
        self.value -= rhs.value;
        self.tree = Tree::Sub(Box::new(self.tree.clone()), Box::new(rhs.tree.clone()))
    }
}
define_sub_assign_variants!(LHS = TestScalar, RHS = TestScalar);

impl<'a, 'b> Sub<&'b TestScalar> for &'a TestScalar {
    type Output = TestScalar;

    fn sub(self, rhs: &'b TestScalar) -> Self::Output {
        Self::Output {
            value: self.value - rhs.value,
            tree: Tree::Sub(Box::new(self.tree.clone()), Box::new(rhs.tree.clone())),
        }
    }
}
define_sub_variants!(LHS = TestScalar, RHS = TestScalar, Output = TestScalar);

// TODO: ConditionallySelectable

impl ConstantTimeEq for TestScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl Default for TestScalar {
    fn default() -> Self {
        Self::ZERO
    }
}

macro_rules! define_from {
    ($t:ident) => {
        impl From<$t> for TestScalar {
            fn from(value: $t) -> Self {
                DalekScalar::from(value).into()
            }
        }
    };
}
define_from!(u128);
define_from!(u16);
define_from!(u32);
define_from!(u64);
define_from!(u8);

impl Hash for TestScalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl Index<usize> for TestScalar {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}

impl<'a> Neg for &'a TestScalar {
    type Output = TestScalar;

    fn neg(self) -> Self::Output {
        Self::Output {
            value: self.value.neg(),
            tree: Tree::Neg(Box::new(self.tree.clone())),
        }
    }
}

impl Neg for TestScalar {
    type Output = TestScalar;

    fn neg(self) -> Self::Output {
        Self::Output {
            value: self.value.neg(),
            tree: Tree::Neg(Box::new(self.tree)),
        }
    }
}

impl<T> Product<T> for TestScalar
where
    T: Borrow<TestScalar>,
{
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        DalekScalar::product(iter.map(|x| x.borrow().value)).into()
    }
}

impl<T> Sum<T> for TestScalar
where
    T: Borrow<TestScalar>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        DalekScalar::sum(iter.map(|x| x.borrow().value)).into() // TODO trees are lost
    }
}

// impl Zeroize for TestScalar
// Available on
// crate feature zeroize
//  only.

// impl Copy for TestScalar
