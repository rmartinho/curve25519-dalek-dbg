//#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! Debugging utilities for the curve25519-dalek crate

#[macro_use]
mod macros;

pub mod ristretto;
pub mod scalar;

mod expr;

pub trait Named {
    fn named<S>(self, name: S) -> Self
    where
        String: From<S>;
}
