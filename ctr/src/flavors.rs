//! CTR mode flavors

use cipher::{
    generic_array::{typenum::U16, ArrayLength, GenericArray},
    SeekNum,
};

mod ctr128;
mod ctr32;
mod ctr64;

pub use ctr128::*;
pub use ctr32::*;
pub use ctr64::*;

/// Trait implemented by different counter types used in the CTR mode.
pub trait CtrFlavor: Default + Clone {
    /// Size of the 128-bit block in counter types.
    type Size: ArrayLength<Self>;
    /// Backend numeric type
    type Backend: SeekNum;

    /// Generate block for given `nonce` value.
    fn generate_block(&self, nonce: &GenericArray<Self, Self::Size>) -> GenericArray<u8, U16>;

    /// Load nonce value from bytes.
    fn load(block: &GenericArray<u8, U16>) -> GenericArray<Self, Self::Size>;

    /// Checked addition.
    fn checked_add(&self, rhs: usize) -> Option<Self>;

    /// Wrapped increment.
    fn increment(&mut self);

    /// Convert from a backend value
    fn from_backend(v: Self::Backend) -> Self;

    /// Convert to a backend value
    fn to_backend(&self) -> Self::Backend;
}
