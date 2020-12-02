//! CTR mode flavors

use cipher::{
    generic_array::{ArrayLength, GenericArray},
    generic_array::typenum::{Quot, U16},
    stream::{SeekNum},
};
use core::ops::Div;
use core::convert::TryInto;

/// Trait implemented by different counter types used in the CTR mode.
pub trait CtrFlavor: Default + Copy {
    /// Size of the counter type in bytes.
    type Size;

    type Backend: SeekNum + From<Self> + Into<Self>;

    /// Generate block for given `nonce` value.
    fn generate_block<N>(
        self,
        nonce: &GenericArray<Self, Quot<N, Self::Size>>,
    ) -> GenericArray<u8, N>
    where
        N: ArrayLength<u8> + Div<Self::Size>,
        Quot<N, Self::Size>: ArrayLength<Self>
    {
        // TODO: remove when impl bug is resolved
        let mut block = nonce.clone();
        block[nonce.len() - 1] = self;
        unsafe { core::ptr::read(&block as *const _ as *const _) }
    }

    /// Load nonce value from bytes.
    fn load<N>(block: &GenericArray<u8, N>) -> GenericArray<Self, Quot<N, Self::Size>>
    where
        N: ArrayLength<u8> + Div<Self::Size>,
        Quot<N, Self::Size>: ArrayLength<Self>
    {
        // TODO: remove when impl bug is resolved
        unsafe { core::mem::transmute_copy(block) }
    }

    /// Checked addition.
    fn checked_add(self, rhs: usize) -> Option<Self>;

    /// Wrapped increment.
    fn increment(&mut self);
}

/// 128-bit big endian counter.
#[derive(Default, Copy, Clone)]
#[repr(transparent)]
struct Ctr128BE(u128);

impl From<u128> for Ctr128BE {
    fn from(v: u128) -> Self {
        Self(v)
    }
}

impl From<Ctr128BE> for u128 {
    fn from(v: Ctr128BE) -> Self {
        v.0
    }
}

impl CtrFlavor for Ctr128BE {
    type Size = U16;
    type Backend = u128;

    fn checked_add(self, rhs: usize) -> Option<Self> {
        rhs
            .try_into()
            .ok()
            .and_then(|rhs| self.0.checked_add(rhs))
            .map(|v| Self(v))
    }

    fn increment(&mut self) {
        self.0 += 1;
    }
}
