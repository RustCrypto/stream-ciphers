//! 128-bit counter falvors.
use super::CtrFlavor;
use cipher::generic_array::{
    typenum::{U1, U16},
    GenericArray,
};
use core::convert::TryInto;

/// 128-bit big endian counter flavor.
#[derive(Default, Clone)]
#[repr(transparent)]
pub struct Ctr128BE(u128);

impl CtrFlavor for Ctr128BE {
    type Size = U1;
    type Backend = u128;

    #[inline]
    fn generate_block(&self, nonce: &GenericArray<Self, Self::Size>) -> GenericArray<u8, U16> {
        self.0.wrapping_add(nonce[0].0).to_be_bytes().into()
    }

    #[inline]
    fn load(block: &GenericArray<u8, U16>) -> GenericArray<Self, Self::Size> {
        [Self(u128::from_be_bytes(block[..].try_into().unwrap()))].into()
    }

    #[inline]
    fn checked_add(&self, rhs: usize) -> Option<Self> {
        rhs.try_into()
            .ok()
            .and_then(|rhs| self.0.checked_add(rhs))
            .map(Self)
    }

    #[inline]
    fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    #[inline]
    fn to_backend(&self) -> Self::Backend {
        self.0
    }

    #[inline]
    fn from_backend(v: Self::Backend) -> Self {
        Self(v)
    }
}

/// 128-bit little endian counter flavor.
#[derive(Default, Clone)]
#[repr(transparent)]
pub struct Ctr128LE(u128);

impl CtrFlavor for Ctr128LE {
    type Size = U1;
    type Backend = u128;

    #[inline]
    fn generate_block(&self, nonce: &GenericArray<Self, Self::Size>) -> GenericArray<u8, U16> {
        self.0.wrapping_add(nonce[0].0).to_be_bytes().into()
    }

    #[inline]
    fn load(block: &GenericArray<u8, U16>) -> GenericArray<Self, Self::Size> {
        [Self(u128::from_le_bytes(block[..].try_into().unwrap()))].into()
    }

    #[inline]
    fn checked_add(&self, rhs: usize) -> Option<Self> {
        rhs.try_into()
            .ok()
            .and_then(|rhs| self.0.checked_add(rhs))
            .map(Self)
    }

    #[inline]
    fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    #[inline]
    fn to_backend(&self) -> Self::Backend {
        self.0
    }

    #[inline]
    fn from_backend(v: Self::Backend) -> Self {
        Self(v)
    }
}
