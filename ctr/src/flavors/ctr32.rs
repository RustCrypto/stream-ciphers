//! 32-bit counter falvors.
use super::CtrFlavor;
use cipher::generic_array::{
    typenum::{U16, U4},
    GenericArray,
};
use core::convert::TryInto;

/// 32-bit big endian counter flavor.
#[derive(Default, Copy, Clone)]
#[repr(transparent)]
pub struct Ctr32BE(u32);

impl CtrFlavor for Ctr32BE {
    type Size = U4;
    type Backend = u32;

    #[inline]
    fn generate_block(&self, nonce: &GenericArray<Self, Self::Size>) -> GenericArray<u8, U16> {
        let mut res = GenericArray::<u8, U16>::default();
        let ctr = self.0.wrapping_add(nonce[3].0);
        res[0..4].copy_from_slice(&nonce[0].0.to_ne_bytes());
        res[4..8].copy_from_slice(&nonce[1].0.to_ne_bytes());
        res[8..12].copy_from_slice(&nonce[2].0.to_ne_bytes());
        res[12..16].copy_from_slice(&ctr.to_be_bytes());
        res
    }

    #[inline]
    fn load(block: &GenericArray<u8, U16>) -> GenericArray<Self, Self::Size> {
        [
            Self(u32::from_ne_bytes(block[0..4].try_into().unwrap())),
            Self(u32::from_ne_bytes(block[4..8].try_into().unwrap())),
            Self(u32::from_ne_bytes(block[8..12].try_into().unwrap())),
            Self(u32::from_be_bytes(block[12..16].try_into().unwrap())),
        ]
        .into()
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

/// 32-bit little endian counter flavor.
#[derive(Default, Clone)]
#[repr(transparent)]
pub struct Ctr32LE(u32);

impl CtrFlavor for Ctr32LE {
    type Size = U4;
    type Backend = u32;

    #[inline]
    fn generate_block(&self, nonce: &GenericArray<Self, Self::Size>) -> GenericArray<u8, U16> {
        let mut res = GenericArray::<u8, U16>::default();
        let ctr = self.0.wrapping_add(nonce[0].0);
        res[0..4].copy_from_slice(&ctr.to_le_bytes());
        res[4..8].copy_from_slice(&nonce[1].0.to_ne_bytes());
        res[8..12].copy_from_slice(&nonce[2].0.to_ne_bytes());
        res[12..16].copy_from_slice(&nonce[3].0.to_ne_bytes());
        res
    }

    #[inline]
    fn load(block: &GenericArray<u8, U16>) -> GenericArray<Self, Self::Size> {
        [
            Self(u32::from_le_bytes(block[0..4].try_into().unwrap())),
            Self(u32::from_ne_bytes(block[4..8].try_into().unwrap())),
            Self(u32::from_ne_bytes(block[8..12].try_into().unwrap())),
            Self(u32::from_ne_bytes(block[12..16].try_into().unwrap())),
        ]
        .into()
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
