//! Distinguishing features of ChaCha variants.
//!
//! To be revisited for the 64-bit counter.

#[cfg(feature = "cipher")]
/// A trait to restrict the counter for the cipher crate
pub trait VariantCounter: cipher::Counter {}
#[cfg(not(feature = "cipher"))]
pub trait VariantCounter {}

impl VariantCounter for u32 {}

#[cfg(feature = "legacy")]
impl VariantCounter for u64 {}

/// A trait that distinguishes some ChaCha variants
pub trait Variant: Clone {
    /// the size of the Nonce in u32s
    const NONCE_INDEX: usize;
    /// This const should be evaluated at compile time
    const USES_U32_COUNTER: bool;
    type Counter: VariantCounter;
    type CounterWords: AsRef<[u32]>;

    /// Takes a slice of state[12..NONCE_INDEX] to convert it into
    /// Self::Counter.
    fn get_block_pos(counter_row: &[u32]) -> Self::Counter;

    /// Breaks down the Self::Counter type into a u32 array for setting the
    /// block pos.
    fn set_block_pos_helper(value: Self::Counter) -> Self::CounterWords;

    /// A helper method for calculating the remaining blocks using these types
    fn remaining_blocks(block_pos: Self::Counter) -> Option<usize>;
}

#[derive(Clone)]
/// The details pertaining to the IETF variant
pub struct Ietf();
impl Variant for Ietf {
    const NONCE_INDEX: usize = 13;
    const USES_U32_COUNTER: bool = true;
    type Counter = u32;
    type CounterWords = [u32; 1];
    #[inline(always)]
    fn get_block_pos(counter_row: &[u32]) -> Self::Counter {
        counter_row[0]
    }
    #[inline(always)]
    fn set_block_pos_helper(value: Self::Counter) -> Self::CounterWords {
        [value]
    }
    #[inline(always)]
    fn remaining_blocks(block_pos: Self::Counter) -> Option<usize> {
        (u32::MAX - block_pos).try_into().ok()
    }
}

#[derive(Clone)]
#[cfg(feature = "legacy")]
pub struct Legacy();

#[cfg(feature = "legacy")]
impl Variant for Legacy {
    const NONCE_INDEX: usize = 14;
    const USES_U32_COUNTER: bool = false;
    type Counter = u64;
    type CounterWords = [u32; 2];
    #[inline(always)]
    fn get_block_pos(counter_row: &[u32]) -> Self::Counter {
        counter_row[0] as u64 | (u64::from(counter_row[1]) << 32)
    }
    #[inline(always)]
    fn set_block_pos_helper(value: Self::Counter) -> Self::CounterWords {
        [value as u32, (value >> 32) as u32]
    }
    #[inline(always)]
    fn remaining_blocks(block_pos: Self::Counter) -> Option<usize> {
        let remaining = u64::MAX - block_pos;
        #[cfg(target_pointer_width = "32")]
        if remaining > usize::MAX as u64 {
            return None;
        }
        remaining.try_into().ok()
    }
}
