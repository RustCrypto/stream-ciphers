//! Distinguishing features of ChaCha variants.
//!
//! To be revisited for the 64-bit counter.

/// A trait that distinguishes some ChaCha variants
pub trait Variant: Clone {
    /// the size of the Nonce in u32s
    const NONCE_INDEX: usize;
    const COUNTER_MAX: u64;
    #[cfg(feature = "cipher")]
    type Counter: cipher::StreamCipherCounter;
    #[cfg(not(feature = "cipher"))]
    type Counter;

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
    const COUNTER_MAX: u64 = u32::MAX as u64;
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
        let total_blocks = 1u64 << 32;
        let rem = total_blocks - block_pos as u64;
        #[cfg(target_pointer_width = "32")]
        if rem > usize::MAX as u64 {
            return None;
        } else {
            return Some(rem as usize);
        }
        rem.try_into().ok()
    }
}

#[derive(Clone)]
#[cfg(feature = "legacy")]
pub struct Legacy();

#[cfg(feature = "legacy")]
impl Variant for Legacy {
    const NONCE_INDEX: usize = 14;
    const COUNTER_MAX: u64 = u64::MAX;
    type Counter = u64;

    type CounterWords = [u32; 2];
    #[inline(always)]
    fn get_block_pos(counter_row: &[u32]) -> Self::Counter {
        counter_row[0] as u64 | ((counter_row[1] as u64) << 32)
    }
    #[inline(always)]
    fn set_block_pos_helper(value: Self::Counter) -> Self::CounterWords {
        [value as u32, (value >> 32) as u32]
    }
    #[inline(always)]
    fn remaining_blocks(block_pos: Self::Counter) -> Option<usize> {
        let remaining = (1u128 << 64) - block_pos as u128;
        if remaining > usize::MAX as u128 {
            return None;
        }
        remaining.try_into().ok()
    }
}
