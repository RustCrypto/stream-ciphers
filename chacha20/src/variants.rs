//! ChaCha variant-specific configurations.

mod sealed {
    pub trait Sealed {}
}

/// A trait that distinguishes some ChaCha variants. Contains configurations
/// for "Legacy" DJB variant and the IETF variant.
pub trait Variant: Clone + sealed::Sealed {
    /// Where the nonce starts in the state array.
    const NONCE_INDEX: usize;

    /// The counter's type.
    #[cfg(feature = "cipher")]
    type Counter: cipher::StreamCipherCounter;

    /// The counter's type.
    #[cfg(not(feature = "cipher"))]
    type Counter;

    /// An intermediate helper type for using generics. Should be either
    /// a `[u32; 1]` or a `[u32; 2]`.
    type CounterWords: AsRef<[u32]>;

    /// Takes a slice of `state[12..NONCE_INDEX]` to convert it into
    /// `Self::Counter`.
    fn get_block_pos(counter_row: &[u32]) -> Self::Counter;

    /// Breaks down the `Self::Counter` type into a u32 array for setting the
    /// block pos.
    fn set_block_pos_helper(value: Self::Counter) -> Self::CounterWords;

    /// A helper method for calculating the remaining blocks using these types
    fn remaining_blocks(block_pos: Self::Counter) -> Option<usize>;
}

#[derive(Clone)]
/// IETF ChaCha configuration to use a 32-bit counter and 96-bit nonce.
pub struct Ietf();

impl sealed::Sealed for Ietf {}

impl Variant for Ietf {
    const NONCE_INDEX: usize = 13;
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

/// DJB variant specific features: 64-bit counter and 64-bit nonce.
#[derive(Clone)]
#[cfg(feature = "legacy")]
pub struct Legacy();

impl sealed::Sealed for Legacy {}

#[cfg(feature = "legacy")]
impl Variant for Legacy {
    const NONCE_INDEX: usize = 14;
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
        let remaining = u64::MAX - block_pos;
        #[cfg(target_pointer_width = "32")]
        if remaining > usize::MAX as u64 {
            return None;
        }
        remaining.try_into().ok()
    }
}
