//! Block RNG based on rand_core::BlockRng
use cipher::{BlockSizeUser, StreamCipherCore, Unsigned};
use rand_core::{
    block::{BlockRng, BlockRngCore},
    CryptoRng, Error, RngCore, SeedableRng,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    cipher::{generic_array::GenericArray, ParBlocks, ParBlocksSizeUser}, //KEY_SIZE,
    ChaChaCore,
    KeyIvInit,
    U10,
    U32,
    U4,
    U6,
    U64,
};
use cipher::StreamCipherSeekCore;

// NB. this must remain consistent with some currently hard-coded numbers in this module
const BUF_BLOCKS: u8 = 4;
// number of 32-bit words per ChaCha block (fixed by algorithm definition)
const BLOCK_WORDS: u8 = 16;

/// Array wrapper used for `BlockRngCore::Results` associated types.
//pub type BlockRngResults = BlockX<u32, 32>;
#[derive(Clone)]
//pub struct BlockRngResults([u32; 64]);
pub struct BlockRngResults(ParBlocks<LesserBlock>);

impl Default for BlockRngResults {
    fn default() -> Self {
        Self(GenericArray::from([GenericArray::from([0u8; 64]); 4]))
    }
}
// These 2 impls allow the [[u8; 64]; 4] to be used as a [u32; 64].
// Alternatively, it might be able to be put in a `union`, but they 
// would both require some unsafe code
impl AsRef<[u32]> for BlockRngResults {
    fn as_ref(&self) -> &[u32] {
        // Unsafe conversion, assuming continuous memory layout
        unsafe {
            let (_prefix, result, _suffix) = core::slice::from_raw_parts(
                self.0.as_ptr() as *const u8,
                self.0.len() * U64::USIZE,
            )
            .align_to::<u32>();
            result
        }
    }
}

impl AsMut<[u32]> for BlockRngResults {
    fn as_mut(&mut self) -> &mut [u32] {
        // Unsafe conversion, assuming continuous memory layout
        unsafe {
            let (_prefix, result, _suffix) = core::slice::from_raw_parts_mut(
                self.0.as_mut_ptr() as *mut u8,
                self.0.len() * U64::USIZE,
            )
            .align_to_mut::<u32>();
            result
        }
    }
}

impl BlockSizeUser for BlockRngResults {
    type BlockSize = U32;
    fn block_size() -> usize {
        32
    }
}

#[cfg(feature = "zeroize")]
impl Drop for BlockRngResults {
    fn drop(&mut self) {
        self.as_mut().zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for BlockRngResults {}

/// This is the internal block of ChaChaCore
#[derive(Copy, Clone)]
struct LesserBlock(GenericArray<u8, U64>);
impl AsRef<[u8]> for LesserBlock {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BlockSizeUser for LesserBlock {
    type BlockSize = U64;
    fn block_size() -> usize {
        64
    }
}
impl ParBlocksSizeUser for LesserBlock {
    type ParBlocksSize = U4;
}

/// A trait for altering the state of ChaChaCore<R>
trait AlteredState {
    /// Set the stream identifier
    fn set_stream(&mut self, stream: [u8; 12]);
    /// Get the stream identifier
    fn get_stream(&self) -> [u8; 12];
}

impl<R: Unsigned> AlteredState for ChaChaCore<R> {
    fn set_stream(&mut self, stream: [u8; 12]) {
        let (_prefix, result, _suffix) = unsafe { stream.align_to::<u32>() };
        for (val, chunk) in self.state[13..16].iter_mut().zip(result) {
            *val = *chunk;
        }
    }
    fn get_stream(&self) -> [u8; 12] {
        let (_prefix, result_slice, _suffix) = unsafe { self.state[13..16].align_to::<u8>() };
        let mut result = [0u8; 12];
        result.copy_from_slice(result_slice);
        result
    }
}

macro_rules! impl_chacha_rng {
    ($name:ident, $core:ident, $rounds:ident, $doc:expr) => {
        #[doc = $doc]
        #[cfg_attr(docsrs, doc(cfg(feature = "rng")))]
        #[derive(Clone)]
        pub struct $name {
            rng: BlockRng<$core>,
        }

        impl SeedableRng for $name {
            type Seed = [u8; 32];

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                let core = $core::from_seed(seed);
                Self {
                    rng: BlockRng::new(core),
                }
            }
        }

        impl RngCore for $name {
            #[inline]
            fn next_u32(&mut self) -> u32 {
                self.rng.next_u32()
            }

            #[inline]
            fn next_u64(&mut self) -> u64 {
                self.rng.next_u64()
            }

            #[inline]
            fn fill_bytes(&mut self, bytes: &mut [u8]) {
                self.rng.fill_bytes(bytes)
            }

            #[inline]
            fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
                self.rng.try_fill_bytes(bytes)
            }
        }

        impl CryptoRng for $name {}

        // Custom Debug implementation that does not expose the internal state
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "ChaChaXCore {{}}")
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.rng.core.counter == other.rng.core.counter
                    && self.get_seed() == other.get_seed()
                    && self.get_stream_bytes() == other.get_stream_bytes()
                    && self.get_word_pos() == other.get_word_pos()
            }
        }
        impl Eq for $name {}

        #[doc = "Core random number generator, for use with [`rand_core::block::BlockRng`]"]
        #[cfg_attr(docsrs, doc(cfg(feature = "rng")))]
        #[derive(Clone)]
        pub struct $core {
            block: ChaChaCore<$rounds>,
            counter: u64,
        }

        impl SeedableRng for $core {
            type Seed = [u8; 32];

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                let block = ChaChaCore::<$rounds>::new(&seed.into(), &[0u8; 12].into());
                Self { block, counter: 0 }
            }
        }

        impl BlockRngCore for $core {
            type Item = u32;
            type Results = BlockRngResults;

            fn generate(&mut self, results: &mut Self::Results) {
                // builds a wide buffer to send into Backend .gen_par_ks_blocks()
                // through StreamBackend's .write_keystream_blocks()
                // Buffer is [[u8; 64]; 4] and will run .gen_ks_block() 4 times if
                // it uses soft.rs instead of SIMD

                self.block.write_keystream_blocks(&mut results.0);

                self.counter = self.counter.wrapping_add(1);
            }
        }

        impl $name {
            // The buffer is a 4-block window, i.e. it is always at a block-aligned position in the
            // stream but if the stream has been sought it may not be self-aligned.

            /// Get the offset from the start of the stream, in 32-bit words.
            ///
            /// Since the generated blocks are 16 words (2<sup>4</sup>) long and the
            /// counter is 32-bits, the offset is a 36-bit number. Sub-word offsets are
            /// not supported, hence the result can simply be multiplied by 4 to get a
            /// byte-offset.
            #[inline]
            pub fn get_word_pos(&self) -> u64 {
                let buf_start_block = {
                    let buf_end_block = self.rng.core.block.get_block_pos();
                    u32::wrapping_sub(buf_end_block, BUF_BLOCKS.into())
                };
                let (buf_offset_blocks, block_offset_words) = {
                    let buf_offset_words = self.rng.index() as u32;
                    let blocks_part = buf_offset_words / u32::from(BLOCK_WORDS);
                    let words_part = buf_offset_words % u32::from(BLOCK_WORDS);
                    (blocks_part, words_part)
                };
                let pos_block = u32::wrapping_add(buf_start_block, buf_offset_blocks);
                let pos_block_words = u64::from(pos_block) * u64::from(BLOCK_WORDS);
                pos_block_words + u64::from(block_offset_words)
            }

            /// Set the offset from the start of the stream, in 32-bit words.
            ///
            /// As with `get_word_pos`, we use a 36-bit number. Since the generator
            /// simply cycles at the end of its period (256 GiB), we ignore the upper
            /// 28 bits.
            #[inline]
            pub fn set_word_pos(&mut self, word_offset: u64) {
                let block = (word_offset / u64::from(BLOCK_WORDS)) as u32;
                self.rng.core.block.set_block_pos(block);
                self.rng
                    .generate_and_set((word_offset % u64::from(BLOCK_WORDS)) as usize);
            }

            /// Set the stream number.
            ///
            /// This is initialized to zero; 2<sup>96</sup> unique streams of output
            /// are available per seed/key.
            #[inline]
            pub fn set_stream_bytes(&mut self, stream: [u8; 12]) {
                self.rng.core.block.set_stream(stream);
                if self.rng.index() != 64 {
                    let wp = self.get_word_pos();
                    self.set_word_pos(wp);
                }
            }

            /// Set the stream number. The upper 96 bits are used and the rest are
            /// discarded.
            ///
            /// See also: `.set_stream_bytes()`
            ///
            /// This is initialized to zero; 2<sup>96</sup> unique streams of output
            /// are available per seed/key.
            #[inline]
            pub fn set_stream(&mut self, stream: u128) {
                let mut upper_12_bytes = [0u8; 12];
                upper_12_bytes.copy_from_slice(&stream.to_le_bytes()[0..12]);
                self.rng.core.block.set_stream(upper_12_bytes);
            }

            /// Get the stream number.
            #[inline]
            pub fn get_stream_bytes(&self) -> [u8; 12] {
                self.rng.core.block.get_stream()
            }

            /// Get the stream number.
            #[inline]
            pub fn get_stream(&self) -> u128 {
                let mut bytes = [0u8; 16];
                bytes[0..12].copy_from_slice(&self.get_stream_bytes());
                u128::from_le_bytes(bytes)
            }

            /// Get the seed.
            #[inline]
            pub fn get_seed(&self) -> [u8; 32] {
                let mut result = [0u8; 32];
                let seed = &self.rng.core.block.state[4..12];
                unsafe {
                    let (_p, b, _t) = seed.align_to::<u8>();
                    result.copy_from_slice(&b);
                }
                result
            }
        }

        #[cfg(feature = "zeroize")]
        impl Drop for $core {
            fn drop(&mut self) {
                self.counter.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $core {}
    };
}

impl_chacha_rng!(
    ChaCha8Rng,
    ChaCha8Core,
    U4,
    "Random number generator over the ChaCha8 stream cipher."
);

impl_chacha_rng!(
    ChaCha12Rng,
    ChaCha12Core,
    U6,
    "Random number generator over the ChaCha12 stream cipher."
);

impl_chacha_rng!(
    ChaCha20Rng,
    ChaCha20Core,
    U10,
    "Random number generator over the ChaCha20 stream cipher."
);

#[cfg(test)]
mod tests {

    use super::*;
    use rand_chacha::ChaCha20Rng as OGChacha;
    use rand_core::{RngCore, SeedableRng};

    const KEY: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_rng_output() {
        let mut rng = ChaCha20Rng::from_seed(KEY);
        let mut bytes = [0u8; 13];

        rng.fill_bytes(&mut bytes);
        assert_eq!(
            bytes,
            [177, 105, 126, 159, 198, 70, 30, 25, 131, 209, 49, 207, 105]
        );

        rng.fill_bytes(&mut bytes);
        assert_eq!(
            bytes,
            [167, 163, 252, 19, 79, 20, 152, 128, 232, 187, 43, 93, 35]
        );
    }
    #[test]
    fn test_wrapping_add() {
        let mut rng = ChaCha20Rng::from_entropy();
        rng.set_stream(1337 as u128);
        // test counter wrapping-add
        rng.set_word_pos((2 as u64).pow(36) - 1);
        let mut output = [3u8; 128];
        rng.fill_bytes(&mut output);

        assert_ne!(output, [0u8; 128]);

        assert!(rng.get_word_pos() < 2000 && rng.get_word_pos() != 0);
    }

    #[test]
    fn test_set_and_get_equivalence() {
        let seed = [44u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut original_rng = OGChacha::from_seed(seed);
        let stream = 1337 as u128;
        rng.set_stream(stream);
        original_rng.set_stream(stream as u64);
        let word_pos = 3553439 as u64;
        rng.set_word_pos(word_pos);
        original_rng.set_word_pos(word_pos as u128);

        assert_eq!(rng.get_seed(), seed);
        assert_eq!(rng.get_stream(), stream);
        // set_word_pos() rounds it down to the nearest multiple of 16
        // which would fail this:
        // assert_eq!(rng.get_word_pos(), word_pos);
        assert_eq!(rng.get_word_pos(), original_rng.get_word_pos() as u64);
        assert_eq!(rng.get_word_pos(), word_pos);
    }
}
