// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::{convert::Infallible, fmt::Debug};

use rand_core::{
    SeedableRng, TryCryptoRng, TryRngCore,
    block::{BlockRng, CryptoGenerator, Generator},
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ChaChaCore, R8, R12, R20, Rounds, backends,
    variants::{Legacy, Variant},
};

use cfg_if::cfg_if;

/// Number of 32-bit words per ChaCha block (fixed by algorithm definition).
pub(crate) const BLOCK_WORDS: u8 = 16;

/// The seed for ChaCha20. Implements ZeroizeOnDrop when the
/// zeroize feature is enabled.
#[derive(PartialEq, Eq, Default, Clone)]
pub struct Seed([u8; 32]);

impl AsRef<[u8; 32]> for Seed {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<[u8; 32]> for Seed {
    #[cfg(feature = "zeroize")]
    fn from(mut value: [u8; 32]) -> Self {
        let input = Self(value);
        value.zeroize();
        input
    }
    #[cfg(not(feature = "zeroize"))]
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Seed {}

impl Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// A wrapper around 64 bits of data that can be constructed from any of the
/// following:
/// * `u64`
/// * `[u32; 2]`
/// * `[u8; 8]`
///
/// The arrays should be in little endian order. You should not need to use
/// this directly, as the methods in this crate that use this type call
/// `.into()` for you, so you only need to supply any of the above types.
pub struct U32x2([u32; Self::LEN]);

impl U32x2 {
    /// Amount of raw bytes backing a `U32x2` instance.
    const BYTES: usize = size_of::<Self>();

    /// The length of the array contained within `U32x2`.
    const LEN: usize = 2;
}

impl From<[u32; Self::LEN]> for U32x2 {
    #[inline]
    fn from(value: [u32; Self::LEN]) -> Self {
        Self(value)
    }
}

impl From<[u8; Self::BYTES]> for U32x2 {
    #[inline]
    fn from(value: [u8; Self::BYTES]) -> Self {
        let mut result = Self(Default::default());
        for (cur, chunk) in result
            .0
            .iter_mut()
            .zip(value.chunks_exact(size_of::<u32>()))
        {
            *cur = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        result
    }
}

impl From<u64> for U32x2 {
    #[inline]
    fn from(value: u64) -> Self {
        let result: [u8; Self::BYTES] = value.to_le_bytes()[..Self::BYTES].try_into().unwrap();
        result.into()
    }
}

/// A wrapper for `stream_id`.
///
/// Can be constructed from any of the following:
/// * `u64`
/// * `[u32; 2]`
/// * `[u8; 8]`
///
/// The arrays should be in little endian order.
pub type StreamId = U32x2;

/// A wrapper for `block_pos`.
///
/// Can be constructed from any of the following:
/// * `u64`
/// * `[u32; 2]`
/// * `[u8; 8]`
///
/// The arrays should be in little endian order.
pub type BlockPos = U32x2;

const BUFFER_SIZE: usize = 64;

// NB. this must remain consistent with some currently hard-coded numbers in this module
const BUF_BLOCKS: u8 = BUFFER_SIZE as u8 / BLOCK_WORDS;

impl<R: Rounds, V: Variant> ChaChaCore<R, V> {
    /// Generates 4 blocks in parallel with avx2 & neon, but merely fills
    /// 4 blocks with sse2 & soft
    fn generate(&mut self, buffer: &mut [u32; 64]) {
        cfg_if! {
            if #[cfg(chacha20_force_soft)] {
                backends::soft::Backend(self).gen_ks_blocks(buffer);
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                cfg_if! {
                    if #[cfg(chacha20_force_avx2)] {
                        unsafe {
                            backends::avx2::rng_inner::<R, V>(self, buffer);
                        }
                    } else if #[cfg(chacha20_force_sse2)] {
                        unsafe {
                            backends::sse2::rng_inner::<R, V>(self, buffer);
                        }
                    } else {
                        let (avx2_token, sse2_token) = self.tokens;
                        if avx2_token.get() {
                            unsafe {
                                backends::avx2::rng_inner::<R, V>(self, buffer);
                            }
                        } else if sse2_token.get() {
                            unsafe {
                                backends::sse2::rng_inner::<R, V>(self, buffer);
                            }
                        } else {
                            backends::soft::Backend(self).gen_ks_blocks(buffer);
                        }
                    }
                }
            } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))] {
                unsafe {
                    backends::neon::rng_inner::<R, V>(self, buffer);
                }
            } else {
                backends::soft::Backend(self).gen_ks_blocks(buffer);
            }
        }
    }
}

macro_rules! impl_chacha_rng {
    ($ChaChaXRng:ident, $ChaChaXCore:ident, $rounds:ident, $abst:ident) => {
        /// A cryptographically secure random number generator that uses the ChaCha algorithm.
        ///
        /// ChaCha is a stream cipher designed by Daniel J. Bernstein[^1], that we use as an RNG. It is
        /// an improved variant of the Salsa20 cipher family, which was selected as one of the "stream
        /// ciphers suitable for widespread adoption" by eSTREAM[^2].
        ///
        /// ChaCha uses add-rotate-xor (ARX) operations as its basis. These are safe against timing
        /// attacks, although that is mostly a concern for ciphers and not for RNGs. We provide a SIMD
        /// implementation to support high throughput on a variety of common hardware platforms.
        ///
        /// With the ChaCha algorithm it is possible to choose the number of rounds the core algorithm
        /// should run. The number of rounds is a tradeoff between performance and security, where 8
        /// rounds is the minimum potentially secure configuration, and 20 rounds is widely used as a
        /// conservative choice.
        ///
        /// We use a 64-bit counter and 64-bit stream identifier as in Bernstein's implementation
        /// except that we use a stream identifier in place of a nonce. A 64-bit counter over 64-byte
        /// (16 word) blocks allows 1 ZiB of output before cycling, and the stream identifier allows
        /// 2<sup>64</sup> unique streams of output per seed. Both counter and stream are initialized
        /// to zero but may be set via the `set_word_pos` and `set_stream` methods.
        ///
        /// The word layout is:
        ///
        /// ```text
        /// constant  constant  constant  constant
        /// seed      seed      seed      seed
        /// seed      seed      seed      seed
        /// counter   counter   stream_id stream_id
        /// ```
        /// This implementation uses an output buffer of sixteen `u32` words, and uses
        /// [`BlockRng`] to implement the [`RngCore`] methods.
        ///
        /// # Example for `ChaCha20Rng`
        ///
        /// ```rust
        /// use chacha20::ChaCha20Rng;
        /// // use rand_core traits
        /// use rand_core::{SeedableRng, RngCore};
        ///
        /// // the following inputs are examples and are neither
        /// // recommended nor suggested values
        ///
        /// let seed = [42u8; 32];
        /// let mut rng = ChaCha20Rng::from_seed(seed);
        /// rng.set_stream(100);
        ///
        /// // you can also use a [u8; 8] in `.set_stream()`
        /// rng.set_stream([3u8; 8]);
        /// // or a [u32; 2]
        /// rng.set_stream([4u32; 2]);
        ///
        /// rng.set_word_pos(5);
        ///
        /// let x = rng.next_u32();
        /// let mut array = [0u8; 32];
        /// rng.fill_bytes(&mut array);
        ///
        /// // If you need to zeroize the RNG's buffer, ensure that "zeroize"
        /// // feature is enabled in Cargo.toml, and then it will zeroize on
        /// // drop automatically
        /// # #[cfg(feature = "zeroize")]
        /// use zeroize::Zeroize;
        /// ```
        ///
        /// The other Rngs from this crate are initialized similarly.
        ///
        /// [^1]: D. J. Bernstein, [*ChaCha, a variant of Salsa20*](https://cr.yp.to/chacha.html)
        ///
        /// [^2]: [eSTREAM: the ECRYPT Stream Cipher Project](http://www.ecrypt.eu.org/stream/)
        pub struct $ChaChaXRng {
            /// The ChaChaCore struct
            pub core: BlockRng<$ChaChaXCore>,
        }

        /// The ChaCha core random number generator
        pub struct $ChaChaXCore(ChaChaCore<$rounds, Legacy>);

        impl SeedableRng for $ChaChaXCore {
            type Seed = Seed;

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                Self(ChaChaCore::<$rounds, Legacy>::new(seed.as_ref(), &[0u8; 8]))
            }
        }
        impl SeedableRng for $ChaChaXRng {
            type Seed = [u8; 32];

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                Self {
                    core: BlockRng::new($ChaChaXCore::from_seed(seed.into())),
                }
            }
        }
        impl TryRngCore for $ChaChaXRng {
            type Error = Infallible;

            #[inline]
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(self.core.next_word())
            }
            #[inline]
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(self.core.next_u64_from_u32())
            }
            #[inline]
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                self.core.fill_bytes(dest);
                Ok(())
            }
        }
        impl CryptoGenerator for $ChaChaXCore {}
        impl TryCryptoRng for $ChaChaXRng {}

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $ChaChaXCore {}

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $ChaChaXRng {}

        // Custom Debug implementation that does not expose the internal state
        impl Debug for $ChaChaXRng {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "ChaChaXCore {{}}")
            }
        }

        impl $ChaChaXRng {
            // The buffer is a 4-block window, i.e. it is always at a block-aligned position in the
            // stream but if the stream has been sought it may not be self-aligned.

            /// Get the offset from the start of the stream, in 32-bit words.
            ///
            /// Since the generated blocks are 64 words (2<sup>6</sup>) long and the
            /// counter is 64-bits, the offset is a 68-bit number. Sub-word offsets are
            /// not supported, hence the result can simply be multiplied by 4 to get a
            /// byte-offset.
            #[inline]
            pub fn get_word_pos(&self) -> u128 {
                let mut block_counter = (u64::from(self.core.core.0.state[13]) << 32)
                    | u64::from(self.core.core.0.state[12]);
                if self.core.word_offset() != 0 {
                    block_counter = block_counter.wrapping_sub(BUF_BLOCKS as u64);
                }
                let word_pos =
                    block_counter as u128 * BLOCK_WORDS as u128 + self.core.word_offset() as u128;
                // eliminate bits above the 68th bit
                word_pos & ((1 << 68) - 1)
            }

            /// Set the offset from the start of the stream, in 32-bit words. **This
            /// value will be erased when calling `set_stream()`, so call
            /// `set_stream()` before calling `set_word_pos()`** if you intend on
            /// using both of them together.
            ///
            /// As with `get_word_pos`, we use a 68-bit number. Since the generator
            /// simply cycles at the end of its period (1 ZiB), we ignore the upper
            /// 60 bits.
            #[inline]
            pub fn set_word_pos(&mut self, word_offset: u128) {
                let index = (word_offset % BLOCK_WORDS as u128) as usize;
                let counter = word_offset / BLOCK_WORDS as u128;
                //self.set_block_pos(counter as u64);
                self.core.core.0.state[12] = counter as u32;
                self.core.core.0.state[13] = (counter >> 32) as u32;
                self.core.reset_and_skip(index);
            }

            /// Sets the block pos and resets the RNG's index. **This value will be
            /// erased when calling `set_stream()`, so call `set_stream()` before
            /// calling `set_block_pos()`** if you intend on using both of them
            /// together.
            ///
            /// The word pos will be equal to `block_pos * 16 words per block`.
            ///
            /// This method takes any of the following:
            /// * `u64`
            /// * `[u32; 2]`
            /// * `[u8; 8]`
            ///
            /// Note: the arrays should be in little endian order.
            #[inline]
            #[allow(unused)]
            pub fn set_block_pos<B: Into<BlockPos>>(&mut self, block_pos: B) {
                self.core.reset_and_skip(0);
                let block_pos = block_pos.into().0;
                self.core.core.0.state[12] = block_pos[0];
                self.core.core.0.state[13] = block_pos[1]
            }

            /// Get the block pos.
            #[inline]
            #[allow(unused)]
            pub fn get_block_pos(&self) -> u64 {
                let counter =
                    self.core.core.0.state[12] as u64 | ((self.core.core.0.state[13] as u64) << 32);
                if self.core.word_offset() != 0 {
                    counter - BUF_BLOCKS as u64 + self.core.word_offset() as u64 / 16
                } else {
                    counter
                }
            }

            /// Sets the stream number, resetting the `index` and `block_pos` to 0,
            /// effectively setting the `word_pos` to 0 as well. Consider storing
            /// the `word_pos` prior to calling this method.
            ///
            /// This method takes any of the following:
            /// * `u64`
            /// * `[u32; 2]`
            /// * `[u8; 8]`
            ///
            /// Note: the arrays should be in little endian order.
            ///
            /// This is initialized to zero; 2<sup>64</sup> unique streams of output
            /// are available per seed/key. In theory a 96-bit nonce can be used by
            /// passing the last 64-bits to this function and using the first 32-bits as
            /// the most significant half of the 64-bit counter, which may be set
            /// directly via `set_block_pos` like so:
            ///
            /// ```
            /// use chacha20::ChaCha20Rng;
            /// use rand_core::{SeedableRng, RngCore};
            ///
            /// let seed = [2u8; 32];
            /// let mut rng = ChaCha20Rng::from_seed(seed);
            ///
            /// // set state[12] to 0, state[13] to 1, state[14] to 2, state[15] to 3
            /// rng.set_stream([2u32, 3u32]);
            /// rng.set_block_pos([0u32, 1u32]);
            ///
            /// // confirm that state is set correctly
            /// assert_eq!(rng.get_block_pos(), 1 << 32);
            /// assert_eq!(rng.get_stream(), (3 << 32) + 2);
            ///
            /// // restoring `word_pos`/`index` after calling `set_stream`:
            /// let word_pos = rng.get_word_pos();
            /// rng.set_stream(4);
            /// rng.set_word_pos(word_pos);
            /// ```
            #[inline]
            pub fn set_stream<S: Into<StreamId>>(&mut self, stream: S) {
                let stream: StreamId = stream.into();
                self.core.core.0.state[14..].copy_from_slice(&stream.0);
                self.set_block_pos(0);
            }

            /// Get the stream number.
            #[inline]
            pub fn get_stream(&self) -> u64 {
                let mut result = [0u8; 8];
                for (i, &big) in self.core.core.0.state[14..BLOCK_WORDS as usize]
                    .iter()
                    .enumerate()
                {
                    let index = i * 4;
                    result[index + 0] = big as u8;
                    result[index + 1] = (big >> 8) as u8;
                    result[index + 2] = (big >> 16) as u8;
                    result[index + 3] = (big >> 24) as u8;
                }
                u64::from_le_bytes(result)
            }

            /// Get the seed.
            #[inline]
            pub fn get_seed(&self) -> [u8; 32] {
                let mut result = [0u8; 32];
                for (i, &big) in self.core.core.0.state[4..12].iter().enumerate() {
                    let index = i * 4;
                    result[index + 0] = big as u8;
                    result[index + 1] = (big >> 8) as u8;
                    result[index + 2] = (big >> 16) as u8;
                    result[index + 3] = (big >> 24) as u8;
                }
                result
            }
        }

        impl PartialEq<$ChaChaXRng> for $ChaChaXRng {
            fn eq(&self, rhs: &$ChaChaXRng) -> bool {
                let a: $abst::$ChaChaXRng = self.into();
                let b: $abst::$ChaChaXRng = rhs.into();
                a == b
            }
        }

        impl Eq for $ChaChaXRng {}

        impl From<$ChaChaXCore> for $ChaChaXRng {
            fn from(core: $ChaChaXCore) -> Self {
                $ChaChaXRng {
                    core: BlockRng::new(core),
                }
            }
        }

        mod $abst {
            // The abstract state of a ChaCha stream, independent of implementation choices. The
            // comparison and serialization of this object is considered a semver-covered part of
            // the API.
            #[derive(Debug, PartialEq, Eq)]
            pub(crate) struct $ChaChaXRng {
                seed: crate::rng::Seed,
                stream: u64,
                word_pos: u128,
            }

            impl From<&super::$ChaChaXRng> for $ChaChaXRng {
                // Forget all information about the input except what is necessary to determine the
                // outputs of any sequence of pub API calls.
                fn from(r: &super::$ChaChaXRng) -> Self {
                    Self {
                        seed: r.get_seed().into(),
                        stream: r.get_stream(),
                        word_pos: r.get_word_pos(),
                    }
                }
            }

            impl From<&$ChaChaXRng> for super::$ChaChaXRng {
                // Construct one of the possible concrete RNGs realizing an abstract state.
                fn from(a: &$ChaChaXRng) -> Self {
                    use rand_core::SeedableRng;
                    let mut r = Self::from_seed(a.seed.0.into());
                    r.set_stream(a.stream);
                    r.set_word_pos(a.word_pos);
                    r
                }
            }
        }

        impl Generator for $ChaChaXCore {
            type Output = [u32; BUFFER_SIZE];

            #[inline]
            fn generate(&mut self, r: &mut Self::Output) {
                self.0.generate(r);
            }

            #[cfg(feature = "zeroize")]
            fn drop(&mut self, output: &mut Self::Output) {
                output.zeroize();
            }
        }
    };
}

impl_chacha_rng!(ChaCha8Rng, ChaCha8Core, R8, abst8);

impl_chacha_rng!(ChaCha12Rng, ChaCha12Core, R12, abst12);

impl_chacha_rng!(ChaCha20Rng, ChaCha20Core, R20, abst20);

#[cfg(test)]
pub(crate) mod tests {
    use rand_core::RngCore;

    use super::*;

    const KEY: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_wrapping_add() {
        let mut rng = ChaCha20Rng::from_seed(KEY);
        rng.set_stream(1337);
        // test counter wrapping-add
        rng.set_word_pos((1 << 68) - 65);
        let mut output = [3u8; 1280];
        rng.fill_bytes(&mut output);

        assert_ne!(output, [0u8; 1280]);

        assert!(rng.get_word_pos() < 2000);
        assert!(rng.get_word_pos() != 0);
    }

    #[test]
    fn test_set_and_get_equivalence() {
        let seed = [44u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // test set_stream with [u32; 2]
        rng.set_stream([313453u32, 0u32]);
        assert_eq!(rng.get_stream(), 313453);

        // test set_stream with [u8; 12]
        rng.set_stream([89, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(rng.get_stream(), 89);

        // test set_stream with u128
        rng.set_stream(11111111);
        assert_eq!(rng.get_stream(), 11111111);

        // test set_block_pos with u32
        rng.set_block_pos(58392);
        assert_eq!(rng.get_block_pos(), 58392);
        // test word_pos = 16 * block_pos
        assert_eq!(rng.get_word_pos(), 58392 * 16);

        // test set_block_pos with [u8; 8]
        rng.set_block_pos([77, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(rng.get_block_pos(), 77);

        // test set_word_pos with u64
        rng.set_word_pos(8888);
        assert_eq!(rng.get_word_pos(), 8888);
    }

    type ChaChaRng = ChaCha20Rng;

    #[test]
    fn test_chacha_clone_streams() {
        let seed = [
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ];
        let mut rng1 = ChaChaRng::from_seed(seed);
        let mut rng2 = ChaChaRng::from_seed(seed);
        for _ in 0..16 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }

        rng1.set_stream(51);
        assert_eq!(rng1.get_stream(), 51);
        assert_eq!(rng2.get_stream(), 0);
        let mut fill_1 = [0u8; 7];
        rng1.fill_bytes(&mut fill_1);
        let mut fill_2 = [0u8; 7];
        rng2.fill_bytes(&mut fill_2);
        assert_ne!(fill_1, fill_2);
        for _ in 0..7 {
            assert!(rng1.next_u64() != rng2.next_u64());
        }
        rng2.set_stream(51); // switch part way through block
        for _ in 7..16 {
            assert_ne!(rng1.next_u64(), rng2.next_u64());
        }
        rng1.set_stream(51);
        rng2.set_stream(51);
        for _ in 0..16 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_chacha_word_pos_wrap_exact() {
        use super::{BLOCK_WORDS, BUF_BLOCKS};
        let mut rng = ChaChaRng::from_seed(Default::default());
        // refilling the buffer in set_word_pos will wrap the block counter to 0
        let last_block = (1 << 68) - u128::from(BUF_BLOCKS * BLOCK_WORDS);
        rng.set_word_pos(last_block);
        assert_eq!(rng.get_word_pos(), last_block);
    }

    #[test]
    fn test_chacha_word_pos_wrap_excess() {
        use super::BLOCK_WORDS;
        let mut rng = ChaChaRng::from_seed(Default::default());
        // refilling the buffer in set_word_pos will wrap the block counter past 0
        let last_block = (1 << 68) - u128::from(BLOCK_WORDS);
        rng.set_word_pos(last_block);
        assert_eq!(rng.get_word_pos(), last_block);
    }

    #[test]
    fn test_chacha_word_pos_zero() {
        let mut rng = ChaChaRng::from_seed(Default::default());
        assert_eq!(rng.core.core.0.state[12], 0);
        assert_eq!(rng.core.word_offset(), 0);
        assert_eq!(rng.get_word_pos(), 0);
        rng.set_word_pos(0);
        assert_eq!(rng.get_word_pos(), 0);
    }

    #[test]
    #[allow(trivial_casts)]
    fn test_trait_objects() {
        use rand_core::CryptoRng;

        let seed = Default::default();
        let mut rng1 = ChaChaRng::from_seed(seed);
        let mut rng2 = &mut ChaChaRng::from_seed(seed) as &mut dyn CryptoRng;
        for _ in 0..1000 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    /// If this test fails, the backend may not be
    /// performing 64-bit addition.
    #[test]
    fn counter_wrapping_64_bit_counter() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        // get first four blocks and word pos
        let mut first_blocks = [0u8; 64 * 4];
        rng.fill_bytes(&mut first_blocks);
        let first_blocks_end_word_pos = rng.get_word_pos();
        let first_blocks_end_block_counter = rng.get_block_pos();

        // get first four blocks after wrapping
        rng.set_block_pos([u32::MAX, u32::MAX]);
        let mut result = [0u8; 64 * 5];
        rng.fill_bytes(&mut result);
        assert_eq!(first_blocks_end_word_pos, rng.get_word_pos());
        assert_eq!(first_blocks_end_block_counter, rng.get_block_pos());

        if first_blocks[0..64 * 4].ne(&result[64..]) {
            for (i, (a, b)) in first_blocks.iter().zip(result.iter().skip(64)).enumerate() {
                if a.ne(b) {
                    panic!("i = {}\na = {}\nb = {}", i, a, b);
                }
            }
        }
        assert_eq!(&first_blocks[0..64 * 4], &result[64..]);
    }

    /// If this test fails, the backend may be doing
    /// 32-bit addition.
    #[test]
    fn counter_not_wrapping_at_32_bits() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        // get first four blocks and word pos
        let mut first_blocks = [0u8; 64 * 4];
        rng.fill_bytes(&mut first_blocks);
        let first_blocks_end_word_pos = rng.get_word_pos();

        // get first four blocks after the supposed overflow
        rng.set_block_pos(u32::MAX as u64);
        let mut result = [0u8; 64 * 5];
        rng.fill_bytes(&mut result);
        assert_ne!(first_blocks_end_word_pos, rng.get_word_pos());
        assert_eq!(
            rng.get_word_pos(),
            first_blocks_end_word_pos + (1 << 32) * BLOCK_WORDS as u128
        );
        assert_ne!(&first_blocks[0..64 * 4], &result[64..]);
    }
}
