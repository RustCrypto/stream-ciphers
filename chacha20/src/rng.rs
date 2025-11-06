// Copyright 2018 Developers of the Rand project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::fmt::Debug;

use rand_core::{
    CryptoRng, RngCore, SeedableRng,
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
const BUF_BLOCKS: u8 = BUFFER_SIZE as u8 >> 4;

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
        impl RngCore for $ChaChaXRng {
            #[inline]
            fn next_u32(&mut self) -> u32 {
                self.core.next_word()
            }
            #[inline]
            fn next_u64(&mut self) -> u64 {
                self.core.next_u64_from_u32()
            }
            #[inline]
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                self.core.fill_bytes(dest)
            }
        }
        impl CryptoGenerator for $ChaChaXCore {}
        impl CryptoRng for $ChaChaXRng {}

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
                block_counter = block_counter.wrapping_sub(BUF_BLOCKS as u64);
                let word_pos =
                    block_counter as u128 * BLOCK_WORDS as u128 + self.core.index() as u128;
                // eliminate bits above the 68th bit
                word_pos & ((1 << 68) - 1)
            }

            /// Set the offset from the start of the stream, in 32-bit words.
            ///
            /// As with `get_word_pos`, we use a 68-bit number. Since the generator
            /// simply cycles at the end of its period (1 ZiB), we ignore the upper
            /// 60 bits.
            #[inline]
            pub fn set_word_pos(&mut self, word_offset: u128) {
                let index = (word_offset & 0b1111) as usize;
                let counter = word_offset >> 4;
                //self.set_block_pos(counter as u64);
                self.core.core.0.state[12] = counter as u32;
                self.core.core.0.state[13] = (counter >> 32) as u32;
                self.core.generate_and_set(index);
            }

            /// Set the block pos and reset the RNG's index.
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
                self.core.reset();
                let block_pos = block_pos.into().0;
                self.core.core.0.state[12] = block_pos[0];
                self.core.core.0.state[13] = block_pos[1]
            }

            /// Get the block pos.
            #[inline]
            #[allow(unused)]
            pub fn get_block_pos(&self) -> u64 {
                self.core.core.0.state[12] as u64 | ((self.core.core.0.state[13] as u64) << 32)
            }

            /// Set the stream number. The lower 64 bits are used and the rest are
            /// discarded. This method takes any of the following:
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
            /// rng.set_block_pos([0u32, 1u32]);
            /// rng.set_stream([2u32, 3u32]);
            ///
            /// // confirm that state is set correctly
            /// assert_eq!(rng.get_block_pos(), 1 << 32);
            /// assert_eq!(rng.get_stream(), (3 << 32) + 2);
            /// ```
            #[inline]
            pub fn set_stream<S: Into<StreamId>>(&mut self, stream: S) {
                let stream: StreamId = stream.into();
                self.core.core.0.state[14..].copy_from_slice(&stream.0);
                if self.core.index() != BUFFER_SIZE {
                    self.core.generate_and_set(self.core.index());
                }
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

    use hex_literal::hex;

    use super::*;

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
    fn test_chacha_construction() {
        let seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let mut rng1 = ChaChaRng::from_seed(seed);
        assert_eq!(rng1.next_u32(), 137206642);

        assert_eq!(rng1.get_seed(), seed);

        let mut rng2 = ChaChaRng::from_rng(&mut rng1);
        assert_eq!(rng2.next_u32(), 1325750369);
    }

    #[test]
    fn test_chacha_true_values_a() {
        // Test vectors 1 and 2 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8,
            0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815,
            0x69b687c3, 0x8665eeb2,
        ];
        assert_eq!(results, expected);

        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612,
            0xed7aee32, 0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51,
            0x1f0ae1ac, 0x6f4d794b,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_true_values_b() {
        // Test vector 3 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let mut rng = ChaChaRng::from_seed(seed);

        // Skip block 0
        for _ in 0..16 {
            rng.next_u32();
        }

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8,
            0x5aaa49c9, 0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8,
            0xebdd4aa6, 0xa0136c00,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_true_values_c() {
        // Test vector 4 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [
            0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let expected = [
            0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1,
            0xcaf09aae, 0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5,
            0x87f47473, 0x96f0992e,
        ];
        let expected_end = 3 * 16;
        let mut results = [0u32; 16];

        // Test block 2 by skipping block 0 and 1
        let mut rng1 = ChaChaRng::from_seed(seed);
        for _ in 0..32 {
            rng1.next_u32();
        }
        for i in results.iter_mut() {
            *i = rng1.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng1.get_word_pos(), expected_end);

        // Test block 2 by using `set_word_pos`
        let mut rng2 = ChaChaRng::from_seed(seed);
        rng2.set_word_pos(2 * 16);
        for i in results.iter_mut() {
            *i = rng2.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng2.get_word_pos(), expected_end);

        // Test block 2 by using `set_block_pos` and u32
        let mut rng3 = ChaChaRng::from_seed(seed);
        rng3.set_block_pos(2);
        results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng3.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng3.get_word_pos(), expected_end);

        // Test block 2 by using `set_block_pos` and [u8; 8]
        let mut rng4 = ChaChaRng::from_seed(seed);
        rng4.set_block_pos([2, 0, 0, 0, 0, 0, 0, 0]);
        results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng4.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng4.get_word_pos(), expected_end);

        // Test skipping behaviour with other types
        let mut buf = [0u8; 32];
        rng2.fill_bytes(&mut buf[..]);
        assert_eq!(rng2.get_word_pos(), expected_end + 8);
        rng2.fill_bytes(&mut buf[0..25]);
        assert_eq!(rng2.get_word_pos(), expected_end + 15);
        rng2.next_u64();
        assert_eq!(rng2.get_word_pos(), expected_end + 17);
        rng2.next_u32();
        rng2.next_u64();
        assert_eq!(rng2.get_word_pos(), expected_end + 20);
        rng2.fill_bytes(&mut buf[0..1]);
        assert_eq!(rng2.get_word_pos(), expected_end + 21);
    }

    #[test]
    fn test_chacha_multiple_blocks() {
        let seed = [
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ];
        let mut rng = ChaChaRng::from_seed(seed);

        // Store the 17*i-th 32-bit word,
        // i.e., the i-th word of the i-th 16-word block
        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
            for _ in 0..16 {
                rng.next_u32();
            }
        }
        let expected = [
            0xf225c81a, 0x6ab1be57, 0x04d42951, 0x70858036, 0x49884684, 0x64efec72, 0x4be2d186,
            0x3615b384, 0x11cfa18e, 0xd3c50049, 0x75c775f6, 0x434c6530, 0x2c5bad8f, 0x898881dc,
            0x5f1c86d9, 0xc1f8e7f4,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_true_bytes() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let mut results = [0u8; 32];
        rng.fill_bytes(&mut results);
        let expected = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_nonce() {
        use hex_literal::hex;
        // Test vector 5 from
        // https://www.rfc-editor.org/rfc/rfc8439#section-2.3.2
        let seed = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut rng = ChaChaRng::from_seed(seed);

        let stream_id = hex!("0000004a00000000");
        rng.set_stream(stream_id);
        rng.set_block_pos(hex!("0000000000000009"));

        // The test vectors omit the first 64-bytes of the keystream
        let mut discard_first_64 = [0u8; 64];
        rng.fill_bytes(&mut discard_first_64);

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_nonce_2() {
        // Test vector 5 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        // Although we do not support setting a nonce, we try it here anyway so
        // we can use this test vector.
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        // 96-bit nonce in LE order is: 0,0,0,0, 0,0,0,0, 0,0,0,2
        rng.set_stream(2u64 << (24 + 32));

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef, 0x88228b1a, 0x96a4dfb3, 0x5b76ab72,
            0xc727ee54, 0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297, 0x99c28f5f, 0x628314e8,
            0x398a19fa, 0x6ded1b53,
        ];
        assert_eq!(results, expected);
    }

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
        assert_eq!(rng.core.index(), 64);
        assert_eq!(rng.get_word_pos(), 0);
        rng.set_word_pos(0);
        assert_eq!(rng.get_word_pos(), 0);
    }

    #[test]
    /// Testing the edge cases of `fill_bytes()` by brute-forcing it with dest sizes
    /// that start at 1, and increase by 1 up to `N`, then they decrease from `N`
    /// to 1, and this can repeat multiple times if desired.
    ///
    /// This test uses `rand_chacha v0.3.1` because this version's API is directly
    /// based on `rand_chacha v0.3.1`, and previous versions of `chacha20` could be
    /// affected by rust flags for changing the backend. Also, it doesn't seem to work
    /// with `chacha20 v0.8`
    ///
    /// Because this test uses `rand_chacha v0.3.1` which uses a 64-bit counter, these
    /// test results should be accurate up to `block_pos = 2^32 - 1`.
    fn test_fill_bytes_v2() {
        use rand_chacha::ChaCha20Rng as TesterRng;
        use rand_chacha::rand_core::{RngCore, SeedableRng};

        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let mut tester_rng = TesterRng::from_seed([0u8; 32]);

        let num_iterations = 32;

        // If N is too large, it could cause stack overflow.
        // With N = 1445, the arrays are 1044735 bytes each, or 0.9963 MiB
        const N: usize = 1000;
        // compute the sum from 1 to N, with increments of 1
        const LEN: usize = (N * (N + 1)) / 2;

        let mut test_array: [u8; LEN];
        let mut tester_array: [u8; LEN];

        for _iteration in 0..num_iterations {
            test_array = [0u8; LEN];
            tester_array = [0u8; LEN];

            let mut dest_pos = 0;
            // test fill_bytes with lengths starting at 1 byte, increasing by 1,
            // up to N bytes
            for test_len in 1..=N {
                let debug_start_word_pos = rng.get_word_pos();
                let end_pos = dest_pos + test_len;

                // ensure that the current dest_pos index isn't overwritten already
                assert_eq!(test_array[dest_pos], 0);
                rng.fill_bytes(&mut test_array[dest_pos..end_pos]);
                tester_rng.fill_bytes(&mut tester_array[dest_pos..end_pos]);

                if test_array[dest_pos..end_pos] != tester_array[dest_pos..end_pos] {
                    for (t, (index, expected)) in test_array[dest_pos..end_pos]
                        .iter()
                        .zip(tester_array[dest_pos..end_pos].iter().enumerate())
                    {
                        if t != expected {
                            panic!(
                                "Failed test at start_word_pos = {},\nfailed index: {:?}\nFailing word_pos = {}",
                                debug_start_word_pos,
                                index,
                                debug_start_word_pos + (index / 4) as u128
                            );
                        }
                    }
                }
                assert_eq!(rng.next_u32(), tester_rng.next_u32());

                dest_pos = end_pos;
            }
            test_array = [0u8; LEN];
            tester_array = [0u8; LEN];
            dest_pos = 0;

            // test fill_bytes with lengths starting at `N` bytes, decreasing by 1,
            // down to 1 byte
            for test_len in 1..=N {
                let debug_start_word_pos = rng.get_word_pos();
                let end_pos = dest_pos + N - test_len;

                // ensure that the current dest_pos index isn't overwritten already
                assert_eq!(test_array[dest_pos], 0);
                rng.fill_bytes(&mut test_array[dest_pos..end_pos]);
                tester_rng.fill_bytes(&mut tester_array[dest_pos..end_pos]);

                if test_array[dest_pos..end_pos] != tester_array[dest_pos..end_pos] {
                    for (t, (index, expected)) in test_array[dest_pos..end_pos]
                        .iter()
                        .zip(tester_array[dest_pos..end_pos].iter().enumerate())
                    {
                        if t != expected {
                            panic!(
                                "Failed test at start_word_pos = {},\nfailed index: {:?}\nFailing word_pos = {}",
                                debug_start_word_pos,
                                index,
                                debug_start_word_pos + (index / 4) as u128
                            );
                        }
                    }
                }
                assert_eq!(rng.next_u32(), tester_rng.next_u32());
                dest_pos = end_pos;
            }
        }
    }

    #[test]
    #[allow(trivial_casts)]
    fn test_trait_objects() {
        use rand_core::CryptoRng;

        let seed = Default::default();
        let mut rng1 = ChaChaRng::from_seed(seed);
        let rng2 = &mut ChaChaRng::from_seed(seed) as &mut dyn CryptoRng;
        for _ in 0..1000 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn stream_id_endianness() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        rng.set_stream([3, 3333]);
        let expected = 1152671828;
        assert_eq!(rng.next_u32(), expected);
        rng.set_stream(1234567);
        let expected = 3110319182;
        assert_eq!(rng.next_u32(), expected);
        rng.set_stream([1, 2, 3, 4, 5, 6, 7, 8]);
        let expected = 3790367479;
        assert_eq!(rng.next_u32(), expected);
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
        assert_eq!(first_blocks_end_block_counter, rng.get_block_pos() - 3);

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

    /// Counts how many bytes were incorrect, and returns:
    ///
    /// (`index_of_first_incorrect_word`, `num_incorrect_bytes`)
    fn count_incorrect_bytes(expected: &[u8], output: &[u8]) -> (Option<usize>, u32) {
        assert_eq!(expected.len(), output.len());
        let mut num_incorrect_bytes = 0;
        let mut index_of_first_incorrect_word = None;
        expected
            .iter()
            .enumerate()
            .zip(output.iter())
            .for_each(|((i, a), b)| {
                if a.ne(b) {
                    if index_of_first_incorrect_word.is_none() {
                        index_of_first_incorrect_word = Some(i / 4)
                    }
                    num_incorrect_bytes += 1;
                }
            });
        (index_of_first_incorrect_word, num_incorrect_bytes)
    }

    /// Test vector 8 from https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/ChaCha20/counter-overflow.txt
    #[test]
    fn counter_overflow_and_diagnostics() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let block_pos = 4294967295;
        assert_eq!(block_pos, u32::MAX as u64);
        rng.set_block_pos(4294967295);

        let mut output = [0u8; 64 * 4];
        rng.fill_bytes(&mut output[..64 * 3]);
        let block_before_overflow = hex!(
            "ace4cd09e294d1912d4ad205d06f95d9c2f2bfcf453e8753f128765b62215f4d92c74f2f626c6a640c0b1284d839ec81f1696281dafc3e684593937023b58b1d"
        );
        let first_block_after_overflow = hex!(
            "3db41d3aa0d329285de6f225e6e24bd59c9a17006943d5c9b680e3873bdc683a5819469899989690c281cd17c96159af0682b5b903468a61f50228cf09622b5a"
        );
        let second_block_after_overflow = hex!(
            "46f0f6efee15c8f1b198cb49d92b990867905159440cc723916dc0012826981039ce1766aa2542b05db3bd809ab142489d5dbfe1273e7399637b4b3213768aaa"
        );
        assert!(
            output[..64].eq(&block_before_overflow),
            "The first parblock was incorrect before overflow, indicating that ChaCha was not implemented correctly for this backend. Check the rounds() fn or the functions that it calls"
        );

        rng.set_block_pos(u32::MAX as u64 - 1);
        let mut skipped_blocks = [0u8; 64 * 3];
        rng.fill_bytes(&mut skipped_blocks);
        rng.fill_bytes(&mut output[64 * 3..]);

        output.chunks_exact(64).enumerate().skip(1).zip(&[first_block_after_overflow, second_block_after_overflow, second_block_after_overflow]).for_each(|((i, a), b)| {
            let (index_of_first_incorrect_word, num_incorrect_bytes) = count_incorrect_bytes(a, b);
            let msg = if num_incorrect_bytes == 0 {
                "The block was correct and this will not be shown"
            } else if num_incorrect_bytes > 32 {
                "Most of the block was incorrect, indicating an issue with the counter using 32-bit addition towards the beginning of fn rounds()"
            } else if num_incorrect_bytes <= 8 && matches!(index_of_first_incorrect_word, Some(12 | 13)) {
                "When the state was added to the results/res buffer at the end of fn rounds, the counter was probably incremented in 32-bit fashion for this parblock"
            } else {
                // this is probably unreachable in the event of a failed assertion, but it depends on the seed
                "Some of the block was incorrect"
            };
            assert!(a.eq(b), "PARBLOCK #{} uses incorrect counter addition\nDiagnostic = {}\nnum_incorrect_bytes = {}\nindex_of_first_incorrect_word = {:?}", i + 1, msg, num_incorrect_bytes, index_of_first_incorrect_word);
        });
    }

    /// Test vector 9 from https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/ChaCha20/counter-overflow.txt
    #[test]
    fn counter_wrap_1() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let block_pos = 18446744073709551615;
        assert_eq!(block_pos, u64::MAX);
        rng.set_block_pos(block_pos);

        let mut output = [0u8; 64 * 3];
        rng.fill_bytes(&mut output);
        let expected = hex!(
            "d7918cd8620cf832532652c04c01a553092cfb32e7b3f2f5467ae9674a2e9eec17368ec8027a357c0c51e6ea747121fec45284be0f099d2b3328845607b1768976b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
        );
        assert_eq!(expected, output);
    }
}
