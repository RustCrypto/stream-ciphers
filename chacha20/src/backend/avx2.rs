//! The ChaCha20 core function. Defined in RFC 8439 Section 2.3.
//!
//! <https://tools.ietf.org/html/rfc8439#section-2.3>
//!
//! AVX2-optimized implementation for x86/x86-64 CPUs adapted from the SUPERCOP
//! `goll_gueron` backend (public domain) described in:
//!
//! Goll, M., and Gueron,S.: Vectorization of ChaCha Stream Cipher. Cryptology ePrint Archive,
//! Report 2013/759, November, 2013, <https://eprint.iacr.org/2013/759.pdf>

use super::autodetect::BUFFER_SIZE;
use crate::{rounds::Rounds, BLOCK_SIZE, CONSTANTS, IV_SIZE, KEY_SIZE};
use core::{convert::TryInto, marker::PhantomData};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// The number of blocks processed per invocation by this backend.
const BLOCKS: usize = 2;

/// Helper union for accessing per-block state.
///
/// ChaCha20 block state is stored in four 32-bit words, so we can process two blocks in
/// parallel. We store the state words as a union to enable cheap transformations between
/// their interpretations.
#[derive(Clone, Copy)]
union StateWord {
    blocks: [__m128i; BLOCKS],
    avx: __m256i,
}

/// The ChaCha20 core function (AVX2 accelerated implementation for x86/x86_64)
// TODO(tarcieri): zeroize?
#[derive(Clone)]
pub(crate) struct Core<R: Rounds> {
    v0: StateWord,
    v1: StateWord,
    v2: StateWord,
    iv: [i32; 2],
    rounds: PhantomData<R>,
}

impl<R: Rounds> Core<R> {
    /// Initialize core function with the given key size, IV, and number of rounds
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE], iv: [u8; IV_SIZE]) -> Self {
        let (v0, v1, v2) = unsafe { key_setup(key) };
        let iv = [
            i32::from_le_bytes(iv[4..].try_into().unwrap()),
            i32::from_le_bytes(iv[..4].try_into().unwrap()),
        ];

        Self {
            v0,
            v1,
            v2,
            iv,
            rounds: PhantomData,
        }
    }

    #[inline]
    pub fn generate(&self, counter: u64, output: &mut [u8]) {
        unsafe {
            let (mut v0, mut v1, mut v2) = (self.v0, self.v1, self.v2);
            let mut v3 = iv_setup(self.iv, counter);
            self.rounds(&mut v0, &mut v1, &mut v2, &mut v3);
            store(v0, v1, v2, v3, output);
        }
    }

    #[inline]
    #[cfg(feature = "cipher")]
    #[allow(clippy::cast_ptr_alignment)] // loadu/storeu support unaligned loads/stores
    pub fn apply_keystream(&self, counter: u64, output: &mut [u8]) {
        debug_assert_eq!(output.len(), BUFFER_SIZE);

        unsafe {
            let (mut v0, mut v1, mut v2) = (self.v0, self.v1, self.v2);
            let mut v3 = iv_setup(self.iv, counter);
            self.rounds(&mut v0, &mut v1, &mut v2, &mut v3);

            for i in 0..BLOCKS {
                for (chunk, a) in output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                    .chunks_mut(0x10)
                    .zip([v0, v1, v2, v3].iter().map(|s| s.blocks[i]))
                {
                    let b = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
                    let out = _mm_xor_si128(a, b);
                    _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, out);
                }
            }
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn rounds(
        &self,
        v0: &mut StateWord,
        v1: &mut StateWord,
        v2: &mut StateWord,
        v3: &mut StateWord,
    ) {
        let v3_orig = v3.avx;

        for _ in 0..(R::COUNT / 2) {
            double_quarter_round(v0, v1, v2, v3);
        }

        v0.avx = _mm256_add_epi32(v0.avx, self.v0.avx);
        v1.avx = _mm256_add_epi32(v1.avx, self.v1.avx);
        v2.avx = _mm256_add_epi32(v2.avx, self.v2.avx);
        v3.avx = _mm256_add_epi32(v3.avx, v3_orig);
    }
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(clippy::cast_ptr_alignment)] // loadu supports unaligned loads
unsafe fn key_setup(key: &[u8; KEY_SIZE]) -> (StateWord, StateWord, StateWord) {
    let v0 = _mm_loadu_si128(CONSTANTS.as_ptr() as *const __m128i);
    let v1 = _mm_loadu_si128(key.as_ptr().offset(0x00) as *const __m128i);
    let v2 = _mm_loadu_si128(key.as_ptr().offset(0x10) as *const __m128i);

    (
        StateWord { blocks: [v0, v0] },
        StateWord { blocks: [v1, v1] },
        StateWord { blocks: [v2, v2] },
    )
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn iv_setup(iv: [i32; 2], counter: u64) -> StateWord {
    let s3 = _mm_set_epi32(
        iv[0],
        iv[1],
        ((counter >> 32) & 0xffff_ffff) as i32,
        (counter & 0xffff_ffff) as i32,
    );

    StateWord {
        blocks: [s3, _mm_add_epi64(s3, _mm_set_epi64x(0, 1))],
    }
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(clippy::cast_ptr_alignment)] // storeu supports unaligned stores
unsafe fn store(v0: StateWord, v1: StateWord, v2: StateWord, v3: StateWord, output: &mut [u8]) {
    debug_assert_eq!(output.len(), BUFFER_SIZE);

    for i in 0..BLOCKS {
        for (chunk, v) in output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
            .chunks_mut(0x10)
            .zip([v0, v1, v2, v3].iter().map(|s| s.blocks[i]))
        {
            _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, v);
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn double_quarter_round(
    a: &mut StateWord,
    b: &mut StateWord,
    c: &mut StateWord,
    d: &mut StateWord,
) {
    add_xor_rot(a, b, c, d);
    rows_to_cols(a, b, c, d);
    add_xor_rot(a, b, c, d);
    cols_to_rows(a, b, c, d);
}

/// The goal of this function is to transform the state words from:
/// ```text
/// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
/// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
/// [c0, c1, c2, c3]    [ 8,  9, 10, 11]
/// [d0, d1, d2, d3]    [12, 13, 14, 15]
/// ```
///
/// to:
/// ```text
/// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
/// [b1, b2, b3, b0] == [ 5,  6,  7,  4]
/// [c2, c3, c0, c1]    [10, 11,  8,  9]
/// [d3, d0, d1, d2]    [15, 12, 13, 14]
/// ```
///
/// so that we can apply [`add_xor_rot`] to the resulting columns, and have it compute the
/// "diagonal rounds" (as defined in RFC 7539) in parallel. In practice, this shuffle is
/// non-optimal: the last state word to be altered in `add_xor_rot` is `b`, so the shuffle
/// blocks on the result of `b` being calculated.
///
/// We can optimize this by observing that the four quarter rounds in `add_xor_rot` are
/// data-independent: they only access a single column of the state, and thus the order of
/// the columns does not matter. We therefore instead shuffle the other three state words,
/// to obtain the following equivalent layout:
/// ```text
/// [a3, a0, a1, a2]    [ 3,  0,  1,  2]
/// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
/// [c1, c2, c3, c0]    [ 9, 10, 11,  8]
/// [d2, d3, d0, d1]    [14, 15, 12, 13]
/// ```
///
/// See https://github.com/sneves/blake2-avx2/pull/4 for additional details. The earliest
/// known occurrence of this optimization is in floodyberry's SSE4 ChaCha code from 2014:
/// - https://github.com/floodyberry/chacha-opt/blob/0ab65cb99f5016633b652edebaf3691ceb4ff753/chacha_blocks_ssse3-64.S#L639-L643
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rows_to_cols(
    a: &mut StateWord,
    _b: &mut StateWord,
    c: &mut StateWord,
    d: &mut StateWord,
) {
    // c = ROR256_B(c); d = ROR256_C(d); a = ROR256_D(a);
    c.avx = _mm256_shuffle_epi32(c.avx, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    d.avx = _mm256_shuffle_epi32(d.avx, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    a.avx = _mm256_shuffle_epi32(a.avx, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
}

/// The goal of this function is to transform the state words from:
/// ```text
/// [a3, a0, a1, a2]    [ 3,  0,  1,  2]
/// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
/// [c1, c2, c3, c0]    [ 9, 10, 11,  8]
/// [d2, d3, d0, d1]    [14, 15, 12, 13]
/// ```
///
/// to:
/// ```text
/// [a0, a1, a2, a3]    [ 0,  1,  2,  3]
/// [b0, b1, b2, b3] == [ 4,  5,  6,  7]
/// [c0, c1, c2, c3]    [ 8,  9, 10, 11]
/// [d0, d1, d2, d3]    [12, 13, 14, 15]
/// ```
///
/// reversing the transformation of [`rows_to_cols`].
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn cols_to_rows(
    a: &mut StateWord,
    _b: &mut StateWord,
    c: &mut StateWord,
    d: &mut StateWord,
) {
    // c = ROR256_D(c); d = ROR256_C(d); a = ROR256_B(a);
    c.avx = _mm256_shuffle_epi32(c.avx, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    d.avx = _mm256_shuffle_epi32(d.avx, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    a.avx = _mm256_shuffle_epi32(a.avx, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn add_xor_rot(a: &mut StateWord, b: &mut StateWord, c: &mut StateWord, d: &mut StateWord) {
    // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_16(d);
    a.avx = _mm256_add_epi32(a.avx, b.avx);
    d.avx = _mm256_xor_si256(d.avx, a.avx);
    d.avx = _mm256_shuffle_epi8(
        d.avx,
        _mm256_set_epi8(
            13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5,
            4, 7, 6, 1, 0, 3, 2,
        ),
    );

    // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_12(b);
    c.avx = _mm256_add_epi32(c.avx, d.avx);
    b.avx = _mm256_xor_si256(b.avx, c.avx);
    b.avx = _mm256_xor_si256(_mm256_slli_epi32(b.avx, 12), _mm256_srli_epi32(b.avx, 20));

    // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_8(d);
    a.avx = _mm256_add_epi32(a.avx, b.avx);
    d.avx = _mm256_xor_si256(d.avx, a.avx);
    d.avx = _mm256_shuffle_epi8(
        d.avx,
        _mm256_set_epi8(
            14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6,
            5, 4, 7, 2, 1, 0, 3,
        ),
    );

    // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_7(b);
    c.avx = _mm256_add_epi32(c.avx, d.avx);
    b.avx = _mm256_xor_si256(b.avx, c.avx);
    b.avx = _mm256_xor_si256(_mm256_slli_epi32(b.avx, 7), _mm256_srli_epi32(b.avx, 25));
}
