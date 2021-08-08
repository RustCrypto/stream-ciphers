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

/// Helper union for accessing per-block state.
///
/// ChaCha20 block state is stored in four 32-bit words, so we can process two blocks in
/// parallel. We store the state words as a union to enable cheap transformations between
/// their interpretations.
#[derive(Clone, Copy)]
union StateWord {
    blocks: [__m128i; 2],
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
            self.rounds(&mut v0.avx, &mut v1.avx, &mut v2.avx, &mut v3.avx);
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
            self.rounds(&mut v0.avx, &mut v1.avx, &mut v2.avx, &mut v3.avx);

            for (chunk, a) in output[..BLOCK_SIZE]
                .chunks_mut(0x10)
                .zip([v0, v1, v2, v3].iter().map(|s| s.blocks[0]))
            {
                let b = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
                let out = _mm_xor_si128(a, b);
                _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, out);
            }

            for (chunk, a) in output[BLOCK_SIZE..]
                .chunks_mut(0x10)
                .zip([v0, v1, v2, v3].iter().map(|s| s.blocks[1]))
            {
                let b = _mm_loadu_si128(chunk.as_ptr() as *const __m128i);
                let out = _mm_xor_si128(a, b);
                _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, out);
            }
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn rounds(
        &self,
        v0: &mut __m256i,
        v1: &mut __m256i,
        v2: &mut __m256i,
        v3: &mut __m256i,
    ) {
        let v3_orig = *v3;

        for _ in 0..(R::COUNT / 2) {
            double_quarter_round(v0, v1, v2, v3);
        }

        *v0 = _mm256_add_epi32(*v0, self.v0.avx);
        *v1 = _mm256_add_epi32(*v1, self.v1.avx);
        *v2 = _mm256_add_epi32(*v2, self.v2.avx);
        *v3 = _mm256_add_epi32(*v3, v3_orig);
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

    for (chunk, v) in output[..BLOCK_SIZE]
        .chunks_mut(0x10)
        .zip([v0, v1, v2, v3].iter().map(|s| s.blocks[0]))
    {
        _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, v);
    }

    for (chunk, v) in output[BLOCK_SIZE..]
        .chunks_mut(0x10)
        .zip([v0, v1, v2, v3].iter().map(|s| s.blocks[1]))
    {
        _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, v);
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn double_quarter_round(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    add_xor_rot(a, b, c, d);
    rows_to_cols(a, b, c, d);
    add_xor_rot(a, b, c, d);
    cols_to_rows(a, b, c, d);
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rows_to_cols(_a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    // b = ROR256_B(b); c = ROR256_C(c); d = ROR256_D(d);
    *b = _mm256_shuffle_epi32(*b, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    *c = _mm256_shuffle_epi32(*c, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    *d = _mm256_shuffle_epi32(*d, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn cols_to_rows(_a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    // b = ROR256_D(b); c = ROR256_C(c); d = ROR256_B(d);
    *b = _mm256_shuffle_epi32(*b, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    *c = _mm256_shuffle_epi32(*c, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    *d = _mm256_shuffle_epi32(*d, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn add_xor_rot(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_16(d);
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = _mm256_shuffle_epi8(
        *d,
        _mm256_set_epi8(
            13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5,
            4, 7, 6, 1, 0, 3, 2,
        ),
    );

    // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_12(b);
    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = _mm256_xor_si256(_mm256_slli_epi32(*b, 12), _mm256_srli_epi32(*b, 20));

    // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_8(d);
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = _mm256_shuffle_epi8(
        *d,
        _mm256_set_epi8(
            14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6,
            5, 4, 7, 2, 1, 0, 3,
        ),
    );

    // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_7(b);
    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = _mm256_xor_si256(_mm256_slli_epi32(*b, 7), _mm256_srli_epi32(*b, 25));
}
