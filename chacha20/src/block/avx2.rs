//! The ChaCha20 block function. Defined in RFC 8439 Section 2.3.
//!
//! <https://tools.ietf.org/html/rfc8439#section-2.3>
//!
//! AVX2-optimized implementation for x86/x86-64 CPUs adapted from the SUPERCOP
//! `goll_gueron` backend (public domain) described in:
//!
//! Goll, M., and Gueron,S.: Vectorization of ChaCha Stream Cipher. Cryptology ePrint Archive,
//! Report 2013/759, November, 2013, <https://eprint.iacr.org/2013/759.pdf>

use crate::{CONSTANTS, IV_SIZE, KEY_SIZE};
use core::convert::TryInto;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[derive(Clone)]
pub(crate) struct Block {
    d0: __m256i,
    d1: __m256i,
    d2: __m256i,
    iv: [i32; 2],
    rounds: usize,
}

impl Block {
    /// Initialize block function with the given key size, IV, and number of rounds
    #[inline]
    pub(crate) fn new(key: &[u8; KEY_SIZE], iv: [u8; IV_SIZE], rounds: usize) -> Self {
        assert!(
            rounds == 8 || rounds == 12 || rounds == 20,
            "rounds must be 8, 12, or 20"
        );

        let (v0, v1, v2) = unsafe { key_setup(key) };
        let iv = [
            i32::from_le_bytes(iv[4..].try_into().unwrap()),
            i32::from_le_bytes(iv[..4].try_into().unwrap()),
        ];

        Self {
            d0: v0,
            d1: v1,
            d2: v2,
            iv,
            rounds,
        }
    }

    #[inline]
    pub(crate) fn generate(&self, counter: u64, output: &mut [u8]) {
        unsafe {
            rounds(
                self.rounds,
                self.d0,
                self.d1,
                self.d2,
                iv_setup(self.iv, counter),
                output,
            )
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(clippy::cast_ptr_alignment)] // loadu supports unaligned loads
unsafe fn key_setup(key: &[u8; KEY_SIZE]) -> (__m256i, __m256i, __m256i) {
    let v0 = _mm_loadu_si128(CONSTANTS.as_ptr() as *const __m128i);
    let v1 = _mm_loadu_si128(key.as_ptr().offset(0x00) as *const __m128i);
    let v2 = _mm_loadu_si128(key.as_ptr().offset(0x10) as *const __m128i);

    (
        _mm256_broadcastsi128_si256(v0),
        _mm256_broadcastsi128_si256(v1),
        _mm256_broadcastsi128_si256(v2),
    )
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn iv_setup(iv: [i32; 2], counter: u64) -> __m256i {
    let s3 = _mm_set_epi32(
        iv[0],
        iv[1],
        ((counter >> 32) & 0xffff_ffff) as i32,
        (counter & 0xffff_ffff) as i32,
    );

    _mm256_add_epi64(
        _mm256_broadcastsi128_si256(s3),
        _mm256_set_epi64x(0, 1, 0, 0),
    )
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rounds(
    nrounds: usize,
    d0: __m256i,
    d1: __m256i,
    d2: __m256i,
    d3: __m256i,
    output: &mut [u8],
) {
    let (mut v0, mut v1, mut v2, mut v3) = (d0, d1, d2, d3);

    for _ in 0..(nrounds / 2) {
        // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_16(d);
        v0 = _mm256_add_epi32(v0, v1);
        v3 = _mm256_xor_si256(v3, v0);
        v3 = _mm256_shuffle_epi8(
            v3,
            _mm256_set_epi8(
                13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10,
                5, 4, 7, 6, 1, 0, 3, 2,
            ),
        );

        // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_12(b);
        v2 = _mm256_add_epi32(v2, v3);
        v1 = _mm256_xor_si256(v1, v2);
        v1 = _mm256_xor_si256(_mm256_slli_epi32(v1, 12), _mm256_srli_epi32(v1, 20));

        // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_8(d);
        v0 = _mm256_add_epi32(v0, v1);
        v3 = _mm256_xor_si256(v3, v0);
        v3 = _mm256_shuffle_epi8(
            v3,
            _mm256_set_epi8(
                14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11,
                6, 5, 4, 7, 2, 1, 0, 3,
            ),
        );

        // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_7(b);
        v2 = _mm256_add_epi32(v2, v3);
        v1 = _mm256_xor_si256(v1, v2);
        v1 = _mm256_xor_si256(_mm256_slli_epi32(v1, 7), _mm256_srli_epi32(v1, 25));

        // b = ROR256_V1(b); c = ROR256_V2(c); d = ROR256_V3(d);
        v1 = _mm256_shuffle_epi32(v1, (3 << 4) | (2 << 2) | 1);
        v2 = _mm256_shuffle_epi32(v2, (1 << 6) | (3 << 2) | 2);
        v3 = _mm256_shuffle_epi32(v3, (2 << 6) | (1 << 4) | 3);

        // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_16(d);
        v0 = _mm256_add_epi32(v0, v1);
        v3 = _mm256_xor_si256(v3, v0);
        v3 = _mm256_shuffle_epi8(
            v3,
            _mm256_set_epi8(
                13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10,
                5, 4, 7, 6, 1, 0, 3, 2,
            ),
        );

        // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_12(b);
        v2 = _mm256_add_epi32(v2, v3);
        v1 = _mm256_xor_si256(v1, v2);
        v1 = _mm256_xor_si256(_mm256_slli_epi32(v1, 12), _mm256_srli_epi32(v1, 20));

        // a = ADD256_32(a,b); d = XOR256(d,a); d = ROL256_8(d);
        v0 = _mm256_add_epi32(v0, v1);
        v3 = _mm256_xor_si256(v3, v0);
        v3 = _mm256_shuffle_epi8(
            v3,
            _mm256_set_epi8(
                14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11,
                6, 5, 4, 7, 2, 1, 0, 3,
            ),
        );

        // c = ADD256_32(c,d); b = XOR256(b,c); b = ROL256_7(b);
        v2 = _mm256_add_epi32(v2, v3);
        v1 = _mm256_xor_si256(v1, v2);
        v1 = _mm256_xor_si256(_mm256_slli_epi32(v1, 7), _mm256_srli_epi32(v1, 25));

        // b = ROR256_V3(b); c = ROR256_V2(c); d = ROR256_V1(d);
        v1 = _mm256_shuffle_epi32(v1, (2 << 6) | (1 << 4) | 3);
        v2 = _mm256_shuffle_epi32(v2, (1 << 6) | (3 << 2) | 2);
        v3 = _mm256_shuffle_epi32(v3, (3 << 4) | (2 << 2) | 1);
    }

    store(
        _mm256_add_epi32(v0, d0),
        _mm256_add_epi32(v1, d1),
        _mm256_add_epi32(v2, d2),
        _mm256_add_epi32(v3, d3),
        output,
    )
}

#[inline]
#[target_feature(enable = "avx2")]
#[allow(clippy::cast_ptr_alignment)] // storeu supports unaligned stores
unsafe fn store(v0: __m256i, v1: __m256i, v2: __m256i, v3: __m256i, output: &mut [u8]) {
    _mm_storeu_si128(
        output.as_mut_ptr().offset(0x00) as *mut __m128i,
        _mm256_castsi256_si128(v0),
    );
    _mm_storeu_si128(
        output.as_mut_ptr().offset(0x10) as *mut __m128i,
        _mm256_castsi256_si128(v1),
    );
    _mm_storeu_si128(
        output.as_mut_ptr().offset(0x20) as *mut __m128i,
        _mm256_castsi256_si128(v2),
    );
    _mm_storeu_si128(
        output.as_mut_ptr().offset(0x30) as *mut __m128i,
        _mm256_castsi256_si128(v3),
    );
}