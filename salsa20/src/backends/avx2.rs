#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::cast_possible_wrap)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::{STATE_WORDS, Unsigned};
use cipher::{
    BlockSizeUser, ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure,
    consts::{U4, U64},
};
use core::marker::PhantomData;

/// Number of blocks processed in parallel.
const PAR_BLOCKS: usize = 4;
/// Number of `__m256i` sets (each holds 2 blocks).
const N: usize = PAR_BLOCKS / 2;

/// Diagonal indices for the Salsa20 state matrix.
const IDX: [[usize; 4]; 4] = [[0, 5, 10, 15], [4, 9, 14, 3], [8, 13, 2, 7], [12, 1, 6, 11]];

macro_rules! rotl_epi32 {
    ($v:expr, $n:literal) => {{
        let v = $v;
        _mm256_or_si256(_mm256_slli_epi32(v, $n), _mm256_srli_epi32(v, 32 - $n))
    }};
}

#[inline]
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn inner<R, F>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Unsigned,
    F: StreamCipherClosure<BlockSize = U64>,
{
    f.call(&mut Backend::<R> {
        state,
        _pd: PhantomData,
    });
}

struct Backend<'a, R: Unsigned> {
    state: &'a mut [u32; STATE_WORDS],
    _pd: PhantomData<R>,
}

impl<R: Unsigned> BlockSizeUser for Backend<'_, R> {
    type BlockSize = U64;
}

impl<R: Unsigned> ParBlocksSizeUser for Backend<'_, R> {
    type ParBlocksSize = U4;
}

impl<R: Unsigned> StreamCipherBackend for Backend<'_, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        unsafe {
            let res = rounds::<R>(self.state);
            let lo = extract_lo(&res[0]);
            store_block(&lo, block);
            let counter = get_counter(self.state);
            set_counter(self.state, counter + 1);
        }
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut cipher::ParBlocks<Self>) {
        unsafe {
            let res = rounds::<R>(self.state);
            for i in 0..N {
                let lo = extract_lo(&res[i]);
                let hi = extract_hi(&res[i]);
                store_block(&lo, &mut blocks[2 * i]);
                store_block(&hi, &mut blocks[2 * i + 1]);
            }
            let counter = get_counter(self.state);
            set_counter(self.state, counter + PAR_BLOCKS as u64);
        }
    }
}

/// Load two blocks' diagonal values into `__m256i` registers.
///
/// Each `__m256i` holds two blocks: the lower 128 bits contain block 0's
/// diagonal and the upper 128 bits contain block 1's diagonal.
#[inline(always)]
unsafe fn load_diag_pair(state: &[u32; STATE_WORDS], ctr0: u64, ctr1: u64) -> [__m256i; 4] {
    let s = state;
    [
        // a: [s0, s5, s10, s15] (same for both blocks)
        _mm256_set_epi32(
            s[15] as i32,
            s[10] as i32,
            s[5] as i32,
            s[0] as i32,
            s[15] as i32,
            s[10] as i32,
            s[5] as i32,
            s[0] as i32,
        ),
        // b: [s4, ctr_hi, s14, s3] (ctr_hi differs)
        _mm256_set_epi32(
            s[3] as i32,
            s[14] as i32,
            (ctr1 >> 32) as i32,
            s[4] as i32,
            s[3] as i32,
            s[14] as i32,
            (ctr0 >> 32) as i32,
            s[4] as i32,
        ),
        // c: [ctr_lo, s13, s2, s7] (ctr_lo differs)
        _mm256_set_epi32(
            s[7] as i32,
            s[2] as i32,
            s[13] as i32,
            ctr1 as i32,
            s[7] as i32,
            s[2] as i32,
            s[13] as i32,
            ctr0 as i32,
        ),
        // d: [s12, s1, s6, s11] (same for both blocks)
        _mm256_set_epi32(
            s[11] as i32,
            s[6] as i32,
            s[1] as i32,
            s[12] as i32,
            s[11] as i32,
            s[6] as i32,
            s[1] as i32,
            s[12] as i32,
        ),
    ]
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rounds<R: Unsigned>(state: &[u32; STATE_WORDS]) -> [[__m256i; 4]; N] {
    let counter = get_counter(state);
    let mut res = [[_mm256_setzero_si256(); 4]; N];
    for (i, block) in res.iter_mut().enumerate() {
        let base = counter + (i * 2) as u64;
        *block = load_diag_pair(state, base, base + 1);
    }
    let initial = res;

    for _ in 0..R::USIZE * 2 {
        for block in res.iter_mut() {
            quarter_round(block);
            shuffle(block);
        }
    }

    for i in 0..N {
        for j in 0..4 {
            res[i][j] = _mm256_add_epi32(res[i][j], initial[i][j]);
        }
    }

    res
}

#[inline(always)]
unsafe fn quarter_round(block: &mut [__m256i; 4]) {
    let [a, b, c, d] = block;
    *b = _mm256_xor_si256(*b, rotl_epi32!(_mm256_add_epi32(*a, *d), 7));
    *c = _mm256_xor_si256(*c, rotl_epi32!(_mm256_add_epi32(*b, *a), 9));
    *d = _mm256_xor_si256(*d, rotl_epi32!(_mm256_add_epi32(*c, *b), 13));
    *a = _mm256_xor_si256(*a, rotl_epi32!(_mm256_add_epi32(*d, *c), 18));
}

#[inline(always)]
unsafe fn shuffle(block: &mut [__m256i; 4]) {
    let [_, b, c, d] = block;
    let tmp = *b;
    *b = _mm256_shuffle_epi32(*d, 0b_00_11_10_01);
    *c = _mm256_shuffle_epi32(*c, 0b_01_00_11_10);
    *d = _mm256_shuffle_epi32(tmp, 0b_10_01_00_11);
}

#[inline(always)]
unsafe fn extract_lo(set: &[__m256i; 4]) -> [__m128i; 4] {
    [
        _mm256_castsi256_si128(set[0]),
        _mm256_castsi256_si128(set[1]),
        _mm256_castsi256_si128(set[2]),
        _mm256_castsi256_si128(set[3]),
    ]
}

#[inline(always)]
unsafe fn extract_hi(set: &[__m256i; 4]) -> [__m128i; 4] {
    [
        _mm256_extracti128_si256(set[0], 1),
        _mm256_extracti128_si256(set[1], 1),
        _mm256_extracti128_si256(set[2], 1),
        _mm256_extracti128_si256(set[3], 1),
    ]
}

/// Convert diagonal SIMD layout back to sequential little-endian bytes.
#[inline(always)]
unsafe fn store_block(diag: &[__m128i; 4], block: &mut [u8]) {
    let mut vals = [[0u32; 4]; 4];
    for (i, v) in diag.iter().enumerate() {
        _mm_storeu_si128(vals[i].as_mut_ptr().cast(), *v);
    }
    for (reg, idxs) in vals.iter().zip(IDX.iter()) {
        for (&val, &idx) in reg.iter().zip(idxs.iter()) {
            block[idx * 4..idx * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
}

#[inline(always)]
fn get_counter(state: &[u32; STATE_WORDS]) -> u64 {
    (state[8] as u64) | ((state[9] as u64) << 32)
}

#[inline(always)]
fn set_counter(state: &mut [u32; STATE_WORDS], pos: u64) {
    state[8] = pos as u32;
    state[9] = (pos >> 32) as u32;
}
