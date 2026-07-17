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

const PAR_BLOCKS: usize = 4;

/// Diagonal indices for the Salsa20 state matrix.
///
/// The 4x4 state is packed into 4 SSE registers so that each register
/// holds one diagonal. All four column quarter-rounds then execute
/// as a single SIMD operation, and shuffles rotate between
/// column and row round alignment.
const IDX: [[usize; 4]; 4] = [[0, 5, 10, 15], [4, 9, 14, 3], [8, 13, 2, 7], [12, 1, 6, 11]];

macro_rules! rotl_epi32 {
    ($v:expr, $n:literal) => {{
        let v = $v;
        _mm_or_si128(_mm_slli_epi32(v, $n), _mm_srli_epi32(v, 32 - $n))
    }};
}

#[inline]
#[target_feature(enable = "sse2")]
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
            store_block(&res[0], block);
            let counter = get_counter(self.state);
            set_counter(self.state, counter + 1);
        }
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut cipher::ParBlocks<Self>) {
        unsafe {
            let res = rounds::<R>(self.state);
            for i in 0..PAR_BLOCKS {
                store_block(&res[i], &mut blocks[i]);
            }
            let counter = get_counter(self.state);
            set_counter(self.state, counter + PAR_BLOCKS as u64);
        }
    }
}

#[inline(always)]
unsafe fn load_diag(state: &[u32; STATE_WORDS]) -> [__m128i; 4] {
    let s = |i: usize| state[i] as i32;
    [
        _mm_set_epi32(s(IDX[0][3]), s(IDX[0][2]), s(IDX[0][1]), s(IDX[0][0])),
        _mm_set_epi32(s(IDX[1][3]), s(IDX[1][2]), s(IDX[1][1]), s(IDX[1][0])),
        _mm_set_epi32(s(IDX[2][3]), s(IDX[2][2]), s(IDX[2][1]), s(IDX[2][0])),
        _mm_set_epi32(s(IDX[3][3]), s(IDX[3][2]), s(IDX[3][1]), s(IDX[3][0])),
    ]
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rounds<R: Unsigned>(state: &[u32; STATE_WORDS]) -> [[__m128i; 4]; PAR_BLOCKS] {
    let counter = get_counter(state);
    let mut tmp = *state;
    let mut res = [[_mm_setzero_si128(); 4]; PAR_BLOCKS];
    for (i, block) in res.iter_mut().enumerate() {
        let ctr = counter + i as u64;
        tmp[8] = ctr as u32;
        tmp[9] = (ctr >> 32) as u32;
        *block = load_diag(&tmp);
    }
    let initial = res;

    for _ in 0..R::USIZE * 2 {
        for block in res.iter_mut() {
            quarter_round(block);
            shuffle(block);
        }
    }

    for i in 0..PAR_BLOCKS {
        for j in 0..4 {
            res[i][j] = _mm_add_epi32(res[i][j], initial[i][j]);
        }
    }

    res
}

#[inline(always)]
unsafe fn quarter_round(block: &mut [__m128i; 4]) {
    let [a, b, c, d] = block;
    *b = _mm_xor_si128(*b, rotl_epi32!(_mm_add_epi32(*a, *d), 7));
    *c = _mm_xor_si128(*c, rotl_epi32!(_mm_add_epi32(*b, *a), 9));
    *d = _mm_xor_si128(*d, rotl_epi32!(_mm_add_epi32(*c, *b), 13));
    *a = _mm_xor_si128(*a, rotl_epi32!(_mm_add_epi32(*d, *c), 18));
}

/// Rotate diagonal alignment between column and row rounds.
///
/// The same shuffle+swap sequence converts column layout to row layout
/// and vice versa, so it is applied identically after every quarter round.
#[inline(always)]
unsafe fn shuffle(block: &mut [__m128i; 4]) {
    let [_, b, c, d] = block;
    let tmp = *b;
    *b = _mm_shuffle_epi32(*d, 0b_00_11_10_01);
    *c = _mm_shuffle_epi32(*c, 0b_01_00_11_10);
    *d = _mm_shuffle_epi32(tmp, 0b_10_01_00_11);
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
