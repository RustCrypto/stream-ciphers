//! WebAssembly SIMD (`simd128`) implementation: four blocks at a time, each
//! as its four rows, as the NEON backend computes them. Selected when the
//! crate is compiled with the `simd128` target feature
//! (`-C target-feature=+simd128`), which every major WebAssembly engine
//! supports.

use crate::{Rounds, STATE_WORDS, Variant};
use core::{arch::wasm32::*, marker::PhantomData};

#[cfg(feature = "rng")]
use crate::ChaChaCore;

#[cfg(feature = "cipher")]
use crate::chacha::Block;

#[cfg(feature = "cipher")]
use cipher::{
    BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure,
    consts::{U4, U64},
};

struct Backend<R: Rounds, V: Variant> {
    state: [v128; 4],
    _pd: PhantomData<(R, V)>,
}

/// The counter row `row` advanced by `n` blocks: the 32-bit counter of the
/// IETF variant, or the 64-bit counter of the legacy one.
#[inline(always)]
fn add_counter<V: Variant>(row: v128, n: u32) -> v128 {
    match size_of::<V::Counter>() {
        4 => u32x4_add(row, u32x4(n, 0, 0, 0)),
        8 => u64x2_add(row, u64x2(u64::from(n), 0)),
        _ => unreachable!(),
    }
}

impl<R: Rounds, V: Variant> Backend<R, V> {
    #[inline(always)]
    fn new(state: &[u32; STATE_WORDS]) -> Self {
        let row = |i: usize| u32x4(state[i], state[i + 1], state[i + 2], state[i + 3]);
        Backend {
            state: [row(0), row(4), row(8), row(12)],
            _pd: PhantomData,
        }
    }

    /// Writes the counter back into `state`.
    #[inline(always)]
    fn store_counter(&self, state: &mut [u32; STATE_WORDS]) {
        state[12] = u32x4_extract_lane::<0>(self.state[3]);
        if size_of::<V::Counter>() == 8 {
            state[13] = u32x4_extract_lane::<1>(self.state[3]);
        }
    }

    /// The next four blocks' rows, after the rounds and the state's addition.
    #[inline(always)]
    fn four_blocks(&mut self) -> [[v128; 4]; 4] {
        let mut initial = [self.state; 4];
        for (n, block) in (1..).zip(initial.iter_mut().skip(1)) {
            block[3] = add_counter::<V>(self.state[3], n);
        }
        let mut blocks = initial;
        for _ in 0..R::COUNT {
            double_quarter_round(&mut blocks);
        }
        for (block, initial) in blocks.iter_mut().zip(&initial) {
            for (row, initial) in block.iter_mut().zip(initial) {
                *row = u32x4_add(*row, *initial);
            }
        }
        self.state[3] = add_counter::<V>(self.state[3], 4);
        blocks
    }
}

#[inline]
#[cfg(feature = "cipher")]
pub(crate) fn inner<R, F, V>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Rounds,
    F: StreamCipherClosure<BlockSize = U64>,
    V: Variant,
{
    let mut backend = Backend::<R, V>::new(state);
    f.call(&mut backend);
    backend.store_counter(state);
}

/// Sets up the backend and writes four blocks to `buffer`.
#[cfg(feature = "rng")]
#[inline]
pub(crate) fn rng_inner<R, V>(core: &mut ChaChaCore<R, V>, buffer: &mut [u32; 64])
where
    R: Rounds,
    V: Variant,
{
    let mut backend = Backend::<R, V>::new(&core.state);
    for (words, block) in buffer.chunks_exact_mut(16).zip(backend.four_blocks()) {
        for (words, row) in words.chunks_exact_mut(4).zip(block) {
            words[0] = u32x4_extract_lane::<0>(row);
            words[1] = u32x4_extract_lane::<1>(row);
            words[2] = u32x4_extract_lane::<2>(row);
            words[3] = u32x4_extract_lane::<3>(row);
        }
    }
    backend.store_counter(&mut core.state);
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> BlockSizeUser for Backend<R, V> {
    type BlockSize = U64;
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> ParBlocksSizeUser for Backend<R, V> {
    type ParBlocksSize = U4;
}

/// Writes a block's rows to `block`, little-endian as WebAssembly's lanes are.
#[cfg(feature = "cipher")]
#[inline(always)]
fn store(rows: &[v128; 4], block: &mut Block) {
    for (bytes, row) in block.chunks_exact_mut(16).zip(rows) {
        // SAFETY: `bytes` is 16 bytes, what a `v128` store writes; WebAssembly's
        // stores need no alignment.
        unsafe { v128_store(bytes.as_mut_ptr().cast::<v128>(), *row) };
    }
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> StreamCipherBackend for Backend<R, V> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
        let mut rows = [self.state];
        for _ in 0..R::COUNT {
            double_quarter_round(&mut rows);
        }
        for (row, initial) in rows[0].iter_mut().zip(&self.state) {
            *row = u32x4_add(*row, *initial);
        }
        store(&rows[0], block);
        self.state[3] = add_counter::<V>(self.state[3], 1);
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, dest: &mut ParBlocks<Self>) {
        for (rows, block) in self.four_blocks().iter().zip(dest.iter_mut()) {
            store(rows, block);
        }
    }
}

/// `v`'s lanes rotated left by `N` bits each: 16 and 8 as byte shuffles, the
/// others as two shifts.
#[inline(always)]
fn rotate_left<const N: u32>(v: v128) -> v128 {
    match N {
        16 => i8x16_shuffle::<2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13>(v, v),
        8 => i8x16_shuffle::<3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14>(v, v),
        _ => v128_or(u32x4_shl(v, N), u32x4_shr(v, 32 - N)),
    }
}

#[inline(always)]
fn double_quarter_round<const N: usize>(blocks: &mut [[v128; 4]; N]) {
    add_xor_rot(blocks);
    rows_to_cols(blocks);
    add_xor_rot(blocks);
    cols_to_rows(blocks);
}

#[inline(always)]
fn add_xor_rot<const N: usize>(blocks: &mut [[v128; 4]; N]) {
    for [a, b, c, d] in blocks.iter_mut() {
        *a = u32x4_add(*a, *b);
        *d = rotate_left::<16>(v128_xor(*d, *a));
        *c = u32x4_add(*c, *d);
        *b = rotate_left::<12>(v128_xor(*b, *c));
        *a = u32x4_add(*a, *b);
        *d = rotate_left::<8>(v128_xor(*d, *a));
        *c = u32x4_add(*c, *d);
        *b = rotate_left::<7>(v128_xor(*b, *c));
    }
}

/// The diagonals as columns: rows 1, 2 and 3 rotated by 1, 2 and 3 lanes.
#[inline(always)]
fn rows_to_cols<const N: usize>(blocks: &mut [[v128; 4]; N]) {
    for [_, b, c, d] in blocks.iter_mut() {
        *b = i32x4_shuffle::<1, 2, 3, 0>(*b, *b);
        *c = i32x4_shuffle::<2, 3, 0, 1>(*c, *c);
        *d = i32x4_shuffle::<3, 0, 1, 2>(*d, *d);
    }
}

/// The columns back as rows.
#[inline(always)]
fn cols_to_rows<const N: usize>(blocks: &mut [[v128; 4]; N]) {
    for [_, b, c, d] in blocks.iter_mut() {
        *b = i32x4_shuffle::<3, 0, 1, 2>(*b, *b);
        *c = i32x4_shuffle::<2, 3, 0, 1>(*c, *c);
        *d = i32x4_shuffle::<1, 2, 3, 0>(*d, *d);
    }
}
