//! WebAssembly SIMD (`simd128`) implementation: four blocks at a time, each
//! vector holding one state word of the four blocks, so that the rounds need
//! no lane rotations and the blocks are transposed into rows once at the end;
//! a single block as its four rows, as the NEON backend computes them.
//! Selected when the crate is compiled with the `simd128` target feature
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

/// Lane `N` of `v` in every lane.
#[inline(always)]
fn splat_lane<const N: usize>(v: v128) -> v128 {
    i32x4_shuffle::<N, N, N, N>(v, v)
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

    /// Advances the counter by one block: the 32-bit counter of the IETF
    /// variant, or the 64-bit counter of the legacy one.
    #[inline(always)]
    fn increment_counter(&mut self) {
        self.state[3] = match size_of::<V::Counter>() {
            4 => u32x4_add(self.state[3], u32x4(1, 0, 0, 0)),
            8 => u64x2_add(self.state[3], u64x2(1, 0)),
            _ => unreachable!(),
        };
    }

    /// The state's words, each across the next four blocks: the counter's
    /// lanes are the blocks' counters.
    #[inline(always)]
    fn words(&self) -> [v128; 16] {
        let [a, b, c, d] = self.state;
        let counter = splat_lane::<0>(d);
        let low = u32x4_add(counter, u32x4(0, 1, 2, 3));
        let mut high = splat_lane::<1>(d);
        if size_of::<V::Counter>() == 8 {
            // The lanes that wrapped carry into the high word: their mask is -1.
            high = u32x4_sub(high, u32x4_lt(low, counter));
        }
        [
            splat_lane::<0>(a),
            splat_lane::<1>(a),
            splat_lane::<2>(a),
            splat_lane::<3>(a),
            splat_lane::<0>(b),
            splat_lane::<1>(b),
            splat_lane::<2>(b),
            splat_lane::<3>(b),
            splat_lane::<0>(c),
            splat_lane::<1>(c),
            splat_lane::<2>(c),
            splat_lane::<3>(c),
            low,
            high,
            splat_lane::<2>(d),
            splat_lane::<3>(d),
        ]
    }

    /// The next four blocks' rows, after the rounds and the state's addition.
    #[inline(always)]
    fn four_blocks(&mut self) -> [[v128; 4]; 4] {
        let mut words = self.words();
        for _ in 0..R::COUNT {
            double_round(&mut words);
        }
        let mut blocks = transpose(&words);
        for block in &mut blocks {
            for i in 0..4 {
                block[i] = u32x4_add(block[i], self.state[i]);
            }
            self.increment_counter();
        }
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
        let mut rows = self.state;
        for _ in 0..R::COUNT {
            double_quarter_round(&mut rows);
        }
        for (row, initial) in rows.iter_mut().zip(&self.state) {
            *row = u32x4_add(*row, *initial);
        }
        store(&rows, block);
        self.increment_counter();
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

/// A quarter round of `a`, `b`, `c` and `d`: four columns at once when they
/// are one block's rows, four blocks at once when they are one word each.
#[inline(always)]
fn quarter_round(a: &mut v128, b: &mut v128, c: &mut v128, d: &mut v128) {
    *a = u32x4_add(*a, *b);
    *d = rotate_left::<16>(v128_xor(*d, *a));
    *c = u32x4_add(*c, *d);
    *b = rotate_left::<12>(v128_xor(*b, *c));
    *a = u32x4_add(*a, *b);
    *d = rotate_left::<8>(v128_xor(*d, *a));
    *c = u32x4_add(*c, *d);
    *b = rotate_left::<7>(v128_xor(*b, *c));
}

/// A quarter round of words `A`, `B`, `C` and `D` of four blocks held as words.
#[inline(always)]
fn quarter_round_of<const A: usize, const B: usize, const C: usize, const D: usize>(
    x: &mut [v128; 16],
) {
    let (mut a, mut b, mut c, mut d) = (x[A], x[B], x[C], x[D]);
    quarter_round(&mut a, &mut b, &mut c, &mut d);
    (x[A], x[B], x[C], x[D]) = (a, b, c, d);
}

/// A double round of four blocks held as words: the column round, then the
/// diagonal round.
#[inline(always)]
fn double_round(x: &mut [v128; 16]) {
    quarter_round_of::<0, 4, 8, 12>(x);
    quarter_round_of::<1, 5, 9, 13>(x);
    quarter_round_of::<2, 6, 10, 14>(x);
    quarter_round_of::<3, 7, 11, 15>(x);
    quarter_round_of::<0, 5, 10, 15>(x);
    quarter_round_of::<1, 6, 11, 12>(x);
    quarter_round_of::<2, 7, 8, 13>(x);
    quarter_round_of::<3, 4, 9, 14>(x);
}

/// The four blocks' rows from their words.
#[inline(always)]
fn transpose(words: &[v128; 16]) -> [[v128; 4]; 4] {
    let mut blocks = [[words[0]; 4]; 4];
    for (r, group) in words.chunks_exact(4).enumerate() {
        let [a, b, c, d] = [group[0], group[1], group[2], group[3]];
        let ab_low = i32x4_shuffle::<0, 4, 1, 5>(a, b);
        let ab_high = i32x4_shuffle::<2, 6, 3, 7>(a, b);
        let cd_low = i32x4_shuffle::<0, 4, 1, 5>(c, d);
        let cd_high = i32x4_shuffle::<2, 6, 3, 7>(c, d);
        blocks[0][r] = i64x2_shuffle::<0, 2>(ab_low, cd_low);
        blocks[1][r] = i64x2_shuffle::<1, 3>(ab_low, cd_low);
        blocks[2][r] = i64x2_shuffle::<0, 2>(ab_high, cd_high);
        blocks[3][r] = i64x2_shuffle::<1, 3>(ab_high, cd_high);
    }
    blocks
}

/// A double round of one block held as its rows: the column round, the
/// diagonals brought into columns, the diagonal round, the rows restored.
#[cfg(feature = "cipher")]
#[inline(always)]
fn double_quarter_round(rows: &mut [v128; 4]) {
    let [a, b, c, d] = rows;
    quarter_round(a, b, c, d);
    *b = i32x4_shuffle::<1, 2, 3, 0>(*b, *b);
    *c = i32x4_shuffle::<2, 3, 0, 1>(*c, *c);
    *d = i32x4_shuffle::<3, 0, 1, 2>(*d, *d);
    quarter_round(a, b, c, d);
    *b = i32x4_shuffle::<3, 0, 1, 2>(*b, *b);
    *c = i32x4_shuffle::<2, 3, 0, 1>(*c, *c);
    *d = i32x4_shuffle::<1, 2, 3, 0>(*d, *d);
}
