#![allow(unsafe_op_in_unsafe_fn)]
use crate::{Rounds, Variant};
use core::marker::PhantomData;

#[cfg(feature = "rng")]
use crate::ChaChaCore;

#[cfg(feature = "cipher")]
use crate::{STATE_WORDS, chacha::Block};

#[cfg(feature = "cipher")]
use cipher::{
    BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure,
    consts::{U16, U64},
};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Maximum number of blocks processed in parallel.
/// We also support 8 and 4 in gen_tail_blocks.
const MAX_PAR_BLOCKS: usize = 16;

/// Divisor to compute `N`, the number of __m512i needed
/// to represent a number of parallel blocks.
const BLOCKS_PER_VECTOR: usize = 4;

const MAX_N: usize = MAX_PAR_BLOCKS / BLOCKS_PER_VECTOR;

#[inline]
#[target_feature(enable = "avx512f")]
#[cfg(feature = "cipher")]
pub(crate) unsafe fn inner<R, F, V>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Rounds,
    F: StreamCipherClosure<BlockSize = U64>,
    V: Variant,
{
    let state_ptr = state.as_ptr() as *const __m128i;
    let v = [
        _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(0))),
        _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(1))),
        _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(2))),
    ];
    let mut c = _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(3)));
    c = match size_of::<V::Counter>() {
        4 => _mm512_add_epi32(
            c,
            _mm512_set_epi32(0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0),
        ),
        8 => _mm512_add_epi64(c, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0)),
        _ => unreachable!(),
    };
    let mut ctr = [c; MAX_N];
    for i in 0..MAX_N {
        ctr[i] = c;
        c = match size_of::<V::Counter>() {
            4 => _mm512_add_epi32(
                c,
                _mm512_set_epi32(0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4),
            ),
            8 => _mm512_add_epi64(c, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4)),
            _ => unreachable!(),
        };
    }
    let mut backend = Backend::<R, V> {
        v,
        ctr,
        _pd: PhantomData,
    };

    f.call(&mut backend);

    state[12] = _mm256_extract_epi32::<0>(_mm512_extracti32x8_epi32::<0>(backend.ctr[0])) as u32;
    match size_of::<V::Counter>() {
        4 => {}
        8 => {
            state[13] =
                _mm256_extract_epi32::<1>(_mm512_extracti32x8_epi32::<0>(backend.ctr[0])) as u32
        }
        _ => unreachable!(),
    }
}

#[inline]
#[target_feature(enable = "avx512f")]
#[cfg(feature = "rng")]
pub(crate) unsafe fn rng_inner<R, V>(core: &mut ChaChaCore<R, V>, buffer: &mut [u32; 64])
where
    R: Rounds,
    V: Variant,
{
    use core::slice;

    use crate::rng::BLOCK_WORDS;

    let state_ptr = core.state.as_ptr() as *const __m128i;
    let v = [
        _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(0))),
        _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(1))),
        _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(2))),
    ];
    let mut c = _mm512_broadcast_i32x4(_mm_loadu_si128(state_ptr.add(3)));
    c = _mm512_add_epi64(c, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0));
    let mut ctr = [c; MAX_N];
    for i in 0..MAX_N {
        ctr[i] = c;
        c = _mm512_add_epi64(c, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
    }
    let mut backend = Backend::<R, V> {
        v,
        ctr,
        _pd: PhantomData,
    };

    let buffer = slice::from_raw_parts_mut(
        buffer.as_mut_ptr().cast::<Block>(),
        buffer.len() / BLOCK_WORDS as usize,
    );
    backend.gen_par_ks_blocks_inner::<4, { 4 / BLOCKS_PER_VECTOR }>(buffer.try_into().unwrap());

    core.state[12] =
        _mm256_extract_epi32::<0>(_mm512_extracti32x8_epi32::<0>(backend.ctr[0])) as u32;
    core.state[13] =
        _mm256_extract_epi32::<1>(_mm512_extracti32x8_epi32::<0>(backend.ctr[0])) as u32;
}

struct Backend<R: Rounds, V: Variant> {
    v: [__m512i; 3],
    ctr: [__m512i; MAX_N],
    _pd: PhantomData<(R, V)>,
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> BlockSizeUser for Backend<R, V> {
    type BlockSize = U64;
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> ParBlocksSizeUser for Backend<R, V> {
    type ParBlocksSize = U16;
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> Backend<R, V> {
    fn gen_par_ks_blocks_inner<const PAR_BLOCKS: usize, const N: usize>(
        &mut self,
        blocks: &mut [cipher::Block<Self>; PAR_BLOCKS],
    ) {
        assert!(PAR_BLOCKS.is_multiple_of(BLOCKS_PER_VECTOR));

        unsafe {
            let vs = rounds::<N, R>(&self.v, &self.ctr[..N].try_into().unwrap());

            let pb = blocks.len() as i32;
            for c in self.ctr.iter_mut() {
                *c = match size_of::<V::Counter>() {
                    4 => _mm512_add_epi32(
                        *c,
                        _mm512_set_epi32(0, 0, 0, pb, 0, 0, 0, pb, 0, 0, 0, pb, 0, 0, 0, pb),
                    ),
                    8 => _mm512_add_epi64(
                        *c,
                        _mm512_set_epi64(0, pb as i64, 0, pb as i64, 0, pb as i64, 0, pb as i64),
                    ),
                    _ => unreachable!(),
                }
            }

            let mut block_ptr = blocks.as_mut_ptr() as *mut __m128i;
            for (vi, v) in vs.into_iter().enumerate() {
                let t: [__m128i; 16] = core::mem::transmute(v);
                for i in 0..BLOCKS_PER_VECTOR {
                    _mm_storeu_si128(block_ptr.add(i), t[4 * i]);
                    _mm_storeu_si128(block_ptr.add(4 + i), t[4 * i + 1]);
                    _mm_storeu_si128(block_ptr.add(8 + i), t[4 * i + 2]);
                    _mm_storeu_si128(block_ptr.add(12 + i), t[4 * i + 3]);
                }

                if vi == PAR_BLOCKS / BLOCKS_PER_VECTOR - 1 {
                    break;
                }

                block_ptr = block_ptr.add(16);
            }
        }
    }
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> StreamCipherBackend for Backend<R, V> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
        unsafe {
            let res = rounds::<1, R>(&self.v, self.ctr[..1].try_into().unwrap());
            for c in self.ctr.iter_mut() {
                *c = match size_of::<V::Counter>() {
                    4 => _mm512_add_epi32(
                        *c,
                        _mm512_set_epi32(0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1),
                    ),
                    8 => _mm512_add_epi64(*c, _mm512_set_epi64(0, 1, 0, 1, 0, 1, 0, 1)),
                    _ => unreachable!(),
                };
            }

            let block_ptr = block.as_mut_ptr() as *mut __m128i;

            for i in 0..4 {
                _mm_storeu_si128(block_ptr.add(i), _mm512_extracti32x4_epi32::<0>(res[0][i]));
            }
        }
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut ParBlocks<Self>) {
        self.gen_par_ks_blocks_inner::<MAX_PAR_BLOCKS, MAX_N>(
            blocks.as_mut_slice().try_into().unwrap(),
        );
    }

    #[inline(always)]
    fn gen_tail_blocks(&mut self, mut blocks: &mut [cipher::Block<Self>]) {
        while blocks.len() >= 8 {
            self.gen_par_ks_blocks_inner::<8, { 8 / BLOCKS_PER_VECTOR }>(
                (&mut blocks[..8]).try_into().unwrap(),
            );
            blocks = &mut blocks[8..];
        }

        while blocks.len() >= 4 {
            self.gen_par_ks_blocks_inner::<4, { 4 / BLOCKS_PER_VECTOR }>(
                (&mut blocks[..4]).try_into().unwrap(),
            );
            blocks = &mut blocks[4..];
        }

        for block in blocks {
            self.gen_ks_block(block);
        }
    }
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn rounds<const N: usize, R: Rounds>(
    v: &[__m512i; 3],
    c: &[__m512i; N],
) -> [[__m512i; 4]; N] {
    let mut vs: [[__m512i; 4]; N] = [[_mm512_setzero_si512(); 4]; N];
    for i in 0..N {
        vs[i] = [v[0], v[1], v[2], c[i]];
    }
    for _ in 0..R::COUNT {
        double_quarter_round(&mut vs);
    }

    for i in 0..N {
        for j in 0..3 {
            vs[i][j] = _mm512_add_epi32(vs[i][j], v[j]);
        }
        vs[i][3] = _mm512_add_epi32(vs[i][3], c[i]);
    }

    vs
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn double_quarter_round<const N: usize>(v: &mut [[__m512i; 4]; N]) {
    add_xor_rot(v);
    rows_to_cols(v);
    add_xor_rot(v);
    cols_to_rows(v);
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
#[target_feature(enable = "avx512f")]
unsafe fn rows_to_cols<const N: usize>(vs: &mut [[__m512i; 4]; N]) {
    // c >>>= 32; d >>>= 64; a >>>= 96;
    for [a, _, c, d] in vs {
        *c = _mm512_shuffle_epi32::<0b_00_11_10_01>(*c); // _MM_SHUFFLE(0, 3, 2, 1)
        *d = _mm512_shuffle_epi32::<0b_01_00_11_10>(*d); // _MM_SHUFFLE(1, 0, 3, 2)
        *a = _mm512_shuffle_epi32::<0b_10_01_00_11>(*a); // _MM_SHUFFLE(2, 1, 0, 3)
    }
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
#[target_feature(enable = "avx512f")]
unsafe fn cols_to_rows<const N: usize>(vs: &mut [[__m512i; 4]; N]) {
    // c <<<= 32; d <<<= 64; a <<<= 96;
    for [a, _, c, d] in vs {
        *c = _mm512_shuffle_epi32::<0b_10_01_00_11>(*c); // _MM_SHUFFLE(2, 1, 0, 3)
        *d = _mm512_shuffle_epi32::<0b_01_00_11_10>(*d); // _MM_SHUFFLE(1, 0, 3, 2)
        *a = _mm512_shuffle_epi32::<0b_00_11_10_01>(*a); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}

#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn add_xor_rot<const N: usize>(vs: &mut [[__m512i; 4]; N]) {
    // a += b; d ^= a; d <<<= (16, 16, 16, 16);
    for [a, b, _, d] in vs.iter_mut() {
        *a = _mm512_add_epi32(*a, *b);
        *d = _mm512_xor_si512(*d, *a);
        *d = _mm512_rol_epi32::<16>(*d);
    }

    // c += d; b ^= c; b <<<= (12, 12, 12, 12);
    for [_, b, c, d] in vs.iter_mut() {
        *c = _mm512_add_epi32(*c, *d);
        *b = _mm512_xor_si512(*b, *c);
        *b = _mm512_rol_epi32::<12>(*b);
    }

    // a += b; d ^= a; d <<<= (8, 8, 8, 8);
    for [a, b, _, d] in vs.iter_mut() {
        *a = _mm512_add_epi32(*a, *b);
        *d = _mm512_xor_si512(*d, *a);
        *d = _mm512_rol_epi32::<8>(*d);
    }

    // c += d; b ^= c; b <<<= (7, 7, 7, 7);
    for [_, b, c, d] in vs.iter_mut() {
        *c = _mm512_add_epi32(*c, *d);
        *b = _mm512_xor_si512(*b, *c);
        *b = _mm512_rol_epi32::<7>(*b);
    }
}
