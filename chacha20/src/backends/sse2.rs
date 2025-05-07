#![allow(unsafe_op_in_unsafe_fn)]
use crate::{Rounds,Variant};

#[cfg(feature = "rng")]
use crate::{ChaChaCore};

#[cfg(feature = "cipher")]
use crate::{chacha::Block, STATE_WORDS};
#[cfg(feature = "cipher")]
use cipher::{
    consts::{U4, U64},
    BlockSizeUser, ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure,
};
use core::marker::PhantomData;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const PAR_BLOCKS: usize = 4;

#[inline]
#[target_feature(enable = "sse2")]
#[cfg(feature = "cipher")]
pub(crate) unsafe fn inner<R, V, F>(counter: &mut u64, state: &mut [u32; STATE_WORDS], f: F)
where
    R: Rounds,
    V: Variant,
    F: StreamCipherClosure<BlockSize = U64>,
{
    let state_ptr = state.as_ptr() as *const __m128i;
    let mut backend = Backend::<R,V> {
        v: [
            _mm_loadu_si128(state_ptr.add(0)),
            _mm_loadu_si128(state_ptr.add(1)),
            _mm_loadu_si128(state_ptr.add(2)),
            _mm_loadu_si128(state_ptr.add(3)),
        ],
        counter: *counter,
        _pd: PhantomData,
    };

    f.call(&mut backend);

    *counter = backend.counter;

    if V::COUNTER_SIZE == 1 {
        state[12] = _mm_cvtsi128_si32(backend.v[3]) as u32;
    } else {
        let ctr = _mm_cvtsi128_si64(backend.v[3]) as u64;

        state[12] = (ctr&(u32::MAX as u64)) as u32;
        state[13] = (ctr>>32) as u32;
    }

}

struct Backend<R: Rounds, V: Variant> {
    v: [__m128i; 4],
    counter: u64,
    _pd: PhantomData<(R,V)>,
}

#[cfg(feature = "cipher")]
impl<R: Rounds,V: Variant> BlockSizeUser for Backend<R,V> {
    type BlockSize = U64;
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> ParBlocksSizeUser for Backend<R, V> {
    type ParBlocksSize = U4;
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> StreamCipherBackend for Backend<R, V> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
        self.counter = self.counter.saturating_add(1);
        unsafe {
            let res = rounds::<R,V>(&self.v);
            if V::COUNTER_SIZE == 1 {
                let mask = _mm_add_epi32(
                    _mm_and_si128(
                        _mm_cmpeq_epi32(self.v[3], _mm_set_epi32(0,0,0,-1)),
                        _mm_set_epi32(0,0,0,-1)),
                    _mm_set_epi32(0,0,0,1));
                self.v[3] = _mm_add_epi32(self.v[3], _mm_and_si128(mask, _mm_set_epi32(0, 0, 0, 1)));
            } else {
                let mask = _mm_add_epi64(
                    _mm_and_si128(
                        _mm_cmpeq_epi64(self.v[3], _mm_set_epi64x(0,-1)),
                        _mm_set_epi64x(0,-1)),
                    _mm_set_epi64x(0,1));
                self.v[3] = _mm_add_epi64(self.v[3], _mm_and_si128(mask, _mm_set_epi64x(0, 1)));
            }

            let block_ptr = block.as_mut_ptr() as *mut __m128i;
            for i in 0..4 {
                _mm_storeu_si128(block_ptr.add(i), res[0][i]);
            }
        }
    }
    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut cipher::ParBlocks<Self>) {
        if V::COUNTER_SIZE == 1 {
            self.counter = core::cmp::min(V::MAX_USABLE_COUNTER+1,
                self.counter.saturating_add(PAR_BLOCKS as u64));
        } else {
            self.counter = self.counter.saturating_add(PAR_BLOCKS as u64);
        }
        unsafe {
            let res = rounds::<R,V>(&self.v);
            if V::COUNTER_SIZE == 1 {

                let new_v3 = _mm_add_epi32(self.v[3], _mm_set_epi32(0, 0, 0, PAR_BLOCKS as i32));
                let shifted = _mm_add_epi32(self.v[3], _mm_set_epi32(0,0,0,i32::MIN));
                let new_shifted = _mm_add_epi32(new_v3, _mm_set_epi32(0,0,0,i32::MIN));
                let mask = _mm_cmpgt_epi32(shifted,new_shifted);
                let max_val = _mm_and_si128(mask,_mm_set_epi32(0,0,0,-1));
                let new_val = _mm_andnot_si128(mask,new_v3);
                self.v[3] = _mm_or_si128(max_val,new_val);

            } else {
                let new_v3 = _mm_add_epi64(self.v[3], _mm_set_epi64x(0, PAR_BLOCKS as i64));

                let shifted = _mm_add_epi64(self.v[3], _mm_set_epi64x(0,i64::MIN));
                let new_shifted = _mm_add_epi64(new_v3, _mm_set_epi64x(0,i64::MIN));
                let mask = _mm_cmpgt_epi64(shifted,new_shifted);
                let max_val = _mm_and_si128(mask,_mm_set_epi64x(0,-1));
                let new_val = _mm_andnot_si128(mask,new_v3);
                self.v[3] = _mm_or_si128(max_val,new_val);
            }

            let blocks_ptr = blocks.as_mut_ptr() as *mut __m128i;
            for block in 0..PAR_BLOCKS {
                for i in 0..4 {
                    _mm_storeu_si128(blocks_ptr.add(i + block * PAR_BLOCKS), res[block][i]);
                }
            }
        }
    }
}

#[inline]
#[target_feature(enable = "sse2")]
#[cfg(feature = "rng")]
pub(crate) unsafe fn rng_inner<R, V>(core: &mut ChaChaCore<R, V>, buffer: &mut [u32; 64])
where
    R: Rounds,
    V: Variant,
{
    let state_ptr = core.state.as_ptr() as *const __m128i;
    let mut backend = Backend::<R,V> {
        v: [
            _mm_loadu_si128(state_ptr.add(0)),
            _mm_loadu_si128(state_ptr.add(1)),
            _mm_loadu_si128(state_ptr.add(2)),
            _mm_loadu_si128(state_ptr.add(3)),
        ],
        counter: core.counter,
        _pd: PhantomData,
    };

    backend.gen_ks_blocks(buffer);

    core.counter = backend.counter;
    if V::COUNTER_SIZE == 1 {
        core.state[12] = _mm_cvtsi128_si32(backend.v[3]) as u32;
    } else {
        let ctr = _mm_cvtsi128_si64(backend.v[3]) as u64;

        core.state[12] = (ctr&(u32::MAX as u64)) as u32;
        core.state[13] = (ctr>>32) as u32;
    }
}

#[cfg(feature = "rng")]
impl<R: Rounds, V: Variant> Backend<R, V> {
    #[inline(always)]
    fn gen_ks_blocks(&mut self, block: &mut [u32]) {
        if V::COUNTER_SIZE == 1 {
            self.counter = V::MAX_USABLE_COUNTER &
                self.counter.saturating_add(PAR_BLOCKS as u64);
        } else {
            self.counter = self.counter.saturating_add(PAR_BLOCKS as u64);
        }

        unsafe {
            let res = rounds::<R,V>(&self.v);
            if V::COUNTER_SIZE == 1 {

                self.v[3] = _mm_add_epi32(self.v[3], _mm_set_epi32(0, 0, 0, PAR_BLOCKS as i32));

            } else {
                self.v[3] = _mm_add_epi64(self.v[3], _mm_set_epi64x(0, PAR_BLOCKS as i64));
            }

            let blocks_ptr = block.as_mut_ptr() as *mut __m128i;
            for block in 0..PAR_BLOCKS {
                for i in 0..4 {
                    _mm_storeu_si128(blocks_ptr.add(i + block * PAR_BLOCKS), res[block][i]);
                }
            }
        }
    }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rounds<R: Rounds, V: Variant>(v: &[__m128i; 4]) -> [[__m128i; 4]; PAR_BLOCKS] {
    let mut res = [*v; 4];
    for block in 1..PAR_BLOCKS {
        if V::COUNTER_SIZE == 1 {
            res[block][3] = _mm_add_epi32(res[block][3], _mm_set_epi32(0, 0, 0, block as i32));
        } else {
            res[block][3] = _mm_add_epi64(res[block][3], _mm_set_epi64x(0, block as i64));
        }

    }

    for _ in 0..R::COUNT {
        double_quarter_round(&mut res);
    }

    for block in 0..PAR_BLOCKS {
        for i in 0..4 {
            res[block][i] = _mm_add_epi32(res[block][i], v[i]);
        }
        // add the counter since `v` is lacking updated counter values
        if V::COUNTER_SIZE == 1 {
            res[block][3] = _mm_add_epi32(res[block][3], _mm_set_epi32(0, 0, 0, block as i32));
        } else {
            res[block][3] = _mm_add_epi64(res[block][3], _mm_set_epi64x(0, block as i64));
        }
    }

    res
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn double_quarter_round(v: &mut [[__m128i; 4]; PAR_BLOCKS]) {
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
#[target_feature(enable = "sse2")]
unsafe fn rows_to_cols(blocks: &mut [[__m128i; 4]; PAR_BLOCKS]) {
    for [a, _, c, d] in blocks.iter_mut() {
        // c >>>= 32; d >>>= 64; a >>>= 96;
        *c = _mm_shuffle_epi32(*c, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        *a = _mm_shuffle_epi32(*a, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
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
#[target_feature(enable = "sse2")]
unsafe fn cols_to_rows(blocks: &mut [[__m128i; 4]; PAR_BLOCKS]) {
    for [a, _, c, d] in blocks.iter_mut() {
        // c <<<= 32; d <<<= 64; a <<<= 96;
        *c = _mm_shuffle_epi32(*c, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        *a = _mm_shuffle_epi32(*a, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn add_xor_rot(blocks: &mut [[__m128i; 4]; PAR_BLOCKS]) {
    for [a, b, c, d] in blocks.iter_mut() {
        // a += b; d ^= a; d <<<= (16, 16, 16, 16);
        *a = _mm_add_epi32(*a, *b);
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_xor_si128(_mm_slli_epi32(*d, 16), _mm_srli_epi32(*d, 16));

        // c += d; b ^= c; b <<<= (12, 12, 12, 12);
        *c = _mm_add_epi32(*c, *d);
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_xor_si128(_mm_slli_epi32(*b, 12), _mm_srli_epi32(*b, 20));

        // a += b; d ^= a; d <<<= (8, 8, 8, 8);
        *a = _mm_add_epi32(*a, *b);
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_xor_si128(_mm_slli_epi32(*d, 8), _mm_srli_epi32(*d, 24));

        // c += d; b ^= c; b <<<= (7, 7, 7, 7);
        *c = _mm_add_epi32(*c, *d);
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_xor_si128(_mm_slli_epi32(*b, 7), _mm_srli_epi32(*b, 25));
    }
}
