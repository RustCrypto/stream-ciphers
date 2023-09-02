use crate::{Block, StreamClosure, Unsigned, STATE_WORDS};
use cipher::{
    consts::{U1, U64},
    BlockSizeUser, ParBlocksSizeUser, StreamBackend,
};
use core::marker::PhantomData;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn inner<R, F>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Unsigned,
    F: StreamClosure<BlockSize = U64>,
{
    let state_ptr = state.as_ptr() as *const __m128i;
    let mut backend = Backend::<R> {
        v: [
            _mm_loadu_si128(state_ptr.add(0)),
            _mm_loadu_si128(state_ptr.add(1)),
            _mm_loadu_si128(state_ptr.add(2)),
            _mm_loadu_si128(state_ptr.add(3)),
        ],
        _pd: PhantomData,
    };

    f.call(&mut backend);
    state[8] = _mm_cvtsi128_si32(backend.v[2]) as u32;
}

struct Backend<R: Unsigned> {
    v: [__m128i; 4],
    _pd: PhantomData<R>,
}

impl<'a, R: Unsigned> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
}

impl<'a, R: Unsigned> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U1;
}

impl<'a, R: Unsigned> StreamBackend for Backend<R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        unsafe {
            let res = rounds::<R>(&self.v);

            self.v[2] = _mm_add_epi32(self.v[2], _mm_set_epi32(0, 0, 0, 1));
            let block_ptr = block.as_mut_ptr() as *mut __m128i;

            for i in 0..4 {
                _mm_storeu_si128(block_ptr.add(i), res[i]);
            }
        }
    }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rounds<R: Unsigned>(v: &[__m128i; 4]) -> [__m128i; 4] {
    let mut res = *v;

    for _ in 0..R::USIZE {
        double_quarter_round(&mut res);
    }

    for i in 0..4 {
        res[i] = _mm_add_epi32(res[i], v[i]);
    }

    transpose(&mut res);

    res[1] = _mm_shuffle_epi32(res[1], 0b_10_01_00_11);
    res[2] = _mm_shuffle_epi32(res[2], 0b_01_00_11_10);
    res[3] = _mm_shuffle_epi32(res[3], 0b_00_11_10_01);

    transpose(&mut res);

    res
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn double_quarter_round(v: &mut [__m128i; 4]) {
    add_xor_rot(v);
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn transpose([a, b, c, d]: &mut [__m128i; 4]) {
    // attempt from https://randombit.net/bitbashing/posts/integer_matrix_transpose_in_sse2.html
    let t0 = _mm_unpacklo_epi32(*a, *b);
    let t1 = _mm_unpacklo_epi32(*c, *d);
    let t2 = _mm_unpackhi_epi32(*a, *b);
    let t3 = _mm_unpackhi_epi32(*c, *d);

    /* Assigning transposed values back into I[0-3] */
    *a = _mm_unpacklo_epi64(t0, t1);
    *b = _mm_unpackhi_epi64(t0, t1);
    *c = _mm_unpacklo_epi64(t2, t3);
    *d = _mm_unpackhi_epi64(t2, t3);
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn add_xor_rot([a, b, c, d]: &mut [__m128i; 4]) {
    let mut t_sum: __m128i;
    let mut t_rotl: __m128i;

    // Operate on "columns"
    t_sum = _mm_add_epi32(*a, *d);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 7), _mm_srli_epi32(t_sum, 25));
    *b = _mm_xor_si128(*b, t_rotl);

    t_sum = _mm_add_epi32(*b, *a);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 9), _mm_srli_epi32(t_sum, 23));
    *c = _mm_xor_si128(*c, t_rotl);

    t_sum = _mm_add_epi32(*c, *b);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 13), _mm_srli_epi32(t_sum, 19));
    *d = _mm_xor_si128(*d, t_rotl);

    t_sum = _mm_add_epi32(*d, *c);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 18), _mm_srli_epi32(t_sum, 14));
    *a = _mm_xor_si128(*a, t_rotl);

    // Rearrange data.
    *b = _mm_shuffle_epi32(*b, 0x93); // 10_01_00_11
    *c = _mm_shuffle_epi32(*c, 0x4E); // 01_00_11_10
    *d = _mm_shuffle_epi32(*d, 0x39); // 00_11_10_01

    // Operate on "rows".
    t_sum = _mm_add_epi32(*a, *b);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 7), _mm_srli_epi32(t_sum, 25));
    *d = _mm_xor_si128(*d, t_rotl);

    t_sum = _mm_add_epi32(*d, *a);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 9), _mm_srli_epi32(t_sum, 23));
    *c = _mm_xor_si128(*c, t_rotl);

    t_sum = _mm_add_epi32(*c, *d);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 13), _mm_srli_epi32(t_sum, 19));
    *b = _mm_xor_si128(*b, t_rotl);

    t_sum = _mm_add_epi32(*b, *c);
    t_rotl = _mm_xor_si128(_mm_slli_epi32(t_sum, 18), _mm_srli_epi32(t_sum, 14));
    *a = _mm_xor_si128(*a, t_rotl);

    // Rearrange data.
    *b = _mm_shuffle_epi32(*b, 0x39); // 00_11_10_01
    *c = _mm_shuffle_epi32(*c, 0x4E); // 01_00_11_10
    *d = _mm_shuffle_epi32(*d, 0x93); // 10_01_00_11
}
