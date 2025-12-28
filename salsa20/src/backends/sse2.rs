//! SSE2 backend for Salsa20.

use crate::{Block, STATE_WORDS, SalsaCore, Unsigned};
use cipher::{
    Array, BlockSizeUser, ParBlocksSizeUser, StreamCipherBackend, StreamCipherSeekCore,
    consts::{U1, U64},
};

pub(crate) struct Backend<'a, R: Unsigned>(pub(crate) &'a mut SalsaCore<R>);

impl<'a, R: Unsigned> From<&'a mut SalsaCore<R>> for Backend<'a, R> {
    fn from(core: &'a mut SalsaCore<R>) -> Self {
        Backend(core)
    }
}

impl<R: Unsigned> BlockSizeUser for Backend<'_, R> {
    type BlockSize = U64;
}

impl<R: Unsigned> ParBlocksSizeUser for Backend<'_, R> {
    type ParBlocksSize = U1;
}

impl<R: Unsigned> Backend<'_, R> {
    #[inline(always)]
    pub(crate) fn gen_ks_block_altn(&mut self, block: &mut [u32; STATE_WORDS]) {
        unsafe { run_rounds_sse2_ptr::<R>(block.as_mut_ptr().cast(), &self.0.state) };

        self.0.set_block_pos(self.0.get_block_pos() + 1);
    }
}

impl<R: Unsigned> StreamCipherBackend for Backend<'_, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let mut res = [0u32; STATE_WORDS];
        unsafe { run_rounds_sse2_ptr::<R>(res.as_mut_ptr().cast(), &self.0.state) };

        self.0.set_block_pos(self.0.get_block_pos() + 1);

        for i in 0..16 {
            block[i * 4..(i + 1) * 4]
                .copy_from_slice(&res[crate::DATA_LAYOUT_INVERSE[i]].to_le_bytes());
        }
    }
}

#[inline(always)]
/// Run the Salsa20 rounds using SSE2 instructions.
///
/// Input: state in internal order
/// Output: out in internal order, does not have to be aligned on any boundary
unsafe fn run_rounds_sse2_ptr<R: Unsigned>(out: *mut Array<u8, U64>, state: &[u32; STATE_WORDS]) {
    use core::arch::x86_64::*;
    unsafe {
        let [a_save, b_save, d_save, c_save] = [
            _mm_loadu_si128(state.as_ptr().add(0).cast()),
            _mm_loadu_si128(state.as_ptr().add(4).cast()),
            _mm_loadu_si128(state.as_ptr().add(8).cast()),
            _mm_loadu_si128(state.as_ptr().add(12).cast()),
        ];
        let [mut a, mut b, mut c, mut d] = [a_save, b_save, c_save, d_save];

        macro_rules! mm_rol_epi32x {
            ($w:expr, $amt:literal) => {{
                let w = $w;
                _mm_xor_si128(_mm_slli_epi32(w, $amt), _mm_srli_epi32(w, 32 - $amt))
            }};
        }

        macro_rules! quarter_xmmwords {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                $b = _mm_xor_si128($b, mm_rol_epi32x!(_mm_add_epi32($a, $d), 7));
                $c = _mm_xor_si128($c, mm_rol_epi32x!(_mm_add_epi32($b, $a), 9));
                $d = _mm_xor_si128($d, mm_rol_epi32x!(_mm_add_epi32($c, $b), 13));
                $a = _mm_xor_si128($a, mm_rol_epi32x!(_mm_add_epi32($d, $c), 18));
            };
        }

        for _ in 0..R::USIZE {
            quarter_xmmwords!(a, b, c, d);

            // a stays in place
            // b = left shuffle d by 1 element
            d = _mm_shuffle_epi32(d, 0b00_11_10_01);
            // c = left shuffle c by 2 elements
            c = _mm_shuffle_epi32(c, 0b01_00_11_10);
            // d = left shuffle b by 3 elements
            b = _mm_shuffle_epi32(b, 0b10_01_00_11);

            (b, d) = (d, b);

            quarter_xmmwords!(a, b, c, d);

            // a stays in place
            // b = left shuffle d by 1 element
            d = _mm_shuffle_epi32(d, 0b00_11_10_01);
            // c = left shuffle c by 2 elements
            c = _mm_shuffle_epi32(c, 0b01_00_11_10);
            // d = left shuffle b by 3 elements
            b = _mm_shuffle_epi32(b, 0b10_01_00_11);

            (b, d) = (d, b);
        }

        _mm_storeu_si128(out.byte_add(0).cast(), _mm_add_epi32(a, a_save));
        _mm_storeu_si128(out.byte_add(16).cast(), _mm_add_epi32(b, b_save));
        _mm_storeu_si128(out.byte_add(32).cast(), _mm_add_epi32(d, d_save));
        _mm_storeu_si128(out.byte_add(48).cast(), _mm_add_epi32(c, c_save));
    }
}
