//! Portable implementation which does not rely on architecture-specific
//! intrinsics.

use crate::{Block, STATE_WORDS, SalsaCore, Unsigned};
use cipher::{
    BlockSizeUser, ParBlocksSizeUser, StreamCipherBackend, StreamCipherSeekCore,
    consts::{U1, U64},
};

use super::quarter_round;

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
        let res = run_rounds::<R>(&self.0.state);

        self.0.set_block_pos(self.0.get_block_pos() + 1);

        block.copy_from_slice(&res);
    }
}

impl<R: Unsigned> StreamCipherBackend for Backend<'_, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let res = run_rounds::<R>(&self.0.state);

        self.0.set_block_pos(self.0.get_block_pos() + 1);

        for i in 0..16 {
            block[i * 4..(i + 1) * 4]
                .copy_from_slice(&res[crate::DATA_LAYOUT_INVERSE[i]].to_le_bytes());
        }
    }
}

#[inline(always)]
fn run_rounds<R: Unsigned>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = *state;

    for _ in 0..R::USIZE {
        // column rounds
        quarter_round(0, 4, 8, 12, &mut res);
        quarter_round(5, 9, 13, 1, &mut res);
        quarter_round(10, 14, 2, 6, &mut res);
        quarter_round(15, 3, 7, 11, &mut res);

        // diagonal rounds
        quarter_round(0, 1, 2, 3, &mut res);
        quarter_round(5, 6, 7, 4, &mut res);
        quarter_round(10, 11, 8, 9, &mut res);
        quarter_round(15, 12, 13, 14, &mut res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}
