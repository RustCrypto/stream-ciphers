//! ChaCha20 cipher core implementation

use salsa20_core::{SalsaFamilyCipher, SalsaFamilyState};
use stream_cipher::{LoopError, SyncStreamCipher, SyncStreamCipherSeek};

/// ChaCha20 core cipher functionality
#[derive(Debug)]
pub struct Cipher {
    state: SalsaFamilyState,
}

impl Cipher {
    /// Create cipher with the given state
    pub(crate) fn new(state: SalsaFamilyState) -> Self {
        let mut cipher = Cipher { state };
        cipher.gen_block();
        cipher
    }

    /// Generate a block
    pub(crate) fn gen_block(&mut self) {
        self.init_block();
        self.rounds();
        self.add_block();
    }

    /// Run the 20 rounds (i.e. 10 double rounds) of ChaCha20
    #[inline]
    fn rounds(&mut self) {
        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();

        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();
        self.double_round();
    }

    /// Double round function
    #[inline]
    fn double_round(&mut self) {
        let block = self.state.block_mut();

        quarter_round(0, 4, 8, 12, block);
        quarter_round(1, 5, 9, 13, block);
        quarter_round(2, 6, 10, 14, block);
        quarter_round(3, 7, 11, 15, block);
        quarter_round(0, 5, 10, 15, block);
        quarter_round(1, 6, 11, 12, block);
        quarter_round(2, 7, 8, 13, block);
        quarter_round(3, 4, 9, 14, block);
    }

    /// Initialize a new block
    #[inline]
    fn init_block(&mut self) {
        let iv = self.state.iv();
        let key = self.state.key();
        let block_idx = self.state.block_idx();
        let block = self.state.block_mut();

        block[0] = 0x6170_7865;
        block[1] = 0x3320_646e;
        block[2] = 0x7962_2d32;
        block[3] = 0x6b20_6574;
        block[4] = key[0];
        block[5] = key[1];
        block[6] = key[2];
        block[7] = key[3];
        block[8] = key[4];
        block[9] = key[5];
        block[10] = key[6];
        block[11] = key[7];
        block[12] = (block_idx & 0xffff_ffff) as u32;
        block[13] = ((block_idx >> 32) & 0xffff_ffff) as u32;
        block[14] = iv[0];
        block[15] = iv[1];
    }

    /// Add a block
    #[inline]
    fn add_block(&mut self) {
        let iv = self.state.iv();
        let key = self.state.key();
        let block_idx = self.state.block_idx();
        let block = self.state.block_mut();

        block[0] = block[0].wrapping_add(0x6170_7865);
        block[1] = block[1].wrapping_add(0x3320_646e);
        block[2] = block[2].wrapping_add(0x7962_2d32);
        block[3] = block[3].wrapping_add(0x6b20_6574);
        block[4] = block[4].wrapping_add(key[0]);
        block[5] = block[5].wrapping_add(key[1]);
        block[6] = block[6].wrapping_add(key[2]);
        block[7] = block[7].wrapping_add(key[3]);
        block[8] = block[8].wrapping_add(key[4]);
        block[9] = block[9].wrapping_add(key[5]);
        block[10] = block[10].wrapping_add(key[6]);
        block[11] = block[11].wrapping_add(key[7]);
        block[12] = block[12].wrapping_add((block_idx & 0xffff_ffff) as u32);
        block[13] = block[13].wrapping_add(((block_idx >> 32) & 0xffff_ffff) as u32);
        block[14] = block[14].wrapping_add(iv[0]);
        block[15] = block[15].wrapping_add(iv[1]);
    }
}

impl SalsaFamilyCipher for Cipher {
    #[inline]
    fn next_block(&mut self) {
        self.state.next_block();
        self.gen_block();
    }

    #[inline]
    fn offset(&self) -> usize {
        self.state.offset()
    }

    #[inline]
    fn set_offset(&mut self, offset: usize) {
        self.state.set_offset(offset)
    }

    #[inline]
    fn block_word(&self, idx: usize) -> u32 {
        self.state.block_word(idx)
    }
}

impl SyncStreamCipher for Cipher {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.process(data);
        Ok(())
    }
}

impl SyncStreamCipherSeek for Cipher {
    fn current_pos(&self) -> u64 {
        self.state.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.state.seek(pos);
        self.gen_block();
    }
}

/// The ChaCha20 quarter round function
#[inline]
pub(crate) fn quarter_round(a: usize, b: usize, c: usize, d: usize, block: &mut [u32; 16]) {
    block[a] = block[a].wrapping_add(block[b]);
    block[d] ^= block[a];
    block[d] = block[d].rotate_left(16);

    block[c] = block[c].wrapping_add(block[d]);
    block[b] ^= block[c];
    block[b] = block[b].rotate_left(12);

    block[a] = block[a].wrapping_add(block[b]);
    block[d] ^= block[a];
    block[d] = block[d].rotate_left(8);

    block[c] = block[c].wrapping_add(block[d]);
    block[b] ^= block[c];
    block[b] = block[b].rotate_left(7);
}
