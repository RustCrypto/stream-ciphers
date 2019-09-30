//! The Salsa20 block function.

use salsa20_core::{CONSTANTS, IV_WORDS, KEY_WORDS, STATE_WORDS};

/// The Salsa20 block function
///
/// While Salsa20 is a stream cipher, not a block cipher, its core
/// primitive is a function which acts on a 512-bit block
// TODO(tarcieri): zeroize? need to make sure we're actually copying first
pub(crate) struct Block {
    /// Internal state of the block function
    state: [u32; STATE_WORDS],
}

impl Block {
    /// Generate a block
    pub(crate) fn generate(
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let mut block = Self {
            state: [
                CONSTANTS[0],
                key[0],
                key[1],
                key[2],
                key[3],
                CONSTANTS[1],
                iv[0],
                iv[1],
                (counter & 0xffff_ffff) as u32,
                ((counter >> 32) & 0xffff_ffff) as u32,
                CONSTANTS[2],
                key[4],
                key[5],
                key[6],
                key[7],
                CONSTANTS[3],
            ],
        };

        block.rounds();
        block.finish(key, iv, counter)
    }

    /// Run the 20 rounds (i.e. 10 double rounds) of Salsa20
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
        let state = &mut self.state;

        // column rounds
        quarter_round(0, 4, 8, 12, state);
        quarter_round(5, 9, 13, 1, state);
        quarter_round(10, 14, 2, 6, state);
        quarter_round(15, 3, 7, 11, state);

        // diagonal rounds
        quarter_round(0, 1, 2, 3, state);
        quarter_round(5, 6, 7, 4, state);
        quarter_round(10, 11, 8, 9, state);
        quarter_round(15, 12, 13, 14, state);
    }

    /// Finish computing a state
    #[inline]
    fn finish(
        self,
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let mut state = self.state;

        state[0] = state[0].wrapping_add(CONSTANTS[0]);
        state[1] = state[1].wrapping_add(key[0]);
        state[2] = state[2].wrapping_add(key[1]);
        state[3] = state[3].wrapping_add(key[2]);
        state[4] = state[4].wrapping_add(key[3]);
        state[5] = state[5].wrapping_add(CONSTANTS[1]);
        state[6] = state[6].wrapping_add(iv[0]);
        state[7] = state[7].wrapping_add(iv[1]);
        state[8] = state[8].wrapping_add((counter & 0xffff_ffff) as u32);
        state[9] = state[9].wrapping_add(((counter >> 32) & 0xffff_ffff) as u32);
        state[10] = state[10].wrapping_add(CONSTANTS[2]);
        state[11] = state[11].wrapping_add(key[4]);
        state[12] = state[12].wrapping_add(key[5]);
        state[13] = state[13].wrapping_add(key[6]);
        state[14] = state[14].wrapping_add(key[7]);
        state[15] = state[15].wrapping_add(CONSTANTS[3]);

        state
    }
}

#[inline]
pub(crate) fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
    let mut t: u32;

    t = state[a].wrapping_add(state[d]);
    state[b] ^= t.rotate_left(7) as u32;

    t = state[b].wrapping_add(state[a]);
    state[c] ^= t.rotate_left(9) as u32;

    t = state[c].wrapping_add(state[b]);
    state[d] ^= t.rotate_left(13) as u32;

    t = state[d].wrapping_add(state[c]);
    state[a] ^= t.rotate_left(18) as u32;
}
