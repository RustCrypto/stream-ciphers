//! The ChaCha20 block function. Defined in RFC 8439 Section 2.3.
//!
//! <https://tools.ietf.org/html/rfc8439#section-2.3>

use salsa20_core::{CONSTANTS, IV_WORDS, KEY_WORDS, STATE_WORDS};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) mod sse2;

/// The ChaCha20 block function
///
/// While ChaCha20 is a stream cipher, not a block cipher, its core
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
                CONSTANTS[1],
                CONSTANTS[2],
                CONSTANTS[3],
                key[0],
                key[1],
                key[2],
                key[3],
                key[4],
                key[5],
                key[6],
                key[7],
                (counter & 0xffff_ffff) as u32,
                ((counter >> 32) & 0xffff_ffff) as u32,
                iv[0],
                iv[1],
            ],
        };

        block.rounds();
        block.finish(key, iv, counter)
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
        let state = &mut self.state;
        quarter_round(0, 4, 8, 12, state);
        quarter_round(1, 5, 9, 13, state);
        quarter_round(2, 6, 10, 14, state);
        quarter_round(3, 7, 11, 15, state);
        quarter_round(0, 5, 10, 15, state);
        quarter_round(1, 6, 11, 12, state);
        quarter_round(2, 7, 8, 13, state);
        quarter_round(3, 4, 9, 14, state);
    }

    /// Finish computing a block
    #[inline]
    fn finish(
        self,
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let mut state = self.state;

        state[0] = state[0].wrapping_add(CONSTANTS[0]);
        state[1] = state[1].wrapping_add(CONSTANTS[1]);
        state[2] = state[2].wrapping_add(CONSTANTS[2]);
        state[3] = state[3].wrapping_add(CONSTANTS[3]);
        state[4] = state[4].wrapping_add(key[0]);
        state[5] = state[5].wrapping_add(key[1]);
        state[6] = state[6].wrapping_add(key[2]);
        state[7] = state[7].wrapping_add(key[3]);
        state[8] = state[8].wrapping_add(key[4]);
        state[9] = state[9].wrapping_add(key[5]);
        state[10] = state[10].wrapping_add(key[6]);
        state[11] = state[11].wrapping_add(key[7]);
        state[12] = state[12].wrapping_add((counter & 0xffff_ffff) as u32);
        state[13] = state[13].wrapping_add(((counter >> 32) & 0xffff_ffff) as u32);
        state[14] = state[14].wrapping_add(iv[0]);
        state[15] = state[15].wrapping_add(iv[1]);

        state
    }
}

/// The ChaCha20 quarter round function
#[inline]
pub(crate) fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}
