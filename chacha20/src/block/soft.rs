//! The ChaCha20 block function. Defined in RFC 8439 Section 2.3.
//!
//! <https://tools.ietf.org/html/rfc8439#section-2.3>
//!
//! Portable implementation which does not rely on architecture-specific
//! intrinsics.

use super::quarter_round;
use salsa20_core::{CONSTANTS, IV_WORDS, KEY_WORDS, STATE_WORDS};

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
        let block = Self {
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

        // TODO(tarcieri): ChaCha8, ChaCha12
        block.rounds(20)
    }

    /// Run the 20 rounds (i.e. 10 double rounds) of ChaCha20
    #[inline]
    fn rounds(&self, count: usize) -> [u32; STATE_WORDS] {
        let mut state = self.state;

        for _ in 0..(count / 2) {
            // column rounds
            quarter_round(0, 4, 8, 12, &mut state);
            quarter_round(1, 5, 9, 13, &mut state);
            quarter_round(2, 6, 10, 14, &mut state);
            quarter_round(3, 7, 11, 15, &mut state);

            // diagonal rounds
            quarter_round(0, 5, 10, 15, &mut state);
            quarter_round(1, 6, 11, 12, &mut state);
            quarter_round(2, 7, 8, 13, &mut state);
            quarter_round(3, 4, 9, 14, &mut state);
        }

        for (s1, s0) in state.iter_mut().zip(&self.state) {
            *s1 = s1.wrapping_add(*s0);
        }

        state
    }
}
