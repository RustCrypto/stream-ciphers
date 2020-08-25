//! Salsa20 stream cipher implementation.
//!
//! Adapted from the `ctr` crate.

// TODO(tarcieri): figure out how to unify this with the `ctr` crate (see #95)

use crate::{block::Block, rounds::Rounds, BLOCK_SIZE};
use core::fmt;
use stream_cipher::{LoopError, OverflowError, SeekNum, SyncStreamCipher, SyncStreamCipherSeek};

/// Internal buffer
type Buffer = [u8; BLOCK_SIZE];

/// ChaCha20 as a counter mode stream cipher
pub(crate) struct Cipher<R: Rounds> {
    /// ChaCha20 block function initialized with a key and IV
    block: Block<R>,

    /// Buffer containing previous block function output
    buffer: Buffer,

    /// Position within buffer, or `None` if the buffer is not in use
    buffer_pos: u8,

    /// Current counter value relative to the start of the keystream
    counter: u64,
}

impl<R: Rounds> Cipher<R> {
    /// Create new CTR mode cipher from the given block and starting counter
    pub fn new(block: Block<R>) -> Self {
        Self {
            block,
            buffer: [0u8; BLOCK_SIZE],
            buffer_pos: 0,
            counter: 0,
        }
    }
}

impl<R: Rounds> SyncStreamCipher for Cipher<R> {
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        self.check_data_len(data)?;
        let pos = self.buffer_pos as usize;
        debug_assert!(BLOCK_SIZE > pos);

        let mut counter = self.counter;
        // xor with leftover bytes from the last call if any
        if pos != 0 {
            if data.len() < BLOCK_SIZE - pos {
                let n = pos + data.len();
                xor(data, &self.buffer[pos..n]);
                self.buffer_pos = n as u8;
                return Ok(());
            } else {
                let (l, r) = data.split_at_mut(BLOCK_SIZE - pos);
                data = r;
                xor(l, &self.buffer[pos..]);
                counter += 1;
            }
        }

        let mut chunks = data.chunks_exact_mut(BLOCK_SIZE);
        for chunk in &mut chunks {
            self.block.apply_keystream(counter, chunk);
            counter += 1;
        }

        let rem = chunks.into_remainder();
        self.buffer_pos = rem.len() as u8;
        self.counter = counter;
        if !rem.is_empty() {
            self.block.generate(counter, &mut self.buffer);
            xor(rem, &self.buffer[..rem.len()]);
        }

        Ok(())
    }
}

impl<R: Rounds> SyncStreamCipherSeek for Cipher<R> {
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
        T::from_block_byte(self.counter, self.buffer_pos, BLOCK_SIZE as u8)
    }

    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError> {
        let res = pos.to_block_byte(BLOCK_SIZE as u8)?;
        self.counter = res.0;
        self.buffer_pos = res.1;
        if self.buffer_pos != 0 {
            self.block.generate(self.counter, &mut self.buffer);
        }
        Ok(())
    }
}

impl<R: Rounds> Cipher<R> {
    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let leftover_bytes = BLOCK_SIZE - self.buffer_pos as usize;
        if data.len() < leftover_bytes {
            return Ok(());
        }
        let blocks = 1 + (data.len() - leftover_bytes) / BLOCK_SIZE;
        self.counter
            .checked_add(blocks as u64)
            .ok_or(LoopError)
            .map(|_| ())
    }
}

impl<R: Rounds> fmt::Debug for Cipher<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Cipher {{ .. }}")
    }
}

#[inline(always)]
fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}
