//! Salsa20 stream cipher implementation.
//!
//! Adapted from the `ctr` crate.

// TODO(tarcieri): figure out how to unify this with the `ctr` crate

use crate::{block::Block, BLOCK_SIZE};
use core::{
    cmp,
    fmt::{self, Debug},
};
use stream_cipher::{LoopError, SyncStreamCipher, SyncStreamCipherSeek};

/// Internal buffer
type Buffer = [u8; BLOCK_SIZE];

/// ChaCha20 as a counter mode stream cipher
pub(crate) struct Cipher {
    /// ChaCha20 block function initialized with a key and IV
    block: Block,

    /// Buffer containing previous block function output
    buffer: Buffer,

    /// Position within buffer, or `None` if the buffer is not in use
    buffer_pos: Option<u8>,

    /// Current counter value relative to the start of the keystream
    counter: u64,
}

impl Cipher {
    /// Create new CTR mode cipher from the given block and starting counter
    pub fn new(block: Block) -> Self {
        Self {
            block,
            buffer: [0u8; BLOCK_SIZE],
            buffer_pos: None,
            counter: 0,
        }
    }
}

impl SyncStreamCipher for Cipher {
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        self.check_data_len(data)?;

        // xor with leftover bytes from the last call if any
        if let Some(pos) = self.buffer_pos {
            let pos = pos as usize;

            if data.len() >= BLOCK_SIZE - pos {
                let buf = &self.buffer[pos..];
                let (r, l) = data.split_at_mut(buf.len());
                data = l;
                xor(r, buf);
                self.buffer_pos = None;
            } else {
                let buf = &self.buffer[pos..pos.checked_add(data.len()).unwrap()];
                xor(data, buf);
                self.buffer_pos = Some(pos.checked_add(data.len()).unwrap() as u8);
                return Ok(());
            }
        }

        let mut counter = self.counter;

        while data.len() >= BLOCK_SIZE {
            let (l, r) = { data }.split_at_mut(BLOCK_SIZE);
            data = r;
            self.block.apply_keystream(counter, l);
            counter = counter.checked_add(1).unwrap();
        }

        if !data.is_empty() {
            self.block.generate(counter, &mut self.buffer);
            counter = counter.checked_add(1).unwrap();
            let n = data.len();
            xor(data, &self.buffer[..n]);
            self.buffer_pos = Some(n as u8);
        }

        self.counter = counter;

        Ok(())
    }
}

impl SyncStreamCipherSeek for Cipher {
    fn current_pos(&self) -> u64 {
        let bs = BLOCK_SIZE as u64;

        if let Some(pos) = self.buffer_pos {
            (self.counter.wrapping_sub(1) * bs)
                .checked_add(u64::from(pos))
                .unwrap()
        } else {
            self.counter * bs
        }
    }

    fn seek(&mut self, pos: u64) {
        let bs = BLOCK_SIZE as u64;
        self.counter = pos / bs;
        let rem = pos % bs;

        if rem == 0 {
            self.buffer_pos = None;
        } else {
            self.block.generate(self.counter, &mut self.buffer);
            self.counter = self.counter.checked_add(1).unwrap();
            self.buffer_pos = Some(rem as u8);
        }
    }
}

impl Cipher {
    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let dlen = data.len()
            - self
                .buffer_pos
                .map(|pos| cmp::min(BLOCK_SIZE - pos as usize, data.len()))
                .unwrap_or_default();

        let data_blocks = dlen / BLOCK_SIZE + if data.len() % BLOCK_SIZE != 0 { 1 } else { 0 };

        if self.counter.checked_add(data_blocks as u64).is_some() {
            Ok(())
        } else {
            Err(LoopError)
        }
    }
}

impl Debug for Cipher {
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
