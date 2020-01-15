//! ChaCha20 stream cipher implementation.
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
    block: Block,
    buffer: Buffer,
    base_counter: u64,
    counter: u64,
    pos: Option<u8>,
}

impl Cipher {
    /// Create new CTR mode cipher from the given block and starting counter
    pub fn new(block: Block, base_counter: u64) -> Self {
        Self {
            block,
            buffer: [0u8; BLOCK_SIZE],
            base_counter,
            counter: 0,
            pos: None,
        }
    }
}

impl SyncStreamCipher for Cipher {
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        self.check_data_len(data)?;

        // xor with leftover bytes from the last call if any
        if let Some(pos) = self.pos {
            let pos = pos as usize;

            if data.len() >= BLOCK_SIZE - pos {
                let buf = &self.buffer[pos..];
                let (r, l) = { data }.split_at_mut(buf.len());
                data = l;
                xor(r, buf);
                self.pos = None;
            } else {
                let buf = &self.buffer[pos..pos + data.len()];
                xor(data, buf);
                self.pos = Some((pos + data.len()) as u8);
                return Ok(());
            }
        }

        let mut counter = self.counter;

        while data.len() >= BLOCK_SIZE {
            let (l, r) = { data }.split_at_mut(BLOCK_SIZE);
            data = r;
            self.block.generate(self.base_counter + counter, l);
            counter += 1;
        }

        if !data.is_empty() {
            self.block
                .generate(self.base_counter + counter, &mut self.buffer);
            counter += 1;
            let n = data.len();
            xor(data, &self.buffer[..n]);
            self.pos = Some(n as u8);
        }

        self.counter = counter;

        Ok(())
    }
}

impl SyncStreamCipherSeek for Cipher {
    fn current_pos(&self) -> u64 {
        let bs = BLOCK_SIZE as u64;

        match self.pos {
            Some(pos) => self.counter.wrapping_sub(1) * bs + u64::from(pos),
            None => self.counter * bs,
        }
    }

    fn seek(&mut self, pos: u64) {
        let bs = BLOCK_SIZE as u64;
        self.counter = pos / bs;
        let l = (pos % bs) as u16;
        if l == 0 {
            self.pos = None;
        } else {
            self.block
                .generate(self.base_counter + self.counter, &mut self.buffer);
            self.counter += 1;
            self.pos = Some(l as u8);
        }
    }
}

impl Cipher {
    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let dlen = data.len()
            - match self.pos {
                Some(pos) => cmp::min(BLOCK_SIZE - pos as usize, data.len()),
                None => 0,
            };

        let data_buffers = dlen / BLOCK_SIZE + if data.len() % BLOCK_SIZE != 0 { 1 } else { 0 };

        if self.counter.checked_add(data_buffers as u64).is_some() {
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
