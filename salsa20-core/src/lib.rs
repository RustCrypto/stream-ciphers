//! Shared functionality common to ciphers in the Salsa20 Family
//! (i.e. Salsa20 and ChaCha20)
//!
//! This crate isn't designed to be used directly, but is instead an
//! implementation detail fo the `salsa20` and `chacha20` crates.

#![no_std]
#![deny(missing_docs)]

pub extern crate stream_cipher;

#[cfg(feature = "zeroize")]
pub extern crate zeroize;

use core::fmt;
use stream_cipher::{LoopError, SyncStreamCipher, SyncStreamCipherSeek};

#[cfg(feature = "zeroize")]
use core::ops::Drop;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Number of bits in a Salsa20 family cipher key
pub const KEY_BITS: usize = 256;

/// Number of bytes in a Salsa20 family cipher key
pub const KEY_BYTES: usize = KEY_BITS / 8;

/// Number of 32-bit words in a Salsa20 family cipher key
pub const KEY_WORDS: usize = KEY_BYTES / 4;

/// Number of bits in a Salsa20 family cipher initialization vector
pub const IV_BITS: usize = 64;

/// Number of bytes in a Salsa20 family cipher initialization vector
pub const IV_BYTES: usize = IV_BITS / 8;

/// Number of 32-bit words in a Salsa20 family cipher initialization vector
pub const IV_WORDS: usize = IV_BYTES / 4;

/// Number of bytes in a Salsa20 family cipher internal state
pub const STATE_BYTES: usize = 64;

/// Number of 32-bit words in a Salsa20 family cipher internal state
pub const STATE_WORDS: usize = STATE_BYTES / 4;

/// Initialization constants used by the Salsa20 family
pub const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Trait to be impl'd by all Salsa20 family ciphers
pub trait SalsaFamilyCipher {
    /// Generate a block with a particular counter value
    fn block(&self, counter: u64) -> [u32; STATE_WORDS];
}

/// Counter mode for the block functions of Salsa20 family ciphers
#[derive(Default)]
pub struct Ctr<C: SalsaFamilyCipher> {
    /// Cipher
    cipher: C,

    /// Counter
    counter: u64,

    /// Offset within the current block
    offset: usize,

    /// Internal block state
    block: [u32; STATE_WORDS],
}

impl<C> Ctr<C>
where
    C: SalsaFamilyCipher,
{
    /// Initialize counter mode Salsa family stream cipher
    pub fn new(cipher: C) -> Self {
        let block = cipher.block(0);

        Self {
            cipher,
            counter: 0,
            offset: 0,
            block,
        }
    }
}

impl<C> SyncStreamCipher for Ctr<C>
where
    C: SalsaFamilyCipher,
{
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        let datalen = data.len();
        let initial_offset = self.offset;
        let initial_word_offset = initial_offset % 4;
        let initial_word_remaining = 4 - initial_word_offset;
        let final_offset = initial_offset + datalen % STATE_BYTES;

        let mut i = 0;

        if datalen > initial_word_remaining {
            // If the length of data is longer than remaining bytes in
            // the current word.
            let has_initial_words = initial_word_offset != 0;
            let initial_word_idx = initial_offset / 4;

            let mut word_idx = initial_offset / 4;

            // First, use the remaining part of the current word.
            if has_initial_words {
                let word = self.block[initial_word_idx];

                for j in initial_word_offset..4 {
                    data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                    i += 1;
                }

                word_idx += 1;
            }

            // Check if the remaining data is longer than one block.
            let (leftover_words, leftover_bytes) =
                if (datalen - i) / 4 > STATE_WORDS - (word_idx % STATE_WORDS) {
                    // If the length of the remaining data is longer
                    // than the remaining words in the current block.

                    // Use the remaining part of the current block
                    if word_idx != STATE_WORDS {
                        for j in word_idx..STATE_WORDS {
                            let word = self.block[j];

                            for k in 0..4 {
                                data[i] ^= ((word >> (k * 8)) & 0xff) as u8;
                                i += 1;
                            }
                        }
                    }

                    self.next_block();

                    let nblocks = (datalen - i) / 64;
                    let leftover = (datalen - i) % 64;

                    // Process whole blocks.
                    for _ in 0..nblocks {
                        for j in 0..STATE_WORDS {
                            let word = self.block[j];

                            for k in 0..4 {
                                data[i] ^= ((word >> (k * 8)) & 0xff) as u8;
                                i += 1;
                            }
                        }

                        self.next_block();
                    }

                    let leftover_words = leftover / 4;

                    // Process the leftover part of a block
                    for j in 0..leftover_words {
                        let word = self.block[j];

                        for k in 0..4 {
                            data[i] ^= ((word >> (k * 8)) & 0xff) as u8;
                            i += 1;
                        }
                    }

                    (leftover_words, leftover % 4)
                } else {
                    // If the remaining data is less than the length
                    // of a block.
                    let nwords = (datalen - i) / 4;
                    let leftover_bytes = (datalen - i) % 4;

                    // If we walked off the end of this block,
                    // generate the next one.
                    if has_initial_words && word_idx == STATE_WORDS {
                        word_idx = 0;
                        self.next_block();
                    }

                    // Use the remaining part of the current block
                    for j in word_idx..word_idx + nwords {
                        let word = self.block[j];

                        for k in 0..4 {
                            data[i] ^= ((word >> (k * 8)) & 0xff) as u8;
                            i += 1;
                        }
                    }

                    if word_idx + nwords == STATE_WORDS {
                        self.next_block();
                    }

                    ((word_idx + nwords) % STATE_WORDS, leftover_bytes)
                };

            // Process the leftover part of a single word
            let word = self.block[leftover_words];

            for j in 0..leftover_bytes {
                data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }

            self.offset = (4 * leftover_words) + leftover_bytes;
        } else {
            // If the total length is less than the remaining bytes in
            // a word.
            let word_idx = self.offset / 4 % STATE_WORDS;
            let word = self.block[word_idx];

            for j in initial_word_offset..initial_word_offset + datalen {
                data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }

            if final_offset == STATE_BYTES {
                self.next_block();
            }
        }

        // Set the offset and generate the next block if we ran over.
        self.offset = final_offset % STATE_BYTES;
        Ok(())
    }
}

impl<C> SyncStreamCipherSeek for Ctr<C>
where
    C: SalsaFamilyCipher,
{
    fn current_pos(&self) -> u64 {
        self.counter << 6 | self.offset as u64
    }

    fn seek(&mut self, pos: u64) {
        self.offset = (pos & 0x3f) as usize;
        self.counter = pos >> 6;
        self.block = self.cipher.block(self.counter);
    }
}

impl<C> Ctr<C>
where
    C: SalsaFamilyCipher,
{
    fn next_block(&mut self) {
        self.counter = self.counter.checked_add(1).expect("overflow");
        self.block = self.cipher.block(self.counter);
    }
}

impl<C> fmt::Debug for Ctr<C>
where
    C: SalsaFamilyCipher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SalsaFamilyState {{ block_idx: {}, offset: {}, ... }}",
            self.counter, self.offset
        )
    }
}

#[cfg(feature = "zeroize")]
impl<C> Zeroize for Ctr<C>
where
    C: SalsaFamilyCipher,
{
    fn zeroize(&mut self) {
        self.block.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C> Drop for Ctr<C>
where
    C: SalsaFamilyCipher,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}
