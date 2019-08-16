//! Shared functionality common to ciphers in the Salsa20 Family
//! (i.e. Salsa20 and ChaCha20)
//!
//! This crate isn't designed to be used directly, but is instead an
//! implementation detail fo the `salsa20` and `chacha20` crates.

#![no_std]
#![deny(missing_docs)]

extern crate block_cipher_trait;
pub extern crate stream_cipher;

// TODO: replace with `u32::from_le_bytes`/`to_le_bytes` in libcore (1.32+)
extern crate byteorder;

#[cfg(feature = "zeroize")]
pub extern crate zeroize;

use block_cipher_trait::generic_array::typenum::U32;
use block_cipher_trait::generic_array::typenum::U8;
use block_cipher_trait::generic_array::GenericArray;
use byteorder::{ByteOrder, LE};
use stream_cipher::NewStreamCipher;
use stream_cipher::SyncStreamCipherSeek;

#[cfg(feature = "zeroize")]
use core::ops::Drop;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const KEY_BITS: usize = 256;

const KEY_BYTES: usize = KEY_BITS / 8;

const KEY_WORDS: usize = KEY_BYTES / 4;

const IV_BITS: usize = 64;

const IV_BYTES: usize = IV_BITS / 8;

const IV_WORDS: usize = IV_BYTES / 4;

const STATE_BYTES: usize = 64;

const STATE_WORDS: usize = STATE_BYTES / 4;

/// Trait to be impl'd by all Salsa20 family ciphers
pub trait SalsaFamilyCipher {
    /// Compute the next block
    fn next_block(&mut self);

    /// Get the offset
    fn offset(&self) -> usize;

    /// Set the offset
    fn set_offset(&mut self, offset: usize);

    /// Get the word for the current block
    fn block_word(&self, idx: usize) -> u32;

    /// Process incoming data
    fn process(&mut self, data: &mut [u8]) {
        let datalen = data.len();
        let mut i = 0;
        let initial_offset = self.offset();
        let initial_word_offset = initial_offset % 4;
        let initial_word_remaining = 4 - initial_word_offset;
        let final_offset = initial_offset + datalen % STATE_BYTES;

        if datalen > initial_word_remaining {
            // If the length of data is longer than remaining bytes in
            // the current word.
            let has_initial_words = initial_word_offset != 0;
            let initial_word_idx = initial_offset / 4;

            let mut word_idx = initial_offset / 4;

            // First, use the remaining part of the current word.
            if has_initial_words {
                let word = self.block_word(initial_word_idx);

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
                            let word = self.block_word(j);

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
                            let word = self.block_word(j);

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
                        let word = self.block_word(j);

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
                        let word = self.block_word(j);

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
            let word = self.block_word(leftover_words);

            for j in 0..leftover_bytes {
                data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }

            self.set_offset((4 * leftover_words) + leftover_bytes);
        } else {
            // If the total length is less than the remaining bytes in
            // a word.
            let word_idx = self.offset() / 4 % STATE_WORDS;
            let word = self.block_word(word_idx);

            for j in initial_word_offset..initial_word_offset + datalen {
                data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }

            if final_offset == STATE_BYTES {
                self.next_block();
            }
        }

        // Set the offset and generate the next block if we ran over.
        self.set_offset(final_offset % STATE_BYTES);
    }
}

/// Internal state of a Salsa20 family cipher
pub struct SalsaFamilyState {
    /// Internal block state
    pub block: [u32; STATE_WORDS],

    /// Secret key
    pub key: [u32; KEY_WORDS],

    /// Initialization vector
    pub iv: [u32; IV_WORDS],

    /// Block index
    pub block_idx: u64,

    /// Offset
    pub offset: usize,
}

impl Default for SalsaFamilyState {
    fn default() -> Self {
        Self {
            block: [0; STATE_WORDS],
            key: [0; KEY_WORDS],
            iv: [0; IV_WORDS],
            block_idx: 0,
            offset: 0,
        }
    }
}

impl SalsaFamilyState {
    /// Initialize the internal cipher state
    fn init(&mut self, key: &[u8], iv: &[u8], block_idx: u64, offset: usize) {
        for (i, chunk) in key.chunks(4).enumerate() {
            self.key[i] = LE::read_u32(chunk);
        }

        for (i, chunk) in iv.chunks(4).enumerate() {
            self.iv[i] = LE::read_u32(chunk);
        }

        self.block_idx = block_idx;
        self.offset = offset;
    }
}

impl NewStreamCipher for SalsaFamilyState {
    /// Key size in bytes
    type KeySize = U32;

    /// Nonce size in bytes
    type NonceSize = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut state = SalsaFamilyState::default();
        state.init(key.as_slice(), iv.as_slice(), 0, 0);
        state
    }
}

impl SyncStreamCipherSeek for SalsaFamilyState {
    fn current_pos(&self) -> u64 {
        self.block_idx << 6 | self.offset as u64
    }

    fn seek(&mut self, pos: u64) {
        self.offset = (pos & 0x3f) as usize;
        self.block_idx = pos >> 6;
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SalsaFamilyState {
    fn zeroize(&mut self) {
        self.block.zeroize();
        self.key.zeroize();
        self.iv.zeroize();
        self.block_idx.zeroize();
        self.offset.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SalsaFamilyState {
    fn drop(&mut self) {
        self.zeroize();
    }
}
