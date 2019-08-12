use block_cipher_trait::generic_array::typenum::U32;
use block_cipher_trait::generic_array::typenum::U8;
use block_cipher_trait::generic_array::GenericArray;
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

pub struct SalsaFamilyState {
    pub block: [u32; STATE_WORDS],
    pub key: [u32; KEY_WORDS],
    pub iv: [u32; IV_WORDS],
    pub block_idx: u64,
    pub offset: usize,
}

pub trait SalsaFamilyCipher {
    #[inline]
    fn next_block(&mut self);

    #[inline]
    fn offset(&self) -> usize;

    #[inline]
    fn set_offset(&mut self, offset: usize);

    #[inline]
    fn block_word(&self, idx: usize) -> u32;

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
                    data[i] = data[i] ^ ((word >> (j * 8)) & 0xff) as u8;
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
                                data[i] = data[i] ^ ((word >> (k * 8)) & 0xff) as u8;
                                i += 1;
                            }
                        }

                        self.next_block();
                    } else {
                        // TODO(tarcieri): is this else clause unnecessary or is there a bug?
                        // See: <https://github.com/RustCrypto/stream-ciphers/issues/23>
                        #[allow(unused_assignments)]
                        {
                            word_idx = 0;
                            self.next_block();
                        }
                    }

                    let nblocks = (datalen - i) / 64;
                    let leftover = (datalen - i) % 64;

                    // Process whole blocks.
                    for _ in 0..nblocks {
                        for j in 0..STATE_WORDS {
                            let word = self.block_word(j);

                            for k in 0..4 {
                                data[i] = data[i] ^ ((word >> (k * 8)) & 0xff) as u8;
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
                            data[i] = data[i] ^ ((word >> (k * 8)) & 0xff) as u8;
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
                            data[i] = data[i] ^ ((word >> (k * 8)) & 0xff) as u8;
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
                data[i] = data[i] ^ ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }

            self.set_offset((4 * leftover_words) + leftover_bytes);
        } else {
            // If the total length is less than the remaining bytes in
            // a word.
            let word_idx = self.offset() / 4 % STATE_WORDS;
            let word = self.block_word(word_idx);

            for j in initial_word_offset..initial_word_offset + datalen {
                data[i] = data[i] ^ ((word >> (j * 8)) & 0xff) as u8;
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

impl SalsaFamilyState {
    pub fn create() -> SalsaFamilyState {
        SalsaFamilyState {
            block: [0; STATE_WORDS],
            key: [0; KEY_WORDS],
            iv: [0; IV_WORDS],
            block_idx: 0,
            offset: 0,
        }
    }

    pub fn init(&mut self, key: &[u8], iv: &[u8], block_idx: u64, offset: usize) {
        for i in 0..KEY_WORDS {
            self.key[i] = key[4 * i] as u32 & 0xff
                | (key[(4 * i) + 1] as u32 & 0xff) << 8
                | (key[(4 * i) + 2] as u32 & 0xff) << 16
                | (key[(4 * i) + 3] as u32 & 0xff) << 24;
        }

        for i in 0..IV_WORDS {
            self.iv[i] = iv[4 * i] as u32 & 0xff
                | (iv[(4 * i) + 1] as u32 & 0xff) << 8
                | (iv[(4 * i) + 2] as u32 & 0xff) << 16
                | (iv[(4 * i) + 3] as u32 & 0xff) << 24;
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
        let mut out = SalsaFamilyState::create();

        out.init(key.as_slice(), iv.as_slice(), 0, 0);

        out
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
