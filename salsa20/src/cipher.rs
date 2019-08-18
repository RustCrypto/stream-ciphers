//! Salsa20 cipher core implementation

use block::Block;
use byteorder::{ByteOrder, LE};
use salsa20_core::{SalsaFamilyCipher, IV_WORDS, KEY_WORDS, STATE_WORDS};

/// Salsa20 core cipher functionality
#[derive(Debug)]
pub(crate) struct Cipher {
    /// Secret key
    key: [u32; KEY_WORDS],

    /// Initialization vector
    iv: [u32; IV_WORDS],
}

impl Cipher {
    /// Create cipher with the given state
    pub fn new(key_bytes: &[u8], iv_bytes: &[u8]) -> Self {
        let mut key = [0u32; KEY_WORDS];
        for (i, chunk) in key_bytes.chunks(4).enumerate() {
            key[i] = LE::read_u32(chunk);
        }

        let mut iv = [0u32; IV_WORDS];
        for (i, chunk) in iv_bytes.chunks(4).enumerate() {
            iv[i] = LE::read_u32(chunk);
        }

        Cipher { key, iv }
    }
}

impl SalsaFamilyCipher for Cipher {
    #[inline]
    fn block(&self, counter: u64) -> [u32; STATE_WORDS] {
        Block::generate(&self.key, self.iv, counter)
    }
}
