//! ChaCha20 cipher core implementation

use super::MAX_BLOCKS;
use crate::block::Block;
use byteorder::{ByteOrder, LE};
use salsa20_core::{SalsaFamilyCipher, IV_WORDS, KEY_WORDS, STATE_WORDS};

/// ChaCha20 core cipher functionality
#[derive(Clone, Debug)]
pub(crate) struct Cipher {
    /// Secret key
    key: [u32; KEY_WORDS],

    /// Initialization vector
    iv: [u32; IV_WORDS],

    /// Offset of the initial counter in the keystream. This is derived from
    /// the extra 4 bytes in the 96-byte nonce RFC 8439 version (or is always
    /// 0 in the legacy version)
    counter_offset: u64,
}

impl Cipher {
    /// Create cipher with the given state
    pub fn new(key_bytes: &[u8], iv_bytes: &[u8], counter_offset: u64) -> Self {
        let mut key = [0u32; KEY_WORDS];
        for (i, chunk) in key_bytes.chunks(4).enumerate() {
            key[i] = LE::read_u32(chunk);
        }

        let mut iv = [0u32; IV_WORDS];
        for (i, chunk) in iv_bytes.chunks(4).enumerate() {
            iv[i] = LE::read_u32(chunk);
        }

        Cipher {
            key,
            iv,
            counter_offset,
        }
    }
}

impl SalsaFamilyCipher for Cipher {
    #[inline]
    fn block(&self, counter: u64) -> [u32; STATE_WORDS] {
        // TODO(tarcieri): avoid panic by making block API fallible
        assert!(counter < MAX_BLOCKS as u64, "MAX_BLOCKS exceeded");
        Block::generate(&self.key, self.iv, self.counter_offset + counter)
    }
}
