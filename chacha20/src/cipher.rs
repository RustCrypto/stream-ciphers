//! ChaCha20 cipher core implementation

use byteorder::{ByteOrder, LE};
use salsa20_core::{SalsaFamilyCipher, IV_WORDS, KEY_WORDS, STATE_WORDS};

/// ChaCha20 core cipher functionality
#[derive(Debug)]
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
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn block(&self, counter: u64) -> [u32; STATE_WORDS] {
        if cfg!(target_feature = "sse2") {
            unsafe {
                super::block::sse2::Block::generate(
                    &self.key,
                    self.iv,
                    self.counter_offset + counter,
                )
            }
        } else {
            super::block::Block::generate(&self.key, self.iv, self.counter_offset + counter)
        }
    }

    #[inline]
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn block(&self, counter: u64) -> [u32; STATE_WORDS] {
        super::block::Block::generate(&self.key, self.iv, self.counter_offset + counter)
    }
}
