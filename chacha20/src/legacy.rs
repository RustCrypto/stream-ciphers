//! Legacy version of ChaCha20 with a 64-bit nonce

use crate::cipher::Cipher;
use block_cipher_trait::generic_array::typenum::{U32, U8};
use block_cipher_trait::generic_array::GenericArray;
use salsa20_core::SalsaFamilyState;
use stream_cipher::{LoopError, NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};

/// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
///
/// The `legacy` Cargo feature must be enabled to use this.
pub struct ChaCha20Legacy(Cipher);

impl NewStreamCipher for ChaCha20Legacy {
    /// Key size in bytes
    type KeySize = U32;

    /// Nonce size in bytes
    type NonceSize = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let cipher = Cipher::new(SalsaFamilyState::new(key, iv));
        ChaCha20Legacy(cipher)
    }
}

impl SyncStreamCipher for ChaCha20Legacy {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.0.try_apply_keystream(data)
    }
}

impl SyncStreamCipherSeek for ChaCha20Legacy {
    fn current_pos(&self) -> u64 {
        self.0.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.0.seek(pos);
    }
}
