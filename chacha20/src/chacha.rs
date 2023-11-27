pub use cipher::{
    consts::{U10, U12, U32, U4, U6, U64},
    generic_array::GenericArray,
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamCipher, StreamCipherError, inout::InOutBuf,
};

use crate::{ChaChaCore, Rounds, R20, R8, R12, IETF};

/// Key type used by all ChaCha variants.
pub type Key = GenericArray<u8, U32>;

/// Nonce type used by ChaCha variants.
pub type Nonce = GenericArray<u8, U12>;

/// ChaCha8 stream cipher (reduced-round variant of [`ChaCha20`] with 8 rounds)
pub type ChaCha8 = ChaCha<R8>;

/// ChaCha12 stream cipher (reduced-round variant of [`ChaCha20`] with 12 rounds)
pub type ChaCha12 = ChaCha<R12>;

/// ChaCha20 stream cipher (RFC 8439 version with 96-bit nonce)
pub type ChaCha20 = ChaCha<R20>;

pub struct ChaCha<R: Rounds> {
    block: ChaChaCore<R, IETF>,
}

impl<R: Rounds> KeySizeUser for ChaCha<R> {
    type KeySize = U32;
}

impl<R: Rounds> IvSizeUser for ChaCha<R> {
    type IvSize = U12;
}

impl<R: Rounds> BlockSizeUser for ChaCha<R> {
    type BlockSize = U64;
}

impl<R: Rounds> KeyIvInit for ChaCha<R> {
    #[inline]
    fn new(key: &Key, iv: &Nonce) -> Self {
        Self {
            block: ChaChaCore::new(key.as_ref(), iv.as_ref())
        }
    }
}

impl<R: Rounds> ChaCha<R> {
    pub fn get_block_pos(&self) -> u32 {
        self.block.state[12]
    }
    pub fn set_block_pos(&mut self, pos: u32) {
        self.block.state[12] = pos
    }
}

impl<R: Rounds> StreamCipher for ChaCha<R> {
    fn try_apply_keystream_inout(
            &mut self,
            buf: InOutBuf<'_, '_, u8>,
        ) -> Result<(), StreamCipherError> {
            
            Ok(())
    }
}