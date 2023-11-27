//! Legacy version of ChaCha20 with a 64-bit nonce

use crate::chacha::Key;
use cipher::{
    consts::{U32, U64, U8},
    generic_array::GenericArray,
    BlockSizeUser, IvSizeUser, KeySizeUser,
    KeyIvInit, StreamCipher,
    inout::InOutBuf,
    StreamCipherError, StreamCipherSeek, OverflowError,
    SeekNum
};
use crate::{ChaChaCore, Variant, R20};

#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// Nonce type used by [`ChaCha20Legacy`].
pub type LegacyNonce = GenericArray<u8, U8>;

#[derive(Clone)]
struct Legacy();
impl Variant for Legacy {
    type Counter = u64;
    type Nonce = [u8; 8];
    const NONCE_SIZE: usize = 2;
}

/// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
///
/// **WARNING:** this implementation uses 32-bit counter, while the original
/// implementation uses 64-bit counter. In other words, it does
/// not allow encrypting of more than 256 GiB of data.
pub type ChaCha20Legacy = ChaCha20LegacyCore;

/// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
pub struct ChaCha20LegacyCore{
    block: ChaChaCore<R20, Legacy>
}

impl KeySizeUser for ChaCha20LegacyCore {
    type KeySize = U32;
}

impl IvSizeUser for ChaCha20LegacyCore {
    type IvSize = U8;
}

impl BlockSizeUser for ChaCha20LegacyCore {
    type BlockSize = U64;
}

impl KeyIvInit for ChaCha20LegacyCore {
    #[inline(always)]
    fn new(key: &Key, iv: &LegacyNonce) -> Self {
        Self {
            block: ChaChaCore::<R20, Legacy>::new(key.as_ref(), iv.as_ref())
        }
    }
}

impl ChaCha20LegacyCore {
    /// Get the block counter
    pub fn get_block_pos(&self) -> u32 {
        self.block.state[12]
    }
    /// Set the block counter
    pub fn set_block_pos(&mut self, pos: u32) {
        self.block.state[12] = pos
    }
}

impl StreamCipher for ChaCha20LegacyCore {
    fn try_apply_keystream_inout(
        &mut self,
        buf: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        Ok(())
    }
}

impl StreamCipherSeek for ChaCha20LegacyCore {
    fn current_pos<T: SeekNum>(&self) -> T {
        unimplemented!()
    }
    fn seek<T: SeekNum>(&mut self, pos: T) {
        
    }
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
        unimplemented!()
    }
    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), StreamCipherError> {
        Ok(())
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for ChaCha20LegacyCore {}
