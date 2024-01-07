//! Legacy version of ChaCha20 with a 64-bit nonce

use crate::chacha::Key;
use crate::{ChaChaCore, R20};
use cipher::{
    array::Array,
    consts::{U32, U8},
    IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCoreWrapper,
};

/// Nonce type used by [`ChaCha20Legacy`].
pub type LegacyNonce = Array<u8, U8>;

use crate::variants::Legacy;

/// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
///
/// **WARNING:** this implementation uses 32-bit counter, while the original
/// implementation uses 64-bit counter. In other words, it does
/// not allow encrypting of more than 256 GiB of data.
pub type ChaCha20Legacy = StreamCipherCoreWrapper<ChaCha20LegacyCore>;

/// /// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
pub type ChaCha20LegacyCore = ChaChaCore<R20, Legacy>;

impl KeySizeUser for ChaCha20LegacyCore {
    type KeySize = U32;
}

impl IvSizeUser for ChaCha20LegacyCore {
    type IvSize = U8;
}

impl KeyIvInit for ChaCha20LegacyCore {
    #[inline(always)]
    fn new(key: &Key, iv: &LegacyNonce) -> Self {
        ChaChaCore::<R20, Legacy>::new(key.as_ref(), iv.as_ref())
    }
}
