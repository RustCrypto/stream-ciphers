//! Legacy version of ChaCha20 with a 64-bit nonce

use crate::chacha::{Key, Nonce};
use cipher::{
    consts::{U32, U64, U8},
    generic_array::GenericArray,
    BlockSizeUser, IvSizeUser, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};
use crate::{ChaChaCore, cfg_if, STATE_WORDS, CONSTANTS, avx2_cpuid, sse2_cpuid, PhantomData, Rounds, R20};


use crate::chacha::*;

#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// Nonce type used by [`ChaCha20Legacy`].
pub type LegacyNonce = GenericArray<u8, U8>;

/// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
///
/// **WARNING:** this implementation uses 32-bit counter, while the original
/// implementation uses 64-bit counter. In other words, it does
/// not allow encrypting of more than 256 GiB of data.
pub type ChaCha20Legacy = StreamCipherCoreWrapper<ChaCha20LegacyCore>;

/// The ChaCha20 stream cipher (legacy "djb" construction with 64-bit nonce).
pub struct ChaCha20LegacyCore(ChaChaCore<R20>);

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
        let mut state = [0u32; STATE_WORDS];
        state[0..4].copy_from_slice(&CONSTANTS);
        let key_chunks = key.chunks_exact(4);
        for (val, chunk) in state[4..12].iter_mut().zip(key_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let iv_chunks = iv.chunks_exact(4);
        for (val, chunk) in state[14..16].iter_mut().zip(iv_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        cfg_if! {
            if #[cfg(chacha20_force_soft)] {
                let tokens = ();
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                cfg_if! {
                    if #[cfg(chacha20_force_avx2)] {
                        let tokens = ();
                    } else if #[cfg(chacha20_force_sse2)] {
                        let tokens = ();
                    } else {
                        let tokens = (avx2_cpuid::init(), sse2_cpuid::init());
                    }
                }
            } else {
                let tokens = ();
            }
        }
        Self {
            block
        }
    }
}

impl StreamCipherCore for ChaCha20LegacyCore {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        self.0.remaining_blocks()
    }

    #[inline(always)]
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        self.0.process_with_backend(f);
    }
}

impl StreamCipherSeekCore for ChaCha20LegacyCore {
    type Counter = u32;

    #[inline(always)]
    fn get_block_pos(&self) -> u32 {
        self.0.get_block_pos()
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u32) {
        self.0.set_block_pos(pos);
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for ChaCha20LegacyCore {}
