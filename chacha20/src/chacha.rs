
use cfg_if::cfg_if;
use cipher::{
    consts::{U10, U12, U32, U4, U6, U64},
    generic_array::GenericArray,
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore,
};

use crate::{ChaChaCore, STATE_WORDS, CONSTANTS, avx2_cpuid, sse2_cpuid, PhantomData, Rounds, R20, R8, R12};

/// Block type used by all ChaCha variants.
#[cfg(feature = "cipher")]
type Block = GenericArray<u8, U64>;

/// Key type used by all ChaCha variants.
#[cfg(feature = "cipher")]
pub type Key = GenericArray<u8, U32>;

/// Nonce type used by ChaCha variants.
#[cfg(feature = "cipher")]
pub type Nonce = GenericArray<u8, U12>;

/// ChaCha8 stream cipher (reduced-round variant of [`ChaCha20`] with 8 rounds)
#[cfg(feature = "cipher")]
pub type ChaCha8 = ChaCha<R8>;

/// ChaCha12 stream cipher (reduced-round variant of [`ChaCha20`] with 12 rounds)
#[cfg(feature = "cipher")]
pub type ChaCha12 = ChaCha<R12>;

/// ChaCha20 stream cipher (RFC 8439 version with 96-bit nonce)
#[cfg(feature = "cipher")]
pub type ChaCha20 = ChaCha<R20>;

pub struct ChaCha<R: Rounds> {
    block: ChaChaCore<R>,
}

impl<R: Rounds> KeySizeUser for ChaCha<R> {
    type KeySize = U32;
}
#[cfg(feature = "cipher")]
impl<R: Rounds> IvSizeUser for ChaCha<R> {
    type IvSize = U12;
}
#[cfg(feature = "cipher")]
impl<R: Rounds> BlockSizeUser for ChaCha<R> {
    type BlockSize = U64;
}
#[cfg(feature = "cipher")]
impl<R: Rounds> KeyIvInit for ChaCha<R> {
    #[inline]
    fn new(key: &Key, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0..4].copy_from_slice(&CONSTANTS);
        let key_chunks = key.chunks_exact(4);
        for (val, chunk) in state[4..12].iter_mut().zip(key_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let iv_chunks = iv.chunks_exact(4);
        for (val, chunk) in state[13..16].iter_mut().zip(iv_chunks) {
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
            block: ChaChaCore { 
                state, 
                tokens, 
                rounds: PhantomData, 
                buffer: [0u8; 256], 
                buffer_pos: 0 
            }
        }
    }
}

