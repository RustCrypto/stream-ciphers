//! Implementation of the [Salsa] family of stream ciphers.
//!
//! Cipher functionality is accessed using traits from re-exported [`cipher`] crate.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! USE AT YOUR OWN RISK!
//!
//! # Diagram
//!
//! This diagram illustrates the Salsa quarter round function.
//! Each round consists of four quarter-rounds:
//!
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/img/stream-ciphers/salsa20.png" width="300px">
//!
//! Legend:
//!
//! - ⊞ add
//! - ‹‹‹ rotate
//! - ⊕ xor
//!
//! # Example
//! ```
//! use salsa20::Salsa20;
//! // Import relevant traits
//! use salsa20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
//! use hex_literal::hex;
//!
//! let key = [0x42; 32];
//! let nonce = [0x24; 8];
//! let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
//! let ciphertext = hex!("85843cc5 d58cce7b 5dd3dd04 fa005ded");
//!
//! // Key and IV must be references to the `Array` type.
//! // Here we use the `Into` trait to convert arrays into it.
//! let mut cipher = Salsa20::new(&key.into(), &nonce.into());
//!
//! let mut buffer = plaintext.clone();
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, ciphertext);
//!
//! let ciphertext = buffer.clone();
//!
//! // Salsa ciphers support seeking
//! cipher.seek(0u32);
//!
//! // decrypt ciphertext by applying keystream again
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, plaintext);
//!
//! // stream ciphers can be used with streaming messages
//! cipher.seek(0u32);
//! for chunk in buffer.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buffer, ciphertext);
//! ```
//!
//! Salsa20 will run the SSE2 backend in x86(-64) targets for Salsa20/20 variant.
//! Other variants will fallback to the software backend.
//!
//! [Salsa]: https://en.wikipedia.org/wiki/Salsa20

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]
pub use cipher;

use cipher::{
    Block, BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherClosure,
    StreamCipherCore, StreamCipherCoreWrapper, StreamCipherSeekCore,
    array::{Array, ArraySize, typenum::Unsigned},
    consts::{U4, U6, U8, U10, U24, U32, U64},
};
use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod backends;
mod xsalsa;

pub use xsalsa::{XSalsa8, XSalsa12, XSalsa20, XSalsaCore, hsalsa};

/// Salsa20/8 stream cipher
/// (reduced-round variant of Salsa20 with 8 rounds, *not recommended*)
pub type Salsa8 = StreamCipherCoreWrapper<SalsaCore<U4, U32>>;

/// Salsa20/12 stream cipher
/// (reduced-round variant of Salsa20 with 12 rounds, *not recommended*)
pub type Salsa12 = StreamCipherCoreWrapper<SalsaCore<U6, U32>>;

/// Salsa20/20 stream cipher
/// (20 rounds; **recommended**)
pub type Salsa20 = StreamCipherCoreWrapper<SalsaCore<U10, U32>>;

/// Key type used by all Salsa variants and [`XSalsa20`].
pub type Key<KeySize> = Array<u8, KeySize>;

/// Nonce type used by all Salsa variants.
pub type Nonce = Array<u8, U8>;

/// Nonce type used by [`XSalsa20`].
pub type XNonce = Array<u8, U24>;

/// Number of 32-bit words in the Salsa20 state
const STATE_WORDS: usize = 16;

/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The Salsa20 core function.
pub struct SalsaCore<R: Unsigned, KeySize = U32> {
    /// Internal state of the core function
    state: [u32; STATE_WORDS],
    /// Number of rounds to perform
    rounds: PhantomData<R>,
    /// Key size
    key_size: PhantomData<KeySize>,
}

impl<R: Unsigned, KeySize> SalsaCore<R, KeySize> {
    /// Create new Salsa core from raw state.
    ///
    /// This method is mainly intended for the `scrypt` crate.
    /// Other users generally should not use this method.
    pub fn from_raw_state(state: [u32; STATE_WORDS]) -> Self {
        Self {
            state,
            rounds: PhantomData,
            key_size: PhantomData,
        }
    }
}

impl<R: Unsigned, KeySize> KeySizeUser for SalsaCore<R, KeySize>
where
    KeySize: ArraySize,
{
    type KeySize = KeySize;
}

impl<R: Unsigned, KeySize> IvSizeUser for SalsaCore<R, KeySize> {
    type IvSize = U8;
}

impl<R: Unsigned, KeySize> BlockSizeUser for SalsaCore<R, KeySize> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for SalsaCore<R, U32>
{
    fn new(key: &Key<U32>, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0] = CONSTANTS[0];

        for (i, chunk) in key[..16].chunks(4).enumerate() {
            state[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[5] = CONSTANTS[1];

        for (i, chunk) in iv.chunks(4).enumerate() {
            state[6 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[8] = 0;
        state[9] = 0;
        state[10] = CONSTANTS[2];

        for (i, chunk) in key[16..].chunks(4).enumerate() {
            state[11 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[15] = CONSTANTS[3];

        Self {
            state,
            rounds: PhantomData,
            key_size: PhantomData,
        }
    }
}

impl<R: Unsigned, KeySize> StreamCipherCore for SalsaCore<R, KeySize> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u64::MAX - self.get_block_pos();
        rem.try_into().ok()
    }
    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut backends::soft::Backend(self));
    }
}

impl<R: Unsigned, KeySize> StreamCipherSeekCore for SalsaCore<R, KeySize> {
    type Counter = u64;

    #[inline(always)]
    fn get_block_pos(&self) -> u64 {
        (self.state[8] as u64) + ((self.state[9] as u64) << 32)
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u64) {
        self.state[8] = (pos & 0xffff_ffff) as u32;
        self.state[9] = ((pos >> 32) & 0xffff_ffff) as u32;
    }
}

#[cfg(feature = "zeroize")]
impl<R: Unsigned> Drop for SalsaCore<R> {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<R: Unsigned> ZeroizeOnDrop for SalsaCore<R> {}
