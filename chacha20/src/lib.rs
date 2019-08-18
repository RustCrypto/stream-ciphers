//! The ChaCha20 stream cipher ([RFC 7539])
//!
//! ChaCha20 is a lightweight stream cipher which is amenable to fast,
//! constant-time implementations in software. It improves upon the previous
//! [Salsa20] stream cipher, providing increased per-round diffusion
//! with no cost to performance.
//!
//! Cipher functionality is accessed using traits from re-exported
//! [`stream-cipher`](https://docs.rs/stream-cipher) crate.
//!
//! This crate contains three variants of ChaCha20:
//!
//! - `ChaCha20`: standard IETF variant with 96-bit nonce
//! - `ChaCha20Legacy`: (gated under the `legacy` feature) "djb" variant iwth 64-bit nonce
//! - `XChaCha20`: (gated under the `xchacha20` feature) 192-bit extended nonce variant
//!
//! # Security Warning
//!
//! This crate does not ensure ciphertexts are authentic, which can lead to
//! serious vulnerabilities if used incorrectly!
//!
//! USE AT YOUR OWN RISK!
//!
//! # Usage
//!
//! ```
//! use chacha20::ChaCha20;
//! use chacha20::stream_cipher::generic_array::GenericArray;
//! use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let nonce = GenericArray::from_slice(b"secret nonce");
//!
//! // create cipher instance
//! let mut cipher = ChaCha20::new(&key, &nonce);
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [73, 98, 234, 202, 73, 143, 0]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```
//!
//! [RFC 7539]: https://tools.ietf.org/html/rfc7539
//! [Salsa20]: https://docs.rs/salsa20

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(missing_docs)]

pub extern crate stream_cipher;

extern crate salsa20_core;

// TODO: replace with `u32::from_le_bytes`/`to_le_bytes` in libcore (1.32+)
#[cfg(feature = "xchacha20")]
extern crate byteorder;

mod block;
pub(crate) mod cipher;
#[cfg(feature = "legacy")]
mod legacy;
#[cfg(feature = "xchacha20")]
mod xchacha20;

use self::cipher::Cipher;
use salsa20_core::Ctr;
use stream_cipher::generic_array::{
    typenum::{U12, U32},
    GenericArray,
};
use stream_cipher::{LoopError, NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};

#[cfg(feature = "legacy")]
pub use self::legacy::ChaCha20Legacy;
#[cfg(feature = "xchacha20")]
pub use self::xchacha20::XChaCha20;

/// The ChaCha20 stream cipher (RFC 7539 version with 96-bit nonce)
///
/// Use `ChaCha20Legacy` for the legacy (a.k.a. "djb") construction with a
/// 64-bit nonce.
pub struct ChaCha20(Ctr<Cipher>);

impl NewStreamCipher for ChaCha20 {
    /// Key size in bytes
    type KeySize = U32;

    /// Nonce size in bytes
    type NonceSize = U12;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let exp_iv = &iv[0..4];
        let base_iv = &iv[4..12];
        let counter = (u64::from(exp_iv[0]) & 0xff) << 32
            | (u64::from(exp_iv[1]) & 0xff) << 40
            | (u64::from(exp_iv[2]) & 0xff) << 48
            | (u64::from(exp_iv[3]) & 0xff) << 56;
        let cipher = Cipher::new(key, base_iv, counter);

        ChaCha20(Ctr::new(cipher))
    }
}

impl SyncStreamCipher for ChaCha20 {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.0.try_apply_keystream(data)
    }
}

impl SyncStreamCipherSeek for ChaCha20 {
    fn current_pos(&self) -> u64 {
        self.0.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.0.seek(pos);
    }
}
