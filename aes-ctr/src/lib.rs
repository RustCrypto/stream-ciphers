//! AES-CTR ciphers implementation.
//!
//! Cipher functionality is accessed using traits from re-exported
//! [`stream-cipher`](https://docs.rs/stream-cipher) crate.
//!
//! This crate will select appropriate implementation at compile time depending
//! on target architecture and enabled target features. For the best performance
//! on x86-64 CPUs enable `aes`, `sse2` and `ssse3` target features. You can do
//! it either by using `RUSTFLAGS="-C target-feature=+aes,+ssse3"` or by editing
//! your `.cargo/config`. (`sse2` target feature is usually enabled by default)
//!
//! # Security Warning
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Usage example
//! ```
//! use aes_ctr::Aes128Ctr;
//! use aes_ctr::stream_cipher::generic_array::GenericArray;
//! use aes_ctr::stream_cipher::{
//!     NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek
//! };
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = GenericArray::from_slice(b"very secret key.");
//! let nonce = GenericArray::from_slice(b"and secret nonce");
//! // create cipher instance
//! let mut cipher = Aes128Ctr::new(&key, &nonce);
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [6, 245, 126, 124, 180, 146, 37]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```
#![no_std]
#![deny(missing_docs)]

pub use stream_cipher;

#[cfg(not(all(
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
mod soft;

#[cfg(not(all(
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
use soft as aes;

#[cfg(all(
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
))]
use aesni as aes;

pub use crate::aes::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
