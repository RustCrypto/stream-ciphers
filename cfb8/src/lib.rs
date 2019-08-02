//! Generic [8-bit Cipher Feedback (CFB8)][1] mode implementation.
//!
//! This crate implements CFB8 as a [self-synchronizing stream cipher][2].
//!
//! # Warning
//! This crate does not provide any authentification! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Examples
//! ```
//! extern crate aes;
//! extern crate cfb8;
//! #[macro_use] extern crate hex_literal;
//!
//! use aes::Aes128;
//! use cfb8::Cfb8;
//! use cfb8::stream_cipher::{NewStreamCipher, StreamCipher};
//!
//! type AesCfb8 = Cfb8<Aes128>;
//!
//! let key = b"very secret key.";
//! let iv = b"unique init vect";
//! let plaintext = b"The quick brown fox jumps over the lazy dog.";
//! let ciphertext = hex!("
//!     8fb603d8 66a1181c 08506c75 37ee9cad
//!     35be8ff8 e0c79526 9d735d04 c0a93017
//!     b1a748e0 25146b68 23fc9ad3
//! ");
//!
//! let mut data = plaintext.to_vec();
//! // encrypt plaintext
//! AesCfb8::new_var(key, iv).unwrap().encrypt(&mut data);
//! assert_eq!(data, &ciphertext[..]);
//! // and decrypt it back
//! AesCfb8::new_var(key, iv).unwrap().decrypt(&mut data);
//! assert_eq!(data, &plaintext[..]);
//!
//! // CFB mode can be used with streaming messages
//! let mut cipher = AesCfb8::new_var(key, iv).unwrap();
//! for chunk in data.chunks_mut(3) {
//!     cipher.encrypt(chunk);
//! }
//! assert_eq!(data, &ciphertext[..]);
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher#Self-synchronizing_stream_ciphers
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_cipher_trait;
pub extern crate stream_cipher;

#[cfg(cargo_feature = "zeroize")]
extern crate zeroize;

use stream_cipher::{NewStreamCipher, StreamCipher, InvalidKeyNonceLength};
use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;

#[cfg(cargo_feature = "zeroize")]
use zeroize::Zeroize;
#[cfg(cargo_feature = "zeroize")]
use std::ops::Drop;

/// CFB self-synchronizing stream cipher instance.
pub struct Cfb8<C: BlockCipher> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

#[cfg(cargo_feature = "zeroize")]
impl<C: Zeroize> Zeroize for Cfb8<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.iv.zeroize();
    }
}

#[cfg(cargo_feature = "zeroize")]
impl<C> Drop for Cfb8<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: BlockCipher> NewStreamCipher for Cfb8<C> {
    type KeySize = C::KeySize;
    type NonceSize = C::BlockSize;

    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        iv: &GenericArray<u8, Self::NonceSize>,
    ) -> Self {
        Self { cipher: C::new(key), iv: iv.clone() }
    }

    fn new_var(key: &[u8], iv: &[u8] ) -> Result<Self, InvalidKeyNonceLength> {
        if Self::NonceSize::to_usize() != iv.len() {
            Err(InvalidKeyNonceLength)
        } else {
            let iv = GenericArray::clone_from_slice(iv);
            let cipher = C::new_varkey(key).map_err(|_| InvalidKeyNonceLength)?;
            Ok(Self { cipher, iv })
        }
    }
}

impl<C: BlockCipher> StreamCipher for Cfb8<C> {
    fn encrypt(&mut self, data: &mut [u8]) {
        let mut iv = self.iv.clone();
        let n = iv.len();
        for b in data.iter_mut() {
            let iv_copy = iv.clone();
            self.cipher.encrypt_block(&mut iv);
            *b ^= iv[0];
            iv[..n-1].clone_from_slice(&iv_copy[1..]);
            iv[n-1] = *b;
        }
        self.iv = iv;
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        let mut iv = self.iv.clone();
        let n = iv.len();
        for b in data.iter_mut() {
            let iv_copy = iv.clone();
            self.cipher.encrypt_block(&mut iv);
            let t = *b;
            *b ^= iv[0];
            iv[..n-1].clone_from_slice(&iv_copy[1..]);
            iv[n-1] = t;
        }
        self.iv = iv;
    }
}
