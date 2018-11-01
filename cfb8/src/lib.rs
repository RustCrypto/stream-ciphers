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
//! let mut buffer = plaintext.to_vec();
//! // encrypt plaintext
//! AesCfb8::new_var(key, iv).unwrap().encrypt(&mut buffer);
//! assert_eq!(buffer, &ciphertext[..]);
//! // and decrypt it back
//! AesCfb8::new_var(key, iv).unwrap().decrypt(&mut buffer);
//! assert_eq!(buffer, &plaintext[..]);
//!
//! // CFB mode can be used with streaming messages
//! let mut cipher = AesCfb8::new_var(key, iv).unwrap();
//! for chunk in buffer.chunks_mut(3) {
//!     cipher.encrypt(chunk);
//! }
//! assert_eq!(buffer, &ciphertext[..]);
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher#Self-synchronizing_stream_ciphers
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_cipher_trait;
#[cfg(feature = "std")]
extern crate std;

use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;

mod errors;

pub use errors::InvalidKeyIvLength;

/// CFB self-synchronizing stream cipher instance.
pub struct Cfb8<C: BlockCipher> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
type Key<C> = GenericArray<u8, <C as BlockCipher>::KeySize>;

impl<C: BlockCipher> Cfb8<C> {
    /// Create a new CFB mode instance with generic array key and IV.
    pub fn new(key: &Key<C>, iv: &Block<C>) -> Self {
        Self { cipher: C::new(key), iv: iv.clone() }
    }

    /// Create a new CFB mode instance with sliced key and IV.
    ///
    /// Returns an `InvalidKeyIvLength` error if key or IV have incorrect size.
    pub fn new_var(key: &[u8], iv: &[u8]) -> Result<Self, InvalidKeyIvLength> {
        if iv.len() != C::BlockSize::to_usize() {
            return Err(InvalidKeyIvLength);
        }
        let cipher = C::new_varkey(key).map_err(|_| InvalidKeyIvLength)?;
        let iv = GenericArray::clone_from_slice(iv);
        Ok(Self { cipher, iv })
    }

    /// Encrypt data.
    pub fn encrypt(&mut self, buffer: &mut [u8]) {
        let mut iv = self.iv.clone();
        let n = iv.len();
        for b in buffer.iter_mut() {
            let iv_copy = iv.clone();
            self.cipher.encrypt_block(&mut iv);
            *b ^= iv[0];
            iv[..n-1].clone_from_slice(&iv_copy[1..]);
            iv[n-1] = *b;
        }
        self.iv = iv;
    }

    /// Decrypt data.
    pub fn decrypt(&mut self, buffer: &mut [u8]) {
        let mut iv = self.iv.clone();
        let n = iv.len();
        for b in buffer.iter_mut() {
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
