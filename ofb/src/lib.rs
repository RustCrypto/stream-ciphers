//! Generic [Output Feedback (OFB)][1] mode implementation.
//!
//! This crate implements OFB as a [synchronous stream cipher][2].
//!
//! # Security Warning
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Examples
//! ```
//! use aes::Aes128;
//! use hex_literal::hex;
//! use ofb::Ofb;
//! use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};
//!
//! type AesOfb = Ofb<Aes128>;
//!
//! let key = b"very secret key.";
//! let iv = b"unique init vect";
//! let plaintext = b"The quick brown fox jumps over the lazy dog.";
//! let ciphertext = hex!("
//!     8f0cb6e8 9286cd02 09c95da4 fa663269
//!     9455b0bb e346b653 ec0d44aa bece8cc9
//!     f886df67 049d780d 9ccdf957
//! ");
//!
//! let mut buffer = plaintext.to_vec();
//! // create cipher instance
//! let mut cipher = AesOfb::new_var(key, iv).unwrap();
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, &ciphertext[..]);
//! // and decrypt it back
//! AesOfb::new_var(key, iv).unwrap().apply_keystream(&mut buffer);
//! assert_eq!(buffer, &plaintext[..]);
//!
//! // OFB mode can be used with streaming messages
//! let mut cipher = AesOfb::new_var(key, iv).unwrap();
//! for chunk in buffer.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buffer, &ciphertext[..]);
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#OFB
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher#Synchronous_stream_ciphers

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use stream_cipher;

use block_cipher::generic_array::typenum::Unsigned;
use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};
use stream_cipher::{InvalidKeyNonceLength, LoopError, NewStreamCipher, SyncStreamCipher};

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;

/// OFB self-synchronizing stream cipher instance.
pub struct Ofb<C: BlockCipher> {
    cipher: C,
    block: Block<C>,
    pos: usize,
}

impl<C> NewStreamCipher for Ofb<C>
where
    C: BlockCipher + NewBlockCipher,
{
    type KeySize = C::KeySize;
    type NonceSize = C::BlockSize;

    fn new(key: &GenericArray<u8, C::KeySize>, iv: &Block<C>) -> Self {
        let cipher = C::new(key);
        let mut block = iv.clone();
        cipher.encrypt_block(&mut block);
        Self {
            cipher,
            block,
            pos: 0,
        }
    }

    fn new_var(key: &[u8], iv: &[u8]) -> Result<Self, InvalidKeyNonceLength> {
        if Self::NonceSize::to_usize() != iv.len() {
            Err(InvalidKeyNonceLength)
        } else {
            let cipher = C::new_varkey(key).map_err(|_| InvalidKeyNonceLength)?;
            let mut block = GenericArray::clone_from_slice(iv);
            cipher.encrypt_block(&mut block);
            Ok(Self {
                cipher,
                block,
                pos: 0,
            })
        }
    }
}

impl<C: BlockCipher> SyncStreamCipher for Ofb<C> {
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        let bs = C::BlockSize::to_usize();
        if data.len() >= bs - self.pos {
            let (l, r) = { data }.split_at_mut(bs - self.pos);
            data = r;
            xor(l, &self.block[self.pos..]);
            self.cipher.encrypt_block(&mut self.block);
        } else {
            let n = data.len();
            xor(data, &self.block[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(());
        }

        let mut block = self.block.clone();
        while data.len() >= bs {
            let (l, r) = { data }.split_at_mut(bs);
            data = r;
            xor(l, &block);
            self.cipher.encrypt_block(&mut block);
        }
        self.block = block;
        let n = data.len();
        self.pos = n;
        xor(data, &self.block[..n]);
        Ok(())
    }
}

#[inline(always)]
fn xor(buf1: &mut [u8], buf2: &[u8]) {
    debug_assert_eq!(buf1.len(), buf2.len());
    for (a, b) in buf1.iter_mut().zip(buf2) {
        *a ^= *b;
    }
}
