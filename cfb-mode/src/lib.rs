//! Generic [Cipher Feedback (CFB)][1] mode implementation.
//!
//! This crate implements CFB as a [self-synchronizing stream cipher][2].
//! 
//! # Warning
//! This crate does not provide any authentification! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Examples
//! ```
//! extern crate aes;
//! extern crate cfb_mode;
//! #[macro_use] extern crate hex_literal;
//! 
//! use aes::Aes128;
//! use cfb_mode::Cfb;
//! 
//! type AesCfb = Cfb<Aes128>;
//! 
//! let key = b"very secret key.";
//! let iv = b"unique init vect";
//! let plaintext = b"The quick brown fox jumps over the lazy dog.";
//! let ciphertext = hex!("
//!     8f0cb6e8 9286cd02 09c95da4 fa663269
//!     bf7f286d 76820a4a f6cd3794 64cb6765
//!     8c764fa2 ce107f96 e1cf1dcd
//! ");
//!
//! let mut buffer = plaintext.to_vec();
//! // encrypt plaintext
//! AesCfb::new_var(key, iv).unwrap().encrypt(&mut buffer);
//! assert_eq!(buffer, &ciphertext[..]);
//! // and decrypt it back
//! AesCfb::new_var(key, iv).unwrap().decrypt(&mut buffer);
//! assert_eq!(buffer, &plaintext[..]);
//!
//! // CFB mode can be used with streaming messages
//! let mut cipher = AesCfb::new_var(key, iv).unwrap();
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
use core::slice;

mod errors;

pub use errors::InvalidKeyIvLength;

/// CFB self-synchronizing stream cipher instance.
pub struct Cfb<C: BlockCipher> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    pos: usize,
}

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
type ParBlocks<C> = GenericArray<Block<C>, <C as BlockCipher>::ParBlocks>;
type Key<C> = GenericArray<u8, <C as BlockCipher>::KeySize>;

impl<C: BlockCipher> Cfb<C> {
    /// Create a new CFB mode instance with generic array key and IV.
    pub fn new(key: &Key<C>, iv: &Block<C>) -> Self {
        let cipher = C::new(key);
        let mut iv = iv.clone();
        cipher.encrypt_block(&mut iv);
        Self { cipher, iv, pos: 0 }
    }

    /// Create a new CFB mode instance with sliced key and IV.
    ///
    /// Returns an `InvalidKeyIvLength` error if key or IV have incorrect size.
    pub fn new_var(key: &[u8], iv: &[u8]) -> Result<Self, InvalidKeyIvLength> {
        if iv.len() != C::BlockSize::to_usize() {
            return Err(InvalidKeyIvLength);
        }
        let cipher = C::new_varkey(key).map_err(|_| InvalidKeyIvLength)?;
        let mut iv = GenericArray::clone_from_slice(iv);
        cipher.encrypt_block(&mut iv);
        Ok(Self { cipher, iv, pos: 0 })
    }

    /// Encrypt data.
    pub fn encrypt(&mut self, mut buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();

        if buffer.len() < bs - self.pos {
            xor_set1(buffer, &mut self.iv[self.pos..]);
            self.pos += buffer.len();
            return;
        } else {
            let (left, right) = { buffer }.split_at_mut(bs - self.pos);
            buffer = right;
            xor_set1(left, &mut self.iv[self.pos..]);
            self.cipher.encrypt_block(&mut self.iv);
        }

        while buffer.len() >= bs {
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            xor_set1(block, self.iv.as_mut_slice());
            self.cipher.encrypt_block(&mut self.iv);
        }

        xor_set1(buffer, self.iv.as_mut_slice());
        self.pos = buffer.len();
    }

    /// Decrypt data.
    pub fn decrypt(&mut self, mut buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();

        if buffer.len() < bs - self.pos {
            xor_set2(buffer, &mut self.iv[self.pos..]);
            self.pos += buffer.len();
            return;
        } else {
            let (left, right) = { buffer }.split_at_mut(bs - self.pos);
            buffer = right;
            xor_set2(left, &mut self.iv[self.pos..]);
            self.cipher.encrypt_block(&mut self.iv);
        }

        let bss = bs * pb;
        if pb != 1 && buffer.len() >= bss {
            let mut iv_blocks: ParBlocks<C> = unsafe {
                (&*(buffer.as_ptr() as *const ParBlocks<C>)).clone()
            };
            self.cipher.encrypt_blocks(&mut iv_blocks);
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            xor(block, self.iv.as_slice());

            while buffer.len() >= 2*bss - bs {
                let (blocks, r) = { buffer }.split_at_mut(bss);
                buffer = r;
                let mut next_iv_blocks: ParBlocks<C> = unsafe {
                    let ptr = buffer.as_ptr().offset(- (bs as isize));
                    (&*(ptr as *const ParBlocks<C>)).clone()
                };
                self.cipher.encrypt_blocks(&mut next_iv_blocks);

                xor(blocks, unsafe {
                    let ptr = iv_blocks.as_mut_ptr() as *mut u8;
                    slice::from_raw_parts(ptr, bss)
                });
                iv_blocks = next_iv_blocks;
            }

            let n = pb - 1;
            let (blocks, r) = { buffer }.split_at_mut(n*bs);
            buffer = r;
            let chunks = blocks.chunks_mut(bs);
            for (iv, block) in iv_blocks[..n].iter().zip(chunks) {
                xor(block, iv.as_slice())
            }
            self.iv = iv_blocks[n].clone();
        }

        while buffer.len() >= bs {
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            xor_set2(block, self.iv.as_mut_slice());
            self.cipher.encrypt_block(&mut self.iv);
        }

        xor_set2(buffer, self.iv.as_mut_slice());
        self.pos = buffer.len();
    }
}

#[inline(always)]
fn xor(buf1: &mut [u8], buf2: &[u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        *a ^= *b;
    }
}

#[inline(always)]
fn xor_set1(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a ^ *b;
        *a = t;
        *b = t;
    }
}

#[inline(always)]
fn xor_set2(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a;
        *a ^= *b;
        *b = t;
    }
}
