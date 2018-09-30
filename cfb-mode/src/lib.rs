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
//! let plaintext = "The quick brown fox jumps over the lazy dog.";
//! let mut buffer = plaintext.as_bytes().to_vec();
//! // encrypt plaintext
//! AesCfb::new_var(key, iv).unwrap().encrypt(&mut buffer);
//! assert_eq!(buffer, &hex!("
//!     8f0cb6e8 9286cd02 09c95da4 fa663269
//!     bf7f286d 76820a4a f6cd3794 64cb6765
//!     8c764fa2 ce107f96 e1cf1dcd
//! ")[..]);
//! // and decrypt it back
//! AesCfb::new_var(key, iv).unwrap().decrypt(&mut buffer);
//! assert_eq!(buffer, plaintext.as_bytes());
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
use core::{mem, slice};

pub mod errors;

use errors::{InvalidKeyIvLength, InvalidMessageLength};

/// CFB self-synchronizing stream cipher instance.
pub struct Cfb<C: BlockCipher> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
type ParBlocks<C> = GenericArray<Block<C>, <C as BlockCipher>::ParBlocks>;
type Key<C> = GenericArray<u8, <C as BlockCipher>::KeySize>;

static EXPECT_MSG: &'static str = "buffer length is guaranteed to be correct";

impl<C: BlockCipher> Cfb<C> {
    /// Create a new CFB mode instance with generic array key and IV.
    pub fn new(key: &Key<C>, iv: &Block<C>) -> Self {
        Self {
            cipher: C::new(key),
            iv: iv.clone(),
        }
    }

    /// Create a new CFB mode instance with sliced key and IV.
    ///
    /// Returns an `InvalidKeyIvLength` error if key or IV have incorrect size.
    pub fn new_var(key: &[u8], iv: &[u8]) -> Result<Self, InvalidKeyIvLength> {
        let key_len = C::KeySize::to_usize();
        let iv_len = C::BlockSize::to_usize();
        if key.len() != key_len || iv.len() != iv_len {
            return Err(InvalidKeyIvLength);
        }
        Ok(Self {
            cipher: C::new(GenericArray::from_slice(key)),
            iv: GenericArray::clone_from_slice(iv),
        })
    }

    /// Encrypt message blocks.
    ///
    /// Length of the `buffer` must be multiple of the cipher block size. This
    /// method can be called repeatadly.
    pub fn encrypt_blocks(&mut self, mut buffer: &mut [u8])
        -> Result<(), InvalidMessageLength>
    {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 { return Err(InvalidMessageLength); }

        while buffer.len() >= bs {
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(&mut self.iv);
            xor(block, self.iv.as_slice());
            self.iv.clone_from_slice(block);
        }

        Ok(())
    }

    /// Decrypt message blocks.
    ///
    /// Length of the `buffer` must be multiple of the cipher block size. This
    /// method can be called repeatadly.
    pub fn decrypt_blocks(&mut self, mut buffer: &mut [u8])
        -> Result<(), InvalidMessageLength>
    {
        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();

        if buffer.len() % bs != 0 { return Err(InvalidMessageLength); }
        if buffer.len() == 0 { return Ok(()); }

        let bss = bs * pb;
        if pb != 1 && buffer.len() > bss {
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(&mut self.iv);
            let mut ga_blocks: ParBlocks<C> = unsafe {
                mem::transmute_copy(&*block.as_ptr())
            };
            xor(block, self.iv.as_slice());

            while buffer.len() >= bss {
                let (mut blocks, r) = { buffer }.split_at_mut(bss);
                buffer = r;

                self.cipher.encrypt_blocks(&mut ga_blocks);

                let (next_ga, ga_slice) = unsafe {
                    let p = blocks.as_ptr().offset((bss - bs) as isize);
                    let s = slice::from_raw_parts(
                        ga_blocks.as_ptr() as *mut u8,
                        bss,
                    );
                    (mem::transmute_copy(&*p), s)
                };

                xor(&mut blocks, ga_slice);
                ga_blocks = next_ga;
            }

            self.iv = ga_blocks[0].clone();
        }

        while buffer.len() >= bs {
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(&mut self.iv);
            let next_iv = GenericArray::clone_from_slice(block);
            xor(block, self.iv.as_slice());
            self.iv = next_iv;
        }

        Ok(())
    }

    /// Encrypt last message block.
    ///
    /// Length of the `buffer` must be less or equal to the cipher block size.
    pub fn encrypt_last(self, buffer: &mut [u8])
        -> Result<(), InvalidMessageLength>
    {
        let bs = C::BlockSize::to_usize();
        if buffer.len() > bs { return Err(InvalidMessageLength); }

        let mut iv = self.iv.clone();
        self.cipher.encrypt_block(&mut iv);
        for (a, b) in buffer.iter_mut().zip(iv.as_slice()) { *a ^= *b; }

        Ok(())
    }

    /// Decrypt last message block.
    ///
    /// Length of the `buffer` must be less or equal to the cipher block size.
    pub fn decrypt_last(self, buffer: &mut [u8])
        -> Result<(), InvalidMessageLength>
    {
        let bs = C::BlockSize::to_usize();
        if buffer.len() > bs { return Err(InvalidMessageLength); }

        let mut iv = self.iv.clone();
        self.cipher.encrypt_block(&mut iv);
        for (a, b) in buffer.iter_mut().zip(iv.as_slice()) { *a ^= *b; }

        Ok(())
    }

    /// Encrypt message.
    pub fn encrypt(mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        let n = bs * (buffer.len() / bs);
        let (blocks, last) = { buffer }.split_at_mut(n);
        self.encrypt_blocks(blocks).expect(EXPECT_MSG);
        self.encrypt_last(last).expect(EXPECT_MSG);
    }

    /// Decrypt message.
    pub fn decrypt(mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        let n = bs * (buffer.len() / bs);
        let (blocks, last) = { buffer }.split_at_mut(n);
        self.decrypt_blocks(blocks).expect(EXPECT_MSG);
        self.decrypt_last(last).expect(EXPECT_MSG);
    }
}

#[inline(always)]
fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) { *a ^= *b; }
}
