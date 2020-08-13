//! Generic [Cipher Feedback (CFB)][1] mode implementation.
//!
//! This crate implements CFB as a [self-synchronizing stream cipher][2].
//!
//! # Security Warning
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Examples
//! ```
//! use aes::Aes128;
//! use cfb_mode::Cfb;
//! use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};
//! use hex_literal::hex;
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
//! let mut data = plaintext.to_vec();
//! // encrypt plaintext
//! AesCfb::new_var(key, iv).unwrap().encrypt(&mut data);
//! assert_eq!(data, &ciphertext[..]);
//! // and decrypt it back
//! AesCfb::new_var(key, iv).unwrap().decrypt(&mut data);
//! assert_eq!(data, &plaintext[..]);
//!
//! // CFB mode can be used with streaming messages
//! let mut cipher = AesCfb::new_var(key, iv).unwrap();
//! for chunk in data.chunks_mut(3) {
//!     cipher.encrypt(chunk);
//! }
//! assert_eq!(data, &ciphertext[..]);
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher#Self-synchronizing_stream_ciphers

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use stream_cipher;

use stream_cipher::generic_array::typenum::Unsigned;
use stream_cipher::generic_array::GenericArray;
use stream_cipher::block_cipher::{BlockCipher, NewBlockCipher};
use core::slice;
use stream_cipher::{FromBlockCipher, StreamCipher};

/// CFB self-synchronizing stream cipher instance.
pub struct Cfb<C: BlockCipher> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    pos: usize,
}

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
type ParBlocks<C> = GenericArray<Block<C>, <C as BlockCipher>::ParBlocks>;

impl<C> FromBlockCipher for Cfb<C>
where
    C: BlockCipher + NewBlockCipher,
{
    type BlockCipher = C;
    type NonceSize = C::BlockSize;

    fn from_block_cipher(cipher: C, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut iv = iv.clone();
        cipher.encrypt_block(&mut iv);
        Self { cipher, iv, pos: 0 }
    }
}

impl<C: BlockCipher> StreamCipher for Cfb<C> {
    fn encrypt(&mut self, mut data: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let n = data.len();

        if n < bs - self.pos {
            xor_set1(data, &mut self.iv[self.pos..self.pos + n]);
            self.pos += n;
            return;
        }

        let (left, right) = { data }.split_at_mut(bs - self.pos);
        data = right;
        let mut iv = self.iv.clone();
        xor_set1(left, &mut iv[self.pos..]);
        self.cipher.encrypt_block(&mut iv);

        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            xor_set1(chunk, iv.as_mut_slice());
            self.cipher.encrypt_block(&mut iv);
        }

        let rem = chunks.into_remainder();
        xor_set1(rem, iv.as_mut_slice());
        self.pos = rem.len();
        self.iv = iv;
    }

    fn decrypt(&mut self, mut data: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();
        let n = data.len();

        if n < bs - self.pos {
            xor_set2(data, &mut self.iv[self.pos..self.pos + n]);
            self.pos += n;
            return;
        }
        let (left, right) = { data }.split_at_mut(bs - self.pos);
        data = right;
        let mut iv = self.iv.clone();
        xor_set2(left, &mut iv[self.pos..]);
        self.cipher.encrypt_block(&mut iv);

        let bss = bs * pb;
        if pb != 1 && data.len() >= bss {
            let mut iv_blocks: ParBlocks<C> =
                unsafe { (&*(data.as_ptr() as *const ParBlocks<C>)).clone() };
            self.cipher.encrypt_blocks(&mut iv_blocks);
            let (block, r) = { data }.split_at_mut(bs);
            data = r;
            xor(block, iv.as_slice());

            while data.len() >= 2 * bss - bs {
                let (blocks, r) = { data }.split_at_mut(bss);
                data = r;
                let mut next_iv_blocks: ParBlocks<C> = unsafe {
                    let ptr = data.as_ptr().offset(-(bs as isize));
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
            let (blocks, r) = { data }.split_at_mut(n * bs);
            data = r;
            let chunks = blocks.chunks_mut(bs);
            for (iv, block) in iv_blocks[..n].iter().zip(chunks) {
                xor(block, iv.as_slice())
            }
            iv = iv_blocks[n].clone();
        }


        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            xor_set2(chunk, iv.as_mut_slice());
            self.cipher.encrypt_block(&mut iv);
        }

        let rem = chunks.into_remainder();
        xor_set2(rem, iv.as_mut_slice());
        self.pos = rem.len();
        self.iv = iv;
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
