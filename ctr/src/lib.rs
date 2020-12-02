//! Generic implementations of CTR mode for block ciphers.
//!
//! Mode functionality is accessed using traits from re-exported
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # ⚠️ Security Warning: [Hazmat!]
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # `Ctr128` Usage Example
//!
//! ```
//! use ctr::cipher::stream::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
//!
//! // `aes` crate provides AES block cipher implementation
//! type Aes128Ctr = ctr::Ctr128<aes::Aes128>;
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = b"very secret key.";
//! let nonce = b"and secret nonce";
//!
//! // create cipher instance
//! let mut cipher = Aes128Ctr::new(key.into(), nonce.into());
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [6, 245, 126, 124, 180, 146, 37]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```
//!
//! [Hazmat!]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;
use cipher::{
    block::{Block, BlockCipher, ParBlocks},
    generic_array::{ArrayLength, GenericArray},
    generic_array::typenum::{Unsigned, Quot},
    stream::{FromBlockCipher, LoopError, SyncStreamCipher, SeekNum, SyncStreamCipherSeek, OverflowError},
};
use core::fmt;
use core::ops::Div;

pub mod flavors;
use flavors::CtrFlavor;

/// Generic CTR block mode isntance.
pub struct Ctr<B, F>
where
    B: BlockCipher,
    B::BlockSize: Div<F::Size>,
    Quot<B::BlockSize, F::Size>: ArrayLength<F>,
    F: CtrFlavor,
{
    cipher: B,
    nonce: GenericArray<F, Quot<B::BlockSize, F::Size>>,
    counter: F,
    buffer: Block<B>,
    buf_pos: u8,
}

impl<B, F> Ctr<B, F>
where
    B: BlockCipher,
    B::BlockSize: Div<F::Size>,
    Quot<B::BlockSize, F::Size>: ArrayLength<F>,
    F: CtrFlavor,
{
    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let bs = B::BlockSize::USIZE;
        let leftover_bytes = bs - self.buf_pos as usize;
        if data.len() < leftover_bytes {
            return Ok(());
        }
        let blocks = 1 + (data.len() - leftover_bytes) / bs;
        self.counter
            .checked_add(blocks)
            .ok_or(LoopError)
            .map(|_| ())
    }
}

impl<B, F> FromBlockCipher for Ctr<B, F>
where
    B: BlockCipher,
    B::BlockSize: Div<F::Size>,
    Quot<B::BlockSize, F::Size>: ArrayLength<F>,
    F: CtrFlavor,
{
    type BlockCipher = B;
    type NonceSize = B::BlockSize;

    #[inline]
    fn from_block_cipher(cipher: B, nonce: &Block<B>) -> Self {
        let nonce = F::load(nonce);
        Self {
            cipher,
            buffer: Default::default(),
            nonce,
            counter: Default::default(),
            buf_pos: 0,
        }
    }
}


impl<B, F> SyncStreamCipher for Ctr<B, F>
where
    B: BlockCipher,
    B::BlockSize: Div<F::Size>,
    Quot<B::BlockSize, F::Size>: ArrayLength<F>,
    F: CtrFlavor,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        self.check_data_len(data)?;
        let bs = B::BlockSize::USIZE;
        let pos = self.buf_pos as usize;
        debug_assert!(bs > pos);

        let mut counter = self.counter;
        if pos != 0 {
            if data.len() < bs - pos {
                let n = pos + data.len();
                xor(data, &self.buffer[pos..n]);
                self.buf_pos = n as u8;
                return Ok(());
            } else {
                let (l, r) = data.split_at_mut(bs - pos);
                data = r;
                xor(l, &self.buffer[pos..]);
                counter.increment();
            }
        }
        
        // Process blocks in parallel if cipher supports it
        let pb = B::ParBlocks::USIZE;
        if pb != 1 {
            let mut chunks = data.chunks_exact_mut(bs * pb);
            let mut blocks: ParBlocks<B> = Default::default();
            for chunk in &mut chunks {
                for b in blocks.iter_mut() {
                    *b = counter.generate_block(&self.nonce);
                    counter.increment();
                }

                self.cipher.encrypt_blocks(&mut blocks);
                xor(chunk, to_slice::<B>(&blocks));
            }
            data = chunks.into_remainder();
        }

        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            let mut block = counter.generate_block(&self.nonce);
            counter.increment();
            self.cipher.encrypt_block(&mut block);
            xor(chunk, &block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let mut block = counter.generate_block(&self.nonce);
            counter.increment();
            self.cipher.encrypt_block(&mut block);
            xor(rem, &self.buffer[..rem.len()]);
        }
        self.buf_pos = rem.len() as u8;
        self.counter = counter;
        Ok(())
    }
}

impl<B, F> SyncStreamCipherSeek for Ctr<B, F>
where
    B: BlockCipher,
    B::BlockSize: Div<F::Size>,
    Quot<B::BlockSize, F::Size>: ArrayLength<F>,
    F: CtrFlavor,
{
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
        let c = F::Backend::from(self.counter);
        T::from_block_byte(c, self.buf_pos, B::BlockSize::U8)
    }

    fn try_seek<S: SeekNum>(&mut self, pos: S) -> Result<(), LoopError> {
        let res: (F::Backend, u8) = pos.to_block_byte(B::BlockSize::U8)?;
        self.counter = res.0.into();
        self.buf_pos = res.1;
        if self.buf_pos != 0 {
            let mut block = self.counter.generate_block(&self.nonce);
            self.counter.increment();
            self.cipher.encrypt_block(&mut block);
            self.buffer = block;
        }
        Ok(())
    }
}

impl<B, F> fmt::Debug for Ctr<B, F>
where
    B: BlockCipher + fmt::Debug,
    B::BlockSize: Div<F::Size>,
    Quot<B::BlockSize, F::Size>: ArrayLength<F>,
    F: CtrFlavor + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Ctr-{:?}-{:?}", self.counter, self.cipher)
    }
}

#[inline(always)]
fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

#[inline(always)]
fn to_slice<C: BlockCipher>(blocks: &ParBlocks<C>) -> &[u8] {
    let blocks_len = C::BlockSize::to_usize() * C::ParBlocks::to_usize();
    unsafe { core::slice::from_raw_parts(blocks.as_ptr() as *const u8, blocks_len) }
}
