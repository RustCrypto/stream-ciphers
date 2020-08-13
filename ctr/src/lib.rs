//! Generic implementation of CTR mode for block cipher with 128-bit block size.
//!
//! Mode functionality is accessed using traits from re-exported
//! [`stream-cipher`](https://docs.rs/stream-cipher) crate.
//!
//! # Security Warning
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Usage example
//! ```
//! use ctr::stream_cipher::generic_array::GenericArray;
//! use ctr::stream_cipher::{
//!     NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek
//! };
//!
//! // `aes` crate provides AES block cipher implementation
//! type Aes128Ctr = ctr::Ctr128<aes::Aes128>;
//!
//! # fn main() {
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
//! # }
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use stream_cipher;

use core::{cmp, convert::TryInto, fmt, mem};
use stream_cipher::block_cipher::{BlockCipher, NewBlockCipher};
use stream_cipher::generic_array::{
    typenum::{Unsigned, U16},
    ArrayLength, GenericArray,
};
use stream_cipher::{FromBlockCipher, LoopError, SyncStreamCipher, SyncStreamCipherSeek};

#[inline(always)]
fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
type Blocks<C> = GenericArray<Block<C>, <C as BlockCipher>::ParBlocks>;
type Nonce = GenericArray<u8, U16>;

/// CTR mode of operation for 128-bit block ciphers
pub struct Ctr128<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    cipher: C,
    nonce: [u64; 2],
    counter: u64,
    block: Block<C>,
    pos: Option<u8>,
}

impl<C> FromBlockCipher for Ctr128<C>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    type BlockCipher = C;
    type NonceSize = C::BlockSize;

    fn from_block_cipher(cipher: C, nonce: &Nonce) -> Self {
        Self {
            cipher,
            nonce: [
                u64::from_be_bytes(nonce[..8].try_into().unwrap()),
                u64::from_be_bytes(nonce[8..].try_into().unwrap()),
            ],
            counter: 0,
            block: Default::default(),
            pos: None,
        }
    }
}

impl<C> SyncStreamCipher for Ctr128<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        self.check_data_len(data)?;
        // xor with leftover bytes from the last call if any
        if let Some(pos) = self.pos {
            let pos = pos as usize;
            if data.len() >= Self::block_size() - pos {
                let buf = &self.block[pos..];
                let (r, l) = { data }.split_at_mut(buf.len());
                data = l;
                xor(r, buf);
                self.pos = None;
            } else {
                let buf = &self.block[pos..pos + data.len()];
                xor(data, buf);
                self.pos = Some((pos + data.len()) as u8);
                return Ok(());
            }
        }

        let mut counter = self.counter;

        // Process blocks in parallel if cipher supports it
        if C::ParBlocks::to_usize() != 1 {
            let pbs = Self::par_blocks_size();
            while data.len() >= pbs {
                let (l, r) = { data }.split_at_mut(pbs);
                data = r;
                let blocks = self.generate_par_blocks(counter);
                counter += Self::par_blocks();
                xor(l, to_slice::<C>(&blocks));
            }
            self.counter = counter;
        }

        // Process one block at a type
        let bs = Self::block_size();
        while data.len() >= bs {
            let (l, r) = { data }.split_at_mut(bs);
            data = r;
            xor(l, &self.generate_block(counter));
            counter += 1;
        }

        if !data.is_empty() {
            self.block = self.generate_block(counter);
            counter += 1;
            let n = data.len();
            xor(data, &self.block[..n]);
            self.pos = Some(n as u8);
        }

        self.counter = counter;

        Ok(())
    }
}

impl<C> SyncStreamCipherSeek for Ctr128<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    fn current_pos(&self) -> u64 {
        let bs = Self::block_size() as u64;
        match self.pos {
            Some(pos) => self.counter.wrapping_sub(1) * bs + u64::from(pos),
            None => self.counter * bs,
        }
    }

    fn seek(&mut self, pos: u64) {
        let bs = Self::block_size() as u64;
        self.counter = pos / bs;
        let l = (pos % bs) as u16;
        if l == 0 {
            self.pos = None;
        } else {
            self.block = self.generate_block(self.counter);
            self.counter += 1;
            self.pos = Some(l as u8);
        }
    }
}

impl<C> Ctr128<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    #[inline(always)]
    fn generate_par_blocks(&self, counter: u64) -> Blocks<C> {
        let mut block = self.nonce;
        block[1] = block[1].wrapping_add(counter);
        let mut blocks: Blocks<C> = unsafe { mem::zeroed() };
        for b in blocks.iter_mut() {
            let block_be = conv_be(block);
            *b = unsafe { mem::transmute_copy(&block_be) };
            block[1] = block[1].wrapping_add(1);
        }

        self.cipher.encrypt_blocks(&mut blocks);

        blocks
    }

    #[inline(always)]
    fn generate_block(&self, counter: u64) -> Block<C> {
        let mut block = self.nonce;
        block[1] = block[1].wrapping_add(counter);
        let mut block: Block<C> = unsafe { mem::transmute(conv_be(block)) };
        self.cipher.encrypt_block(&mut block);
        block
    }

    fn par_blocks_size() -> usize {
        C::BlockSize::to_usize() * C::ParBlocks::to_usize()
    }

    fn block_size() -> usize {
        C::BlockSize::to_usize()
    }

    fn par_blocks() -> u64 {
        C::ParBlocks::to_u64()
    }

    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let bs = Self::block_size();
        let dlen = data.len()
            - match self.pos {
                Some(pos) => cmp::min(bs - pos as usize, data.len()),
                None => 0,
            };
        let data_blocks = dlen / bs + if data.len() % bs != 0 { 1 } else { 0 };
        if self.counter.checked_add(data_blocks as u64).is_some() {
            Ok(())
        } else {
            Err(LoopError)
        }
    }
}

impl<C> fmt::Debug for Ctr128<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Ctr128 {{ .. }}")
    }
}

#[inline(always)]
fn conv_be(val: [u64; 2]) -> [u64; 2] {
    [val[0].to_be(), val[1].to_be()]
}

#[inline(always)]
fn to_slice<C: BlockCipher>(blocks: &Blocks<C>) -> &[u8] {
    let blocks_len = C::BlockSize::to_usize() * C::ParBlocks::to_usize();
    unsafe { core::slice::from_raw_parts(blocks.as_ptr() as *const u8, blocks_len) }
}
