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

use core::{convert::TryInto, fmt, mem};
use stream_cipher::{
    block_cipher::{BlockCipher, NewBlockCipher},
    generic_array::{
        typenum::{Unsigned, U16},
        ArrayLength, GenericArray,
    },
    FromBlockCipher, LoopError, OverflowError, SeekNum, SyncStreamCipher, SyncStreamCipherSeek,
};

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
    block: Block<C>,
    nonce: [u64; 2],
    counter: u64,
    pos: u8,
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
            pos: 0,
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
        let bs = C::BlockSize::USIZE;
        let pos = self.pos as usize;
        debug_assert!(bs > pos);

        let mut counter = self.counter;
        if pos != 0 {
            if data.len() < bs - pos {
                let n = pos + data.len();
                xor(data, &self.block[pos..n]);
                self.pos = n as u8;
                return Ok(());
            } else {
                let (l, r) = data.split_at_mut(bs - pos);
                data = r;
                xor(l, &self.block[pos..]);
                counter += 1;
            }
        }

        // Process blocks in parallel if cipher supports it
        let pb = C::ParBlocks::USIZE;
        let data = if pb != 1 {
            let mut chunks = data.chunks_exact_mut(bs * pb);
            for chunk in &mut chunks {
                let blocks = self.generate_par_blocks(counter);
                counter += pb as u64;
                xor(chunk, to_slice::<C>(&blocks));
            }
            chunks.into_remainder()
        } else {
            data
        };

        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            xor(chunk, &self.generate_block(counter));
            counter += 1;
        }

        let rem = chunks.into_remainder();
        self.pos = rem.len() as u8;
        self.counter = counter;
        if rem.len() != 0 {
            self.block = self.generate_block(counter);
            xor(rem, &self.block[..rem.len()]);
        }

        Ok(())
    }
}

impl<C> SyncStreamCipherSeek for Ctr128<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
        T::from_block_byte(self.counter, self.pos, C::BlockSize::U8)
    }

    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError> {
        let res = pos.to_block_byte(C::BlockSize::U8)?;
        self.block = self.generate_block(res.0);
        self.counter = res.0;
        self.pos = res.1;
        Ok(())
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

    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let bs = C::BlockSize::USIZE;
        let leftover_bytes = bs - self.pos as usize;
        if data.len() < leftover_bytes {
            return Ok(());
        }
        let blocks = 1 + (data.len() - leftover_bytes) / bs;
        self.counter
            .checked_add(blocks as u64)
            .ok_or(LoopError)
            .map(|_| ())
    }
}

impl<C> fmt::Debug for Ctr128<C>
where
    C: BlockCipher<BlockSize = U16> + fmt::Debug,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Ctr128-{:?}", self.cipher)
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
