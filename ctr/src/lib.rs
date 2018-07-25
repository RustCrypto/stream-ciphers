#![no_std]
pub extern crate stream_cipher;
extern crate block_cipher_trait;

use stream_cipher::{
    StreamCipherCore, NewFixStreamCipher, StreamCipherSeek, LoopError
};

use block_cipher_trait::generic_array::{ArrayLength, GenericArray as GenArr};
use block_cipher_trait::generic_array::typenum::{U16, Unsigned};
use block_cipher_trait::BlockCipher;
use core::mem;

#[inline(always)]
pub fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

type Block<C> = GenArr<u8, <C as BlockCipher>::BlockSize>;
type Blocks<C> = GenArr<Block<C>, <C as BlockCipher>::ParBlocks>;

pub struct Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    cipher: C,
    nonce: [u64; 2],
    counter: u64,
    block: Block<C>,
    pos: Option<u8>,
}

#[inline(always)]
fn conv_be(val: [u64; 2]) -> [u64; 2] {
    [val[0].to_be(), val[1].to_be()]
}

#[inline(always)]
fn to_slice<C: BlockCipher>(blocks: &Blocks<C>) -> &[u8] {
    let blocks_len = C::BlockSize::to_usize()*C::ParBlocks::to_usize();
    unsafe {
        core::slice::from_raw_parts(
            blocks.as_ptr() as *const u8,
            blocks_len,
        )
    }
}

impl<C> NewFixStreamCipher for Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    type KeySize = C::KeySize;
    type NonceSize = C::BlockSize;

    fn new(key: &GenArr<u8, Self::KeySize>, nonce: &GenArr<u8, Self::NonceSize>)
        -> Self
    {
        assert!(Self::block_size() <= core::u8::MAX as usize);
        let nonce = conv_be(unsafe { mem::transmute_copy(nonce) });

        Self {
            cipher: C::new(key),
            nonce,
            counter: 0,
            block: Default::default(),
            pos: None,
        }
    }
}

impl<C> StreamCipherCore for Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8])
        -> Result<(), LoopError>
    {
        // xor with leftover bytes from the last call if any
        if let Some(pos) = self.pos {
            let pos = pos as usize;
            if data.len() >= Self::block_size() - pos {
                let buf = &self.block[pos..];
                let (r, l) = {data}.split_at_mut(buf.len());
                data = l;
                self.check_data_len(data)?;
                xor(r, buf);
                self.pos = None;
            } else {
                let buf = &self.block[pos..pos + data.len()];
                xor(data, buf);
                self.pos = Some((pos + data.len()) as u8);
                return Ok(());
            }
        } else {
            self.check_data_len(data)?;
        }

        let mut counter = self.counter;

        // Process blocks in parallel if cipher cupports it
        if C::ParBlocks::to_usize() != 1 {
            let pbs = Self::par_blocks_size();
            while data.len() >= pbs {
                let (l, r) = {data}.split_at_mut(pbs);
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
            let (l, r) = {data}.split_at_mut(bs);
            data = r;
            xor(l, &self.generate_block(counter));
            counter += 1;
        }

        if data.len() != 0 {
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

impl<C> StreamCipherSeek for Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    fn current_pos(&self) -> u64 {
        let bs = Self::block_size() as u64;
        match self.pos {
            Some(pos) => self.counter.wrapping_sub(1)*bs + pos as u64,
            None => self.counter*bs,
        }
    }

    fn seek(&mut self, pos: u64) {
        let bs = Self::block_size() as u64;
        let n = pos / bs;
        let l = (pos % bs) as u16;
        if l == 0 {
            self.counter = n;
            self.pos = None;
        } else {
            self.counter =  n.wrapping_add(1);
            self.block = self.generate_block(n);
            self.pos = Some(l as u8);
        }
    }
}

impl<C> Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    #[inline(always)]
    fn generate_par_blocks(&self, counter: u64) -> Blocks<C> {
        let mut block = self.nonce;
        block[1] = block[1].wrapping_add(counter);
        let mut blocks: Blocks<C> = unsafe { mem::uninitialized() };
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

    #[inline(always)]
    fn par_blocks_size() -> usize {
        C::BlockSize::to_usize()*C::ParBlocks::to_usize()
    }

    #[inline(always)]
    fn block_size() -> usize {
        C::BlockSize::to_usize()
    }

    #[inline(always)]
    fn par_blocks() -> u64 {
        C::ParBlocks::to_u64()
    }

    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        debug_assert_eq!(self.pos, None);
        let bs = Self::block_size();
        let mut data_blocks = data.len() / bs;
        if data.len() % bs != 0 { data_blocks += 1; }
        if self.counter.checked_add(data_blocks as u64).is_some() {
            Ok(())
        } else {
            Err(LoopError)
        }
    }
}
