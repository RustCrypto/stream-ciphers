#![no_std]
extern crate stream_cipher;
extern crate block_cipher_trait;

use stream_cipher::StreamCipherCore;

use block_cipher_trait::generic_array::{ArrayLength, GenericArray as GenArr};
use block_cipher_trait::generic_array::typenum::{U16, Unsigned};
use block_cipher_trait::BlockCipher;
use core::mem;

#[inline(always)]
pub fn xor(buf: &mut [u8], key: &[u8]) {
    assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

type Blocks<C> = GenArr<
    GenArr<u8, <C as BlockCipher>::BlockSize>, <C as BlockCipher>::ParBlocks>;

pub struct Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    cipher: C,
    nonce: [u64; 2],
    counter: u64,
    // keystream in blocks should be xor-able with data
    blocks: Blocks<C>,
    pos: usize,
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

// replace with trait
impl<C> Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{
    pub fn new(key: &GenArr<u8, C::KeySize>, nonce: &GenArr<u8, C::BlockSize>)
        -> Self
    {
        let nonce = conv_be(unsafe { mem::transmute_copy(nonce) });

        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();

        Self {
            cipher: C::new(key),
            nonce,
            counter: 0,
            blocks: Default::default(),
            pos: bs*pb, // this means that `blocks` are exhausted
        }
    }
}

impl<C> Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{

    #[inline(always)]
    fn generate_blocks(&self, counter: u64) -> Blocks<C> {
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
    fn blocks_slice(&self) -> &[u8] {
        to_slice::<C>(&self.blocks)
    }

    #[inline(always)]
    fn leftover(&self) -> usize {
        Self::blocks_len() - self.pos
    }

    #[inline(always)]
    fn blocks_len() -> usize {
        C::BlockSize::to_usize()*C::ParBlocks::to_usize()
    }

    #[inline(always)]
    fn par_blocks() -> u64 {
        C::ParBlocks::to_u64()
    }
}

impl<C> StreamCipherCore for Ctr128<C>
    where
        C: BlockCipher<BlockSize = U16>,
        C::ParBlocks: ArrayLength<GenArr<u8, U16>>,
{

    fn apply_keystream(&mut self, mut data: &mut [u8]) {
        let leftover = self.leftover();
        if leftover > 0 {
            if data.len() <= leftover {
                let range = self.pos..self.pos+data.len();
                xor(data, &self.blocks_slice()[range]);
                self.pos += data.len();
                return;
            } else {
                let (l, r) = {data}.split_at_mut(leftover);
                data = r;
                xor(l, &self.blocks_slice()[self.pos..]);
            }
        }

        let bsl = Self::blocks_len();
        let mut counter = self.counter;

        while data.len() >= bsl {
            let (l, r) = {data}.split_at_mut(bsl);
            data = r;
            xor(l, to_slice::<C>(&self.generate_blocks(counter)));
            counter += Self::par_blocks();
        }

        // we assume that `data.len() < u64::MAX`
        if self.counter > counter { panic!("counter overflow in CTR mode"); }
        self.counter = counter;
        self.pos = bsl;

        if data.len() > 0 {
            self.blocks = self.generate_blocks(self.counter);
            self.counter = self.counter.checked_add(Self::par_blocks())
                .expect("counter overflow in CTR mode");
            self.pos = data.len();
            xor(data, &self.blocks_slice()[..self.pos])
        }
    }
}
