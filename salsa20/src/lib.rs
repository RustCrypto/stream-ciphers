extern crate block_cipher_trait;
extern crate salsa20_core;
extern crate stream_cipher;

#[cfg(cargo_feature = "zeroize")]
extern crate zeroize;

use block_cipher_trait::generic_array::typenum::{U32, U8};
use block_cipher_trait::generic_array::GenericArray;
use stream_cipher::{NewStreamCipher, StreamCipher, SyncStreamCipherSeek};

#[cfg(cargo_feature = "zeroize")]
use zeroize::Zeroize;

use salsa20_core::{SalsaFamilyCipher, SalsaFamilyState};

/// Wrapper state for Salsa-type ciphers
struct SalsaState {
    state: SalsaFamilyState,
}

/// The Salsa20 cipher.
pub struct Salsa20 {
    state: SalsaState,
}

impl SalsaState {
    #[inline]
    fn double_round(&mut self) {
        let block = &mut self.state.block;
        let mut t: u32;

        t = block[0].wrapping_add(block[12]);
        block[4] ^= t.rotate_left(7) as u32;
        t = block[5].wrapping_add(block[1]);
        block[9] ^= t.rotate_left(7) as u32;
        t = block[10].wrapping_add(block[6]);
        block[14] ^= t.rotate_left(7) as u32;
        t = block[15].wrapping_add(block[11]);
        block[3] ^= t.rotate_left(7) as u32;

        t = block[4].wrapping_add(block[0]);
        block[8] ^= t.rotate_left(9) as u32;
        t = block[9].wrapping_add(block[5]);
        block[13] ^= t.rotate_left(9) as u32;
        t = block[14].wrapping_add(block[10]);
        block[2] ^= t.rotate_left(9) as u32;
        t = block[3].wrapping_add(block[15]);
        block[7] ^= t.rotate_left(9) as u32;

        t = block[8].wrapping_add(block[4]);
        block[12] ^= t.rotate_left(13) as u32;
        t = block[13].wrapping_add(block[9]);
        block[1] ^= t.rotate_left(13) as u32;
        t = block[2].wrapping_add(block[14]);
        block[6] ^= t.rotate_left(13) as u32;
        t = block[7].wrapping_add(block[3]);
        block[11] ^= t.rotate_left(13) as u32;

        t = block[12].wrapping_add(block[8]);
        block[0] ^= t.rotate_left(18) as u32;
        t = block[1].wrapping_add(block[13]);
        block[5] ^= t.rotate_left(18) as u32;
        t = block[6].wrapping_add(block[2]);
        block[10] ^= t.rotate_left(18) as u32;
        t = block[11].wrapping_add(block[7]);
        block[15] ^= t.rotate_left(18) as u32;

        t = block[0].wrapping_add(block[3]);
        block[1] ^= t.rotate_left(7) as u32;
        t = block[5].wrapping_add(block[4]);
        block[6] ^= t.rotate_left(7) as u32;
        t = block[10].wrapping_add(block[9]);
        block[11] ^= t.rotate_left(7) as u32;
        t = block[15].wrapping_add(block[14]);
        block[12] ^= t.rotate_left(7) as u32;

        t = block[1].wrapping_add(block[0]);
        block[2] ^= t.rotate_left(9) as u32;
        t = block[6].wrapping_add(block[5]);
        block[7] ^= t.rotate_left(9) as u32;
        t = block[11].wrapping_add(block[10]);
        block[8] ^= t.rotate_left(9) as u32;
        t = block[12].wrapping_add(block[15]);
        block[13] ^= t.rotate_left(9) as u32;

        t = block[2].wrapping_add(block[1]);
        block[3] ^= t.rotate_left(13) as u32;
        t = block[7].wrapping_add(block[6]);
        block[4] ^= t.rotate_left(13) as u32;
        t = block[8].wrapping_add(block[11]);
        block[9] ^= t.rotate_left(13) as u32;
        t = block[13].wrapping_add(block[12]);
        block[14] ^= t.rotate_left(13) as u32;

        t = block[3].wrapping_add(block[2]);
        block[0] ^= t.rotate_left(18) as u32;
        t = block[4].wrapping_add(block[7]);
        block[5] ^= t.rotate_left(18) as u32;
        t = block[9].wrapping_add(block[8]);
        block[10] ^= t.rotate_left(18) as u32;
        t = block[14].wrapping_add(block[13]);
        block[15] ^= t.rotate_left(18) as u32;
    }

    #[inline]
    fn init_block(&mut self) {
        let block = &mut self.state.block;
        let iv = self.state.iv;
        let key = self.state.key;
        let block_idx = self.state.block_idx;

        block[0] = 0x61707865;
        block[1] = key[0];
        block[2] = key[1];
        block[3] = key[2];
        block[4] = key[3];
        block[5] = 0x3320646e;
        block[6] = iv[0];
        block[7] = iv[1];
        block[8] = (block_idx & 0xffffffff) as u32;
        block[9] = ((block_idx >> 32) & 0xffffffff) as u32;
        block[10] = 0x79622d32;
        block[11] = key[4];
        block[12] = key[5];
        block[13] = key[6];
        block[14] = key[7];
        block[15] = 0x6b206574;
    }

    #[inline]
    fn add_block(&mut self) {
        let block = &mut self.state.block;
        let iv = self.state.iv;
        let key = self.state.key;
        let block_idx = self.state.block_idx;

        block[0] = block[0].wrapping_add(0x61707865);
        block[1] = block[1].wrapping_add(key[0]);
        block[2] = block[2].wrapping_add(key[1]);
        block[3] = block[3].wrapping_add(key[2]);
        block[4] = block[4].wrapping_add(key[3]);
        block[5] = block[5].wrapping_add(0x3320646e);
        block[6] = block[6].wrapping_add(iv[0]);
        block[7] = block[7].wrapping_add(iv[1]);
        block[8] = block[8].wrapping_add((block_idx & 0xffffffff) as u32);
        block[9] = block[9].wrapping_add(((block_idx >> 32) & 0xffffffff) as u32);
        block[10] = block[10].wrapping_add(0x79622d32);
        block[11] = block[11].wrapping_add(key[4]);
        block[12] = block[12].wrapping_add(key[5]);
        block[13] = block[13].wrapping_add(key[6]);
        block[14] = block[14].wrapping_add(key[7]);
        block[15] = block[15].wrapping_add(0x6b206574);
    }
}

impl Salsa20 {
    #[inline]
    fn rounds(&mut self) {
        self.state.double_round();
        self.state.double_round();
        self.state.double_round();
        self.state.double_round();
        self.state.double_round();

        self.state.double_round();
        self.state.double_round();
        self.state.double_round();
        self.state.double_round();
        self.state.double_round();
    }

    fn gen_block(&mut self) {
        self.state.init_block();
        self.rounds();
        self.state.add_block();
    }
}

impl NewStreamCipher for SalsaState {
    /// Key size in bytes
    type KeySize = U32;
    /// Nonce size in bytes
    type NonceSize = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        SalsaState {
            state: SalsaFamilyState::new(key, iv),
        }
    }
}

impl SyncStreamCipherSeek for SalsaState {
    fn current_pos(&self) -> u64 {
        self.state.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.state.seek(pos);
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Zeroize for SalsaState {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl SalsaFamilyCipher for Salsa20 {
    #[inline]
    fn next_block(&mut self) {
        self.state.state.block_idx += 1;
        self.gen_block();
    }

    #[inline]
    fn offset(&self) -> usize {
        self.state.state.offset
    }

    #[inline]
    fn set_offset(&mut self, offset: usize) {
        self.state.state.offset = offset;
    }

    #[inline]
    fn block_word(&self, idx: usize) -> u32 {
        self.state.state.block[idx]
    }
}

impl NewStreamCipher for Salsa20 {
    /// Key size in bytes
    type KeySize = U32;
    /// Nonce size in bytes
    type NonceSize = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut out = Salsa20 {
            state: SalsaState::new(key, iv),
        };

        out.gen_block();

        out
    }
}

impl SyncStreamCipherSeek for Salsa20 {
    fn current_pos(&self) -> u64 {
        self.state.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.state.seek(pos);
        self.gen_block();
    }
}

impl StreamCipher for Salsa20 {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.process(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.process(data);
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Zeroize for Salsa20 {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}
