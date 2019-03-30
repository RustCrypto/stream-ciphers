use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::U32;
use stream_cipher::NewStreamCipher;
use stream_cipher::StreamCipher;
use stream_cipher::SyncStreamCipherSeek;
use zeroize::Zeroize;

use salsa_family_state::SalsaFamilyState;
use salsa_family_state::SalsaFamilyCipher;

pub struct ChaChaState {
    state: SalsaFamilyState
}

pub struct ChaCha20 {
    state: ChaChaState
}

#[inline]
fn quarter_round(a: usize, b: usize, c: usize, d: usize,
                 block: &mut [u32; 16]) {
    block[a] = block[a].wrapping_add(block[b]);
    block[d] ^= block[a];
    block[d] = block[d].rotate_left(16);

    block[c] = block[c].wrapping_add(block[d]);
    block[b] ^= block[c];
    block[b] = block[b].rotate_left(12);

    block[a] = block[a].wrapping_add(block[b]);
    block[d] ^= block[a];
    block[d] = block[d].rotate_left(8);

    block[c] = block[c].wrapping_add(block[d]);
    block[b] ^= block[c];
    block[b] = block[b].rotate_left(7);
}

impl ChaChaState {
    #[inline]
    fn double_round(&mut self) {
        let block = &mut self.state.block;

        quarter_round(0, 4, 8, 12, block);
        quarter_round(1, 5, 9, 13, block);
        quarter_round(2, 6, 10, 14, block);
        quarter_round(3, 7, 11, 15, block);
        quarter_round(0, 5, 10, 15, block);
        quarter_round(1, 6, 11, 12, block);
        quarter_round(2, 7, 8, 13, block);
        quarter_round(3, 4, 9, 14, block);
    }

    #[inline]
    fn init_block(&mut self) {
        let block = &mut self.state.block;
        let iv = self.state.iv;
        let key = self.state.key;
        let block_idx = self.state.block_idx;

        block[0] = block[0].wrapping_add(0x61707865);
        block[1] = block[1].wrapping_add(0x3320646e);
        block[2] = block[2].wrapping_add(0x79622d32);
        block[3] = block[3].wrapping_add(0x6b206574);
        block[4] = block[4].wrapping_add(key[0]);
        block[5] = block[5].wrapping_add(key[1]);
        block[6] = block[6].wrapping_add(key[2]);
        block[7] = block[7].wrapping_add(key[3]);
        block[8] = block[8].wrapping_add(key[4]);
        block[9] = block[9].wrapping_add(key[5]);
        block[10] = block[10].wrapping_add(key[6]);
        block[11] = block[11].wrapping_add(key[7]);
        block[12] = block[12].wrapping_add((block_idx & 0xffffffff) as u32);
        block[13] = block[13].wrapping_add(((block_idx >> 32) & 0xffffffff) as u32);
        block[14] = block[14].wrapping_add(iv[0]);
        block[15] = block[15].wrapping_add(iv[1]);
    }

    #[inline]
    fn add_block(&mut self) {
        let block = &mut self.state.block;
        let iv = self.state.iv;
        let key = self.state.key;
        let block_idx = self.state.block_idx;

        block[0] = 0x61707865;
        block[1] = 0x3320646e;
        block[2] = 0x79622d32;
        block[3] = 0x6b206574;
        block[4] = key[0];
        block[5] = key[1];
        block[6] = key[2];
        block[7] = key[3];
        block[8] = key[4];
        block[9] = key[5];
        block[10] = key[6];
        block[11] = key[7];
        block[12] = (block_idx & 0xffffffff) as u32;
        block[13] = ((block_idx >> 32) & 0xffffffff) as u32;
        block[14] = iv[0];
        block[15] = iv[1];
    }
}

impl ChaCha20 {
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

impl NewStreamCipher for ChaChaState {
    /// Key size in bytes
    type KeySize = U32;
    /// Nonce size in bytes
    type NonceSize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>,
           iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        ChaChaState { state: SalsaFamilyState::new(key, iv) }
    }
}

impl SyncStreamCipherSeek for ChaChaState {
    fn current_pos(&self) -> u64 {
        self.state.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.state.seek(pos);
    }
}

impl Zeroize for ChaChaState {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl SalsaFamilyCipher for ChaCha20 {
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

impl NewStreamCipher for ChaCha20 {
    /// Key size in bytes
    type KeySize = U32;
    /// Nonce size in bytes
    type NonceSize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>,
           iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut out = ChaCha20 { state: ChaChaState::new(key, iv) };

        out.gen_block();

        out
    }
}

impl SyncStreamCipherSeek for ChaCha20 {
    fn current_pos(&self) -> u64 {
        self.state.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.state.seek(pos);
        self.gen_block();
    }
}

impl StreamCipher for ChaCha20 {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.process(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.process(data);
    }
}

impl Zeroize for ChaCha20 {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}
