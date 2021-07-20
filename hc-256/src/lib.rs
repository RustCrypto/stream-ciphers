//! HC-256 Stream Cipher

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/hc-256/0.4.1"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    consts::U32, errors::LoopError, generic_array::GenericArray, NewCipher, StreamCipher,
};

#[cfg(cargo_feature = "zeroize")]
use std::ops::Drop;
#[cfg(cargo_feature = "zeroize")]
use zeroize::Zeroize;

const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const INIT_SIZE: usize = 2660;
const KEY_BITS: usize = 256;
const KEY_WORDS: usize = KEY_BITS / 32;
const IV_BITS: usize = 256;
const IV_WORDS: usize = IV_BITS / 32;

/// The HC-256 stream cipher
pub struct Hc256 {
    ptable: [u32; TABLE_SIZE],
    qtable: [u32; TABLE_SIZE],
    word: u32,
    idx: u32,
    offset: u8,
}

impl NewCipher for Hc256 {
    /// Key size in bytes
    type KeySize = U32;
    /// Nonce size in bytes
    type NonceSize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut out = Hc256::create();
        out.init(key.as_slice(), iv.as_slice());
        out
    }
}

impl StreamCipher for Hc256 {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.process(data);
        Ok(())
    }
}

impl Hc256 {
    fn create() -> Hc256 {
        Hc256 {
            ptable: [0; TABLE_SIZE],
            qtable: [0; TABLE_SIZE],
            word: 0,
            idx: 0,
            offset: 0,
        }
    }

    fn init(&mut self, key: &[u8], iv: &[u8]) {
        let mut data = [0; INIT_SIZE];

        for i in 0..KEY_WORDS {
            data[i] = key[4 * i] as u32 & 0xff
                | (key[(4 * i) + 1] as u32 & 0xff) << 8
                | (key[(4 * i) + 2] as u32 & 0xff) << 16
                | (key[(4 * i) + 3] as u32 & 0xff) << 24;
        }

        for i in 0..IV_WORDS {
            data[i + KEY_WORDS] = iv[4 * i] as u32 & 0xff
                | (iv[(4 * i) + 1] as u32 & 0xff) << 8
                | (iv[(4 * i) + 2] as u32 & 0xff) << 16
                | (iv[(4 * i) + 3] as u32 & 0xff) << 24;
        }

        for i in IV_WORDS + KEY_WORDS..INIT_SIZE {
            data[i] = f2(data[i - 2])
                .wrapping_add(data[i - 7])
                .wrapping_add(f1(data[i - 15]))
                .wrapping_add(data[i - 16])
                .wrapping_add(i as u32);
        }

        self.ptable[..TABLE_SIZE].clone_from_slice(&data[512..(TABLE_SIZE + 512)]);
        self.qtable[..TABLE_SIZE].clone_from_slice(&data[1536..(TABLE_SIZE + 1536)]);

        self.idx = 0;

        #[cfg(cargo_feature = "zeroize")]
        data.zeroize();

        for _ in 0..4096 {
            self.gen_word();
        }

        // This forces generation of the first block
        #[cfg(cargo_feature = "zeroize")]
        self.word.zeroize();

        self.offset = 4;
    }

    #[inline]
    fn g1(&self, x: u32, y: u32) -> u32 {
        (x.rotate_right(10) ^ y.rotate_right(23))
            .wrapping_add(self.qtable[(x ^ y) as usize & TABLE_MASK])
    }

    #[inline]
    fn g2(&self, x: u32, y: u32) -> u32 {
        (x.rotate_right(10) ^ y.rotate_right(23))
            .wrapping_add(self.ptable[(x ^ y) as usize & TABLE_MASK])
    }

    #[inline]
    fn h1(&self, x: u32) -> u32 {
        self.qtable[(x & 0xff) as usize]
            .wrapping_add(self.qtable[(256 + ((x >> 8) & 0xff)) as usize])
            .wrapping_add(self.qtable[(512 + ((x >> 16) & 0xff)) as usize])
            .wrapping_add(self.qtable[(768 + ((x >> 24) & 0xff)) as usize])
    }

    #[inline]
    fn h2(&self, x: u32) -> u32 {
        self.qtable[(x & 0xff) as usize]
            .wrapping_add(self.qtable[(256 + ((x >> 8) & 0xff)) as usize])
            .wrapping_add(self.qtable[(512 + ((x >> 16) & 0xff)) as usize])
            .wrapping_add(self.qtable[(768 + ((x >> 24) & 0xff)) as usize])
    }

    fn gen_word(&mut self) -> u32 {
        let i = self.idx as usize;
        let j = self.idx as usize & TABLE_MASK;

        self.offset = 0;
        self.idx = (self.idx + 1) & (2048 - 1);

        if i < 1024 {
            self.ptable[j] = self.ptable[j]
                .wrapping_add(self.ptable[j.wrapping_sub(10) & TABLE_MASK])
                .wrapping_add(self.g1(
                    self.ptable[j.wrapping_sub(3) & TABLE_MASK],
                    self.ptable[j.wrapping_sub(1023) & TABLE_MASK],
                ));

            self.h1(self.ptable[j.wrapping_sub(12) & TABLE_MASK]) ^ self.ptable[j]
        } else {
            self.qtable[j] = self.qtable[j]
                .wrapping_add(self.qtable[j.wrapping_sub(10) & TABLE_MASK])
                .wrapping_add(self.g2(
                    self.qtable[j.wrapping_sub(3) & TABLE_MASK],
                    self.qtable[j.wrapping_sub(1023) & TABLE_MASK],
                ));

            self.h2(self.qtable[j.wrapping_sub(12) & TABLE_MASK]) ^ self.qtable[j]
        }
    }

    fn process(&mut self, data: &mut [u8]) {
        let mut i = 0;
        let mut word: u32 = self.word;

        // First, use the remaining part of the current word.
        for j in self.offset..4 {
            data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
            i += 1;
        }

        let mainlen = (data.len() - i) / 4;
        let leftover = (data.len() - i) % 4;

        // Process all the whole words
        for _ in 0..mainlen {
            word = self.gen_word();

            for j in 0..4 {
                data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }
        }

        // Process the end of the block
        if leftover != 0 {
            word = self.gen_word();

            for j in 0..leftover {
                data[i] ^= ((word >> (j * 8)) & 0xff) as u8;
                i += 1;
            }

            self.offset = leftover as u8;
        } else {
            self.offset = 4;
        }

        self.word = word;
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Zeroize for Hc256 {
    fn zeroize(&mut self) {
        self.ptable.zeroize();
        self.qtable.zeroize();
        self.word.zeroize();
        self.idx.zeroize();
        self.offset.zeroize();
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Drop for Hc256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[inline]
fn f1(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn f2(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
