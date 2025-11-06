//! Implementation of the [HC-256] stream cipher.
//!
//! Cipher functionality is accessed using traits from re-exported [`cipher`] crate.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! USE AT YOUR OWN RISK!
//!
//! # Example
//! ```
//! use hc_256::Hc256;
//! // Import relevant traits
//! use hc_256::cipher::{KeyIvInit, StreamCipher};
//! use hex_literal::hex;
//!
//! let key = [0x42; 32];
//! let nonce = [0x24; 32];
//! let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
//! let ciphertext = hex!("ca982177 325cd40e bc208045 066c420f");
//!
//! // Key and IV must be references to the `Array` type.
//! // Here we use the `Into` trait to convert arrays into it.
//! let mut cipher = Hc256::new(&key.into(), &nonce.into());
//!
//! let mut buffer = plaintext.clone();
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, ciphertext);
//!
//! let ciphertext = buffer.clone();
//!
//! // decrypt ciphertext by applying keystream again
//! let mut cipher = Hc256::new(&key.into(), &nonce.into());
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, plaintext);
//!
//! // stream ciphers can be used with streaming messages
//! let mut cipher = Hc256::new(&key.into(), &nonce.into());
//! for chunk in buffer.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buffer, ciphertext);
//! ```
//!
//! [HC-256]: https://en.wikipedia.org/wiki/HC-256

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    AlgorithmName, Block, BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser,
    ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure, StreamCipherCore,
    StreamCipherCoreWrapper,
    consts::{U1, U4, U32},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const INIT_SIZE: usize = 2660;
const KEY_BITS: usize = 256;
const KEY_WORDS: usize = KEY_BITS / 32;
const IV_BITS: usize = 256;
const IV_WORDS: usize = IV_BITS / 32;

/// The HC-256 stream cipher core
pub type Hc256 = StreamCipherCoreWrapper<Hc256Core>;

/// The HC-256 stream cipher core
pub struct Hc256Core {
    ptable: [u32; TABLE_SIZE],
    qtable: [u32; TABLE_SIZE],
    idx: u32,
}

impl BlockSizeUser for Hc256Core {
    type BlockSize = U4;
}

impl KeySizeUser for Hc256Core {
    type KeySize = U32;
}

impl IvSizeUser for Hc256Core {
    type IvSize = U32;
}

impl KeyIvInit for Hc256Core {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        fn f1(x: u32) -> u32 {
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
        }

        fn f2(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }

        let mut out = Self {
            ptable: [0; TABLE_SIZE],
            qtable: [0; TABLE_SIZE],
            idx: 0,
        };
        let mut data = [0; INIT_SIZE];

        for i in 0..KEY_WORDS {
            data[i] = key[4 * i] as u32 & 0xff
                | ((key[(4 * i) + 1] as u32 & 0xff) << 8)
                | ((key[(4 * i) + 2] as u32 & 0xff) << 16)
                | ((key[(4 * i) + 3] as u32 & 0xff) << 24);
        }

        for i in 0..IV_WORDS {
            data[i + KEY_WORDS] = iv[4 * i] as u32 & 0xff
                | ((iv[(4 * i) + 1] as u32 & 0xff) << 8)
                | ((iv[(4 * i) + 2] as u32 & 0xff) << 16)
                | ((iv[(4 * i) + 3] as u32 & 0xff) << 24);
        }

        for i in IV_WORDS + KEY_WORDS..INIT_SIZE {
            data[i] = f2(data[i - 2])
                .wrapping_add(data[i - 7])
                .wrapping_add(f1(data[i - 15]))
                .wrapping_add(data[i - 16])
                .wrapping_add(i as u32);
        }

        out.ptable[..TABLE_SIZE].clone_from_slice(&data[512..(TABLE_SIZE + 512)]);
        out.qtable[..TABLE_SIZE].clone_from_slice(&data[1536..(TABLE_SIZE + 1536)]);

        out.idx = 0;

        for _ in 0..4096 {
            out.gen_word();
        }

        out
    }
}

impl StreamCipherCore for Hc256Core {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(self));
    }
}

impl AlgorithmName for Hc256Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hc256")
    }
}

impl fmt::Debug for Hc256Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hc256Core { ... }")
    }
}

impl Hc256Core {
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
        self.ptable[(x & 0xff) as usize]
            .wrapping_add(self.ptable[(256 + ((x >> 8) & 0xff)) as usize])
            .wrapping_add(self.ptable[(512 + ((x >> 16) & 0xff)) as usize])
            .wrapping_add(self.ptable[(768 + ((x >> 24) & 0xff)) as usize])
    }

    fn gen_word(&mut self) -> u32 {
        let i = self.idx as usize;
        let j = self.idx as usize & TABLE_MASK;

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
}

#[cfg(feature = "zeroize")]
impl Drop for Hc256Core {
    fn drop(&mut self) {
        self.ptable.zeroize();
        self.qtable.zeroize();
        self.idx.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Hc256Core {}

struct Backend<'a>(&'a mut Hc256Core);

impl BlockSizeUser for Backend<'_> {
    type BlockSize = <Hc256Core as BlockSizeUser>::BlockSize;
}

impl ParBlocksSizeUser for Backend<'_> {
    type ParBlocksSize = U1;
}

impl StreamCipherBackend for Backend<'_> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        block.copy_from_slice(&self.0.gen_word().to_le_bytes());
    }
}
