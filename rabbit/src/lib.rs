//! Implementation of the [Rabbit] stream cipher.
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
//! use rabbit::Rabbit;
//! // Import relevant traits
//! use rabbit::cipher::{KeyIvInit, StreamCipher};
//! use hex_literal::hex;
//!
//! let key = [0x42; 16];
//! let nonce = [0x24; 8];
//! let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
//! let ciphertext = hex!("10298496 ceda18ee 0e257cbb 1ab43bcc");
//!
//! // Key and IV must be references to the `Array` type.
//! // Here we use the `Into` trait to convert arrays into it.
//! let mut cipher = Rabbit::new(&key.into(), &nonce.into());
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
//! let mut cipher = Rabbit::new(&key.into(), &nonce.into());
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, plaintext);
//!
//! // stream ciphers can be used with streaming messages
//! let mut cipher = Rabbit::new(&key.into(), &nonce.into());
//! for chunk in buffer.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buffer, ciphertext);
//! ```
//!
//! [Rabbit]: https://tools.ietf.org/html/rfc4503#section-2.3

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    Block, BlockSizeUser, InnerIvInit, IvSizeUser, KeyInit, KeySizeUser, ParBlocksSizeUser,
    StreamCipherBackend, StreamCipherClosure, StreamCipherCore, StreamCipherCoreWrapper,
    consts::{U1, U8, U16},
    crypto_common::InnerUser,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// RFC 4503. 2.3.  Key Setup Scheme (page 2).
const KEY_BYTE_LEN: usize = 16;
/// RFC 4503. 2.4.  IV Setup Scheme (page 2-3).
const IV_BYTE_LEN: usize = 8;

/// RFC 4503. 2.1.  Notation (page 2).
const WORDSIZE: u64 = 1 << 32;

/// RFC 4503. 2.5.  Counter System (page 3).
const A: [u32; 8] = [
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3,
];

/// Rabbit Stream Cipher Key.
pub type Key = cipher::Key<RabbitCore>;

/// Rabbit Stream Cipher Initialization Vector.
pub type Iv = cipher::Iv<RabbitCore>;

type BlockSize = U16;

/// The Rabbit stream cipher initializied only with key.
pub type RabbitKeyOnly = StreamCipherCoreWrapper<RabbitKeyOnlyCore>;
/// The Rabbit stream cipher initializied with key and IV.
pub type Rabbit = StreamCipherCoreWrapper<RabbitCore>;

/// RFC 4503. 2.2.  Inner State (page 2).
struct State {
    /// State variables
    x: [u32; 8],
    /// Counter variables
    c: [u32; 8],
    carry_bit: u8,
}

impl State {
    /// RFC 4503. 2.3.  Key Setup Scheme (page 2).
    fn setup_key(key: [u8; KEY_BYTE_LEN]) -> Self {
        let mut k = [0u16; 8];

        k[0] = (key[0x0] as u16) | ((key[0x1] as u16) << 8);
        k[1] = (key[0x2] as u16) | ((key[0x3] as u16) << 8);
        k[2] = (key[0x4] as u16) | ((key[0x5] as u16) << 8);
        k[3] = (key[0x6] as u16) | ((key[0x7] as u16) << 8);
        k[4] = (key[0x8] as u16) | ((key[0x9] as u16) << 8);
        k[5] = (key[0xA] as u16) | ((key[0xB] as u16) << 8);
        k[6] = (key[0xC] as u16) | ((key[0xD] as u16) << 8);
        k[7] = (key[0xE] as u16) | ((key[0xF] as u16) << 8);

        let mut x = [0u32; 8];
        let mut c = [0u32; 8];
        for j in 0..8 {
            if j % 2 == 0 {
                x[j] = ((k[(j + 1) % 8] as u32) << 16) | (k[j] as u32);
                c[j] = ((k[(j + 4) % 8] as u32) << 16) | (k[(j + 5) % 8] as u32);
            } else {
                x[j] = ((k[(j + 5) % 8] as u32) << 16) | (k[(j + 4) % 8] as u32);
                c[j] = ((k[j] as u32) << 16) | (k[(j + 1) % 8] as u32);
            }
        }

        let carry_bit = 0;
        let mut state = Self { x, c, carry_bit };

        for _ in 0..4 {
            state.next_state();
        }

        for j in 0..8 {
            state.c[j] ^= state.x[(j + 4) % 8];
        }

        state
    }

    /// RFC 4503. 2.4.  IV Setup Scheme (page 2-3).
    fn setup_iv(&mut self, iv: [u8; IV_BYTE_LEN]) {
        let mut i = [0_u32; 4];

        i[0] =
            iv[0] as u32 | ((iv[1] as u32) << 8) | ((iv[2] as u32) << 16) | ((iv[3] as u32) << 24);
        i[2] =
            iv[4] as u32 | ((iv[5] as u32) << 8) | ((iv[6] as u32) << 16) | ((iv[7] as u32) << 24);
        i[1] = (i[0] >> 16) | (i[2] & 0xFFFF0000);
        i[3] = (i[2] << 16) | (i[0] & 0x0000FFFF);

        self.c[0] ^= i[0];
        self.c[1] ^= i[1];
        self.c[2] ^= i[2];
        self.c[3] ^= i[3];
        self.c[4] ^= i[0];
        self.c[5] ^= i[1];
        self.c[6] ^= i[2];
        self.c[7] ^= i[3];

        for _ in 0..4 {
            self.next_state();
        }
    }

    /// RFC 4503. 2.5.  Counter System (page 3).
    fn counter_update(&mut self) {
        #[allow(unused_mut, clippy::needless_range_loop)]
        for j in 0..8 {
            let t = self.c[j] as u64 + A[j] as u64 + self.carry_bit as u64;
            self.carry_bit = ((t / WORDSIZE) as u8) & 0b1;
            self.c[j] = (t % WORDSIZE) as u32;
        }
    }

    /// RFC 4503. 2.6. Next-State Function (page 3-4).
    fn next_state(&mut self) {
        let mut g = [0u32; 8];

        self.counter_update();

        #[allow(clippy::needless_range_loop)]
        for j in 0..8 {
            let u_plus_v = self.x[j] as u64 + self.c[j] as u64;
            let square_uv = (u_plus_v % WORDSIZE) * (u_plus_v % WORDSIZE);
            g[j] = (square_uv ^ (square_uv >> 32)) as u32;
        }

        self.x[0] = g[0]
            .wrapping_add(g[7].rotate_left(16))
            .wrapping_add(g[6].rotate_left(16));
        self.x[1] = g[1].wrapping_add(g[0].rotate_left(8)).wrapping_add(g[7]);
        self.x[2] = g[2]
            .wrapping_add(g[1].rotate_left(16))
            .wrapping_add(g[0].rotate_left(16));
        self.x[3] = g[3].wrapping_add(g[2].rotate_left(8)).wrapping_add(g[1]);
        self.x[4] = g[4]
            .wrapping_add(g[3].rotate_left(16))
            .wrapping_add(g[2].rotate_left(16));
        self.x[5] = g[5].wrapping_add(g[4].rotate_left(8)).wrapping_add(g[3]);
        self.x[6] = g[6]
            .wrapping_add(g[5].rotate_left(16))
            .wrapping_add(g[4].rotate_left(16));
        self.x[7] = g[7].wrapping_add(g[6].rotate_left(8)).wrapping_add(g[5]);
    }

    /// RFC 4503. 2.7. Extraction Scheme (page 4).
    fn extract(&self) -> [u8; 16] {
        let mut s = [0u8; 16];

        let mut tmp = [0_u16; 8];

        tmp[0] = ((self.x[0]) ^ (self.x[5] >> 16)) as u16;
        tmp[1] = ((self.x[0] >> 16) ^ (self.x[3])) as u16;
        tmp[2] = ((self.x[2]) ^ (self.x[7] >> 16)) as u16;
        tmp[3] = ((self.x[2] >> 16) ^ (self.x[5])) as u16;
        tmp[4] = ((self.x[4]) ^ (self.x[1] >> 16)) as u16;
        tmp[5] = ((self.x[4] >> 16) ^ (self.x[7])) as u16;
        tmp[6] = ((self.x[6]) ^ (self.x[3] >> 16)) as u16;
        tmp[7] = ((self.x[6] >> 16) ^ (self.x[1])) as u16;

        s[0x0] = tmp[0] as u8;
        s[0x1] = (tmp[0] >> 8) as u8;
        s[0x2] = tmp[1] as u8;
        s[0x3] = (tmp[1] >> 8) as u8;
        s[0x4] = tmp[2] as u8;
        s[0x5] = (tmp[2] >> 8) as u8;
        s[0x6] = tmp[3] as u8;
        s[0x7] = (tmp[3] >> 8) as u8;
        s[0x8] = tmp[4] as u8;
        s[0x9] = (tmp[4] >> 8) as u8;
        s[0xA] = tmp[5] as u8;
        s[0xB] = (tmp[5] >> 8) as u8;
        s[0xC] = tmp[6] as u8;
        s[0xD] = (tmp[6] >> 8) as u8;
        s[0xE] = tmp[7] as u8;
        s[0xF] = (tmp[7] >> 8) as u8;

        s
    }

    fn next_block(&mut self) -> [u8; 16] {
        self.next_state();
        self.extract()
    }
}

#[cfg(feature = "zeroize")]
impl core::ops::Drop for State {
    fn drop(&mut self) {
        self.x.zeroize();
        self.c.zeroize();
        self.carry_bit.zeroize();
    }
}

/// Core state of the Rabbit stream cipher initialized only with key.
pub struct RabbitKeyOnlyCore {
    state: State,
}

impl KeySizeUser for RabbitKeyOnlyCore {
    type KeySize = U16;
}

impl KeyInit for RabbitKeyOnlyCore {
    fn new(key: &Key) -> Self {
        Self {
            state: State::setup_key((*key).into()),
        }
    }
}

impl BlockSizeUser for RabbitKeyOnlyCore {
    type BlockSize = BlockSize;
}

impl StreamCipherCore for RabbitKeyOnlyCore {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        // Rabbit can generate 2^64 blocks, but since it does not implement
        // the seeking traits, we can assume that so many blocks never will
        // be processed
        None
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(&mut self.state));
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for RabbitKeyOnlyCore {}

/// Core state of the Rabbit stream cipher initialized with key and IV.
pub struct RabbitCore {
    state: State,
}

impl InnerUser for RabbitCore {
    type Inner = RabbitKeyOnlyCore;
}

impl IvSizeUser for RabbitCore {
    type IvSize = U8;
}

impl InnerIvInit for RabbitCore {
    fn inner_iv_init(inner: RabbitKeyOnlyCore, iv: &Iv) -> Self {
        let mut state = inner.state;
        state.setup_iv((*iv).into());
        Self { state }
    }
}

impl BlockSizeUser for RabbitCore {
    type BlockSize = BlockSize;
}

impl StreamCipherCore for RabbitCore {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        // Rabbit can generate 2^64 blocks, but since it does not implement
        // the seeking traits, we can assume that so many blocks never will
        // be processed
        None
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(&mut self.state));
    }
}

struct Backend<'a>(&'a mut State);

impl BlockSizeUser for Backend<'_> {
    type BlockSize = BlockSize;
}

impl ParBlocksSizeUser for Backend<'_> {
    type ParBlocksSize = U1;
}

impl StreamCipherBackend for Backend<'_> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        block.copy_from_slice(&self.0.next_block());
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for RabbitCore {}
