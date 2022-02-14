//! An implementation of the RC4 (also sometimes called ARC4) stream cipher.
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
//!
//! ```rust
//! use hex_literal::hex;
//! use rc4::{consts::*, KeyInit, StreamCipher};
//! use rc4::{Key, Rc4};
//!
//! let mut rc4 = Rc4::new(b"Key".into());
//! let mut data = b"Plaintext".to_vec();
//! rc4.apply_keystream(&mut data);
//! assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
//!
//! let mut rc4 = Rc4::new(b"Wiki".into());
//! let mut data = b"pedia".to_vec();
//! rc4.apply_keystream(&mut data);
//! assert_eq!(data, [0x10, 0x21, 0xBF, 0x04, 0x20]);
//!
//! let key = Key::<U6>::from_slice(b"Secret");
//! let mut rc4 = Rc4::<_>::new(key);
//! let mut data = b"Attack at dawn".to_vec();
//! rc4.apply_keystream(&mut data);
//! assert_eq!(
//!     data,
//!     [0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5]
//! );
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/rc4/0.1.0"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher::{self, consts, KeyInit, StreamCipher};

use cipher::{
    generic_array::{ArrayLength, GenericArray},
    Block, BlockSizeUser, KeySizeUser, ParBlocksSizeUser, StreamBackend, StreamCipherCore,
    StreamCipherCoreWrapper, StreamClosure,
};

use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Rc4 key type (8–2048 bits/ 1-256 bytes)
///
/// Implemented as an alias for [`GenericArray`].
pub type Key<KeySize> = GenericArray<u8, KeySize>;

type BlockSize = consts::U1;

/// The Rc4 stream cipher initializied with key
pub type Rc4<KeySize> = StreamCipherCoreWrapper<Rc4Core<KeySize>>;

/// Core state of the Rc4 stream cipher initialized only with key.
pub struct Rc4Core<KeySize> {
    state: Rc4State,

    key_size: PhantomData<KeySize>,
}

impl<KeySize> KeySizeUser for Rc4Core<KeySize>
where
    KeySize: ArrayLength<u8>,
{
    type KeySize = KeySize;
}

impl<KeySize> KeyInit for Rc4Core<KeySize>
where
    KeySize: ArrayLength<u8>,
{
    fn new(key: &Key<KeySize>) -> Self {
        Self {
            state: Rc4State::new(key),
            key_size: Default::default(),
        }
    }
}

impl<KeySize> BlockSizeUser for Rc4Core<KeySize> {
    type BlockSize = BlockSize;
}

impl<KeySize> StreamCipherCore for Rc4Core<KeySize> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(&mut self.state));
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<KeySize> ZeroizeOnDrop for Rc4Core<KeySize> where KeySize: ArrayLength<u8> {}

struct Backend<'a>(&'a mut Rc4State);

impl<'a> BlockSizeUser for Backend<'a> {
    type BlockSize = BlockSize;
}

impl<'a> ParBlocksSizeUser for Backend<'a> {
    type ParBlocksSize = consts::U1;
}

impl<'a> StreamBackend for Backend<'a> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        block[0] = self.0.prga();
    }
}

#[derive(Clone)]
struct Rc4State {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut state = Self {
            state: [0; 256],
            i: 0,
            j: 0,
        };

        state.ksa(key);

        state
    }

    fn ksa(&mut self, key: &[u8]) {
        self.state.iter_mut().enumerate().for_each(|(i, x)| {
            *x = i as u8;
        });

        let i_iter = 0..256usize;
        let key_iter = key.iter().cycle();

        let mut j = 0u8;

        i_iter.zip(key_iter).for_each(|(i, k)| {
            j = j.wrapping_add(self.state[i]).wrapping_add(*k);

            self.state.swap(i, j.into());
        });
    }

    fn s_i(&self) -> u8 {
        self.state[self.i as usize]
    }

    fn s_j(&self) -> u8 {
        self.state[self.j as usize]
    }

    fn prga(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s_i());

        self.state.swap(self.i.into(), self.j.into());

        let index: usize = self.s_i().wrapping_add(self.s_j()).into();

        self.state[index]
    }
}

#[cfg(feature = "zeroize")]
impl core::ops::Drop for Rc4State {
    fn drop(&mut self) {
        self.state.zeroize();
        self.i.zeroize();
        self.j.zeroize();
    }
}
