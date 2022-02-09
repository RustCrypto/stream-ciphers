//! An implementation of the RC4 (also sometimes called ARC4) stream cipher.
//!
//! # Usage
//!
//! ```rust
//! use rc4::{Rc4, Key, nonce};
//! use rc4::{consts::*, NewCipher, StreamCipher};
//!
//! let mut rc4 = Rc4::new(b"Key".into(), &nonce());
//! let mut data = b"Plaintext".to_vec();
//! rc4.apply_keystream(&mut data);
//! assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
//!
//! let mut rc4 = Rc4::new(b"Wiki".into(), &nonce());
//! let mut data = b"pedia".to_vec();
//! rc4.apply_keystream(&mut data);
//! assert_eq!(data, [0x10, 0x21, 0xBF, 0x04, 0x20]);
//!
//! let key = Key::<U6>::from_slice(b"Secret");
//! let mut rc4 = Rc4::<_>::new(key, &nonce());
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

pub use cipher;

use cipher::{
    errors::LoopError,
    generic_array::{ArrayLength, GenericArray},
};

use core::marker::PhantomData;
#[cfg(cargo_feature = "zeroize")]
use std::ops::Drop;
#[cfg(cargo_feature = "zeroize")]
use zeroize::Zeroize;

/// Rc4 key type (8–2048 bits/ 1-256 bytes)
///
/// Implemented as an alias for [`GenericArray`].
pub type Key<KeySize> = GenericArray<u8, KeySize>;

/// default Nonce for Rc4
///
/// Implemented as an alias for [`GenericArray`].
pub fn nonce() -> GenericArray<u8, consts::U0> {
    Default::default()
}

pub use cipher::{consts, NewCipher, StreamCipher};

/// The RC-4 stream cipher
pub struct Rc4<KeySize> {
    state: [u8; 256],
    i: u8,
    j: u8,

    key_size: PhantomData<KeySize>,
}

impl<KeySize> NewCipher for Rc4<KeySize>
where
    KeySize: ArrayLength<u8>,
{
    type NonceSize = consts::U0;
    type KeySize = KeySize;

    fn new(key: &cipher::CipherKey<Self>, _nonce: &cipher::Nonce<Self>) -> Self {
        assert!(key.len() >= 1 && key.len() <= 256);

        let mut rc4 = Rc4 {
            state: [0; 256],
            i: 0,
            j: 0,

            key_size: Default::default(),
        };

        rc4.ksa(key);

        rc4
    }
}

impl<KeySize> StreamCipher for Rc4<KeySize>
where
    KeySize: ArrayLength<u8>,
{
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.process(data);
        Ok(())
    }
}

impl<KeySize> Rc4<KeySize>
where
    KeySize: ArrayLength<u8>,
{
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

    fn process(&mut self, data: &mut [u8]) {
        data.iter_mut().for_each(|x| {
            *x ^= self.prga();
        });
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Zeroize for Rc4 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.i.zeroize();
        self.j.zeroize();

        self.key_size.zeroize();
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Drop for Rc4 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
