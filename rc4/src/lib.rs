//! An implementation of the RC4 (also sometimes called ARC4) stream cipher.

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
    errors::{InvalidLength, LoopError},
    StreamCipher,
};

#[cfg(cargo_feature = "zeroize")]
use std::ops::Drop;
#[cfg(cargo_feature = "zeroize")]
use zeroize::Zeroize;

/// The RC-4 stream cipher
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Create new stream cipher instance from variable length key and nonce
    /// given as byte slices.
    pub fn new_from_slices(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < 1 || key.len() > 256 {
            return Err(InvalidLength);
        }

        let mut rc4 = Rc4 {
            state: [0; 256],
            i: 0,
            j: 0,
        };

        rc4.ksa(key);

        Ok(rc4)
    }
}

impl StreamCipher for Rc4 {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.process(data);
        Ok(())
    }
}

impl Rc4 {
    fn ksa(&mut self, key: &[u8]) {
        self.state.iter_mut().enumerate().for_each(|(i, x)| {
            *x = i as u8;
        });

        let i_iter = (0..256usize).into_iter();
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
    }
}

#[cfg(cargo_feature = "zeroize")]
impl Drop for Rc4 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[test]
fn test() {
    let mut rc4 = Rc4::new_from_slices(b"Key").unwrap();

    let mut data = b"Plaintext".to_vec();
    rc4.try_apply_keystream(&mut data).unwrap();
    assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
}
