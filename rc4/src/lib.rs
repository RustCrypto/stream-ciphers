#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher::{self, KeyInit, StreamCipher, consts};

use cipher::{BlockSizeUser, InOutBuf, InvalidLength, Key, KeySizeUser, StreamCipherError};
use core::array;

const MIN_KEY_SIZE: usize = 1;
const MAX_KEY_SIZE: usize = 256;

/// RC4 stream cipher.
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn s_i(&self) -> u8 {
        self.state[self.i as usize]
    }

    fn s_j(&self) -> u8 {
        self.state[self.j as usize]
    }

    fn prga(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s_i());

        self.state.swap(usize::from(self.i), usize::from(self.j));

        let index = self.s_i().wrapping_add(self.s_j());

        self.state[usize::from(index)]
    }
}

impl KeySizeUser for Rc4 {
    type KeySize = consts::U32;
}

impl KeyInit for Rc4 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key).expect("32 byte keys are supported")
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < MIN_KEY_SIZE || key.len() > MAX_KEY_SIZE {
            return Err(InvalidLength);
        }

        let mut state = array::from_fn(|i| u8::try_from(i).expect("`i` is less than 256"));

        let i_iter = 0..256usize;
        let key_iter = key.iter().cycle();

        let mut j = 0u8;

        i_iter.zip(key_iter).for_each(|(i, k)| {
            j = j.wrapping_add(state[i]).wrapping_add(*k);
            state.swap(i, usize::from(j));
        });

        Ok(Self { state, i: 0, j: 0 })
    }
}

impl BlockSizeUser for Rc4 {
    type BlockSize = consts::U1;
}

impl StreamCipher for Rc4 {
    #[inline(always)]
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        Ok(())
    }

    #[inline]
    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        buf.into_iter().for_each(|mut b| {
            let ks = self.prga();
            *b.get_out() = ks ^ *b.get_in();
        });
    }

    #[inline]
    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        buf.iter_mut().for_each(|b| *b = self.prga());
    }
}

#[cfg(feature = "zeroize")]
impl cipher::zeroize::ZeroizeOnDrop for Rc4 {}

impl core::ops::Drop for Rc4 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use cipher::zeroize::Zeroize;
            self.state.zeroize();
            self.i.zeroize();
            self.j.zeroize();
        }
    }
}
