#![no_std]
extern crate block_cipher_trait;

#[cfg(cargo_feature = "zeroize")]
extern crate zeroize;

pub extern crate stream_cipher;
pub extern crate std;

mod salsa_family_state;
mod salsa;
mod chacha;

pub use chacha::ChaCha20;
pub use salsa::Salsa20;
