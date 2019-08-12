#![no_std]

extern crate block_cipher_trait;

#[cfg(cargo_feature = "zeroize")]
extern crate zeroize;

pub extern crate stream_cipher;

mod salsa_family_state;

pub use salsa_family_state::{SalsaFamilyCipher, SalsaFamilyState};
