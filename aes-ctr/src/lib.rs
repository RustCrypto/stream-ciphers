#![no_std]
pub extern crate stream_cipher;
#[cfg(not(all(
    target_feature = "aes", target_feature = "sse2", target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
extern crate ctr;
#[cfg(not(all(
    target_feature = "aes", target_feature = "sse2", target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
extern crate aes_soft;

#[cfg(not(all(
    target_feature = "aes", target_feature = "sse2", target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
)))]
mod dummy;

#[cfg(all(
    target_feature = "aes", target_feature = "sse2", target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
))]
extern crate aesni;

#[cfg(all(
    target_feature = "aes", target_feature = "sse2", target_feature = "ssse3",
    any(target_arch = "x86_64", target_arch = "x86"),
))]
use aesni as dummy;

pub use dummy::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
