#![feature(test)]
#[macro_use]
extern crate stream_cipher;
use aes;
use cfb_mode;

type Aes128Cfb = cfb_mode::Cfb<aes::Aes128>;

bench_async!(Aes128Cfb);
