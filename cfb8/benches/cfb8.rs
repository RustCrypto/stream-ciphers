#![feature(test)]
#[macro_use]
extern crate stream_cipher;
use aes;
use cfb8;

type Aes128Cfb8 = cfb8::Cfb8<aes::Aes128>;

bench_async!(Aes128Cfb8);
