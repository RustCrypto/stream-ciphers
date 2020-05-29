#![feature(test)]
#[macro_use]
extern crate stream_cipher;
use aes;
use ofb;

bench_sync!(ofb::Ofb<aes::Aes128>);
