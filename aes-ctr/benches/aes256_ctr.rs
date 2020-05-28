#![feature(test)]
#[macro_use]
extern crate stream_cipher;
use aes_ctr;

bench_sync!(aes_ctr::Aes128Ctr);
