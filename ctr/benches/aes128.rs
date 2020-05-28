#![feature(test)]
#[macro_use]
extern crate stream_cipher;
use aes;
use ctr;

type Aes128Ctr = ctr::Ctr128<aes::Aes128>;

bench_sync!(Aes128Ctr);
