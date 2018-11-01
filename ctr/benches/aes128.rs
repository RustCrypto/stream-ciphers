#![feature(test)]
#[macro_use] extern crate stream_cipher;
extern crate aes;
extern crate ctr;

type Aes128Ctr = ctr::Ctr128<aes::Aes128>;

bench_sync!(Aes128Ctr);
