#![no_std]
#![feature(test)]
#[macro_use]
extern crate stream_cipher;
extern crate aes_ctr;

bench_fixed!(aes_ctr::Aes192Ctr);
