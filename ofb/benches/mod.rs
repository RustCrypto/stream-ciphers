#![feature(test)]
#[macro_use] extern crate stream_cipher;
extern crate aes;
extern crate ofb;

bench_sync!(ofb::Ofb<aes::Aes128>);
