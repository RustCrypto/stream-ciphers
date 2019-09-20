#![feature(test)]
#[macro_use]
extern crate stream_cipher;
extern crate salsa20;

bench_sync!(salsa20::Salsa20);
