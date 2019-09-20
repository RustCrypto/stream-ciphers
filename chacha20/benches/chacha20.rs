#![feature(test)]
#[macro_use]
extern crate stream_cipher;
extern crate chacha20;

bench_sync!(chacha20::ChaCha20);
