#![feature(test)]
use stream_cipher::bench_sync;
bench_sync!(ofb::Ofb<aes::Aes128>);
