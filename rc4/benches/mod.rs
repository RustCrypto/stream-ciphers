//! Basic benchmarks
#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    Key: rc4::Rc4;
    rc4_bench1_16b 16;
    rc4_bench2_256b 256;
    rc4_bench3_1kib 1024;
    rc4_bench4_16kib 16384;
);
