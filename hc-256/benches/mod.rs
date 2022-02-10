#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    hc_256::Hc256;
    hc256_bench1_16b 16;
    hc256_bench2_256b 256;
    hc256_bench3_1kib 1024;
    hc256_bench4_16kib 16384;
);
