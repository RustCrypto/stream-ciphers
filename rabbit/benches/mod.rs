#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    rabbit::Rabbit;
    rabbit_bench1_16b 16;
    rabbit_bench2_256b 256;
    rabbit_bench3_1kib 1024;
    rabbit_bench4_16kib 16384;
);
