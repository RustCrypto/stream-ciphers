#![feature(test)]
use stream_cipher::bench_async;

type Aes128Cfb8 = cfb8::Cfb8<aes::Aes128>;
bench_async!(Aes128Cfb8);
