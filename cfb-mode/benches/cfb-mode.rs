#![feature(test)]
use stream_cipher::bench_async;

type Aes128Cfb = cfb_mode::Cfb<aes::Aes128>;
bench_async!(Aes128Cfb);
