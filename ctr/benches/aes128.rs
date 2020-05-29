#![feature(test)]
use stream_cipher::bench_sync;

type Aes128Ctr = ctr::Ctr128<aes::Aes128>;
bench_sync!(Aes128Ctr);
