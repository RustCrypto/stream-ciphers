#![feature(test)]
use stream_cipher::bench_sync;
bench_sync!(aes_ctr::Aes128Ctr);
