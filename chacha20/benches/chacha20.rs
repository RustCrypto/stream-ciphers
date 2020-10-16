#![cfg(feature = "cipher")]
#![feature(test)]

cipher::bench_sync!(chacha20::ChaCha20);
