#![feature(test)]

stream_cipher::bench_sync!(ofb::Ofb<aes::Aes128>);
