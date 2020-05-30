#![feature(test)]

stream_cipher::bench_async!(cfb_mode::Cfb<aes::Aes128>);
