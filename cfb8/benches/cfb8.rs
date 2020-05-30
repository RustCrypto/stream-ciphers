#![feature(test)]

stream_cipher::bench_async!(cfb8::Cfb8<aes::Aes128>);
