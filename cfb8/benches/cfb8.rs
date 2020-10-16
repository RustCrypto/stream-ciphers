#![feature(test)]

cipher::bench_async!(cfb8::Cfb8<aes::Aes128>);
