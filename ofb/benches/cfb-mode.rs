#![feature(test)]

cipher::bench_sync!(ofb::Ofb<aes::Aes128>);
