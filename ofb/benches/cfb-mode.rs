#![feature(test)]

cipher::stream_cipher_sync_bench!(ofb::Ofb<aes::Aes128>);
