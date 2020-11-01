#![feature(test)]

cipher::stream_cipher_async_bench!(cfb_mode::Cfb<aes::Aes128>);
