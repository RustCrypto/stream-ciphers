#![feature(test)]

cipher::stream_cipher_async_bench!(cfb8::Cfb8<aes::Aes128>);
