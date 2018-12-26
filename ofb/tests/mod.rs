extern crate aes;
extern crate ofb;
#[macro_use] extern crate stream_cipher;

new_sync_test!(ofb_aes128, ofb::Ofb<aes::Aes128>, "aes128");

