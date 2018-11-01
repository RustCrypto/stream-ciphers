extern crate aes;
extern crate cfb_mode;
#[macro_use] extern crate stream_cipher;

use cfb_mode::Cfb;

// tests vectors are from:
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
new_async_test!(cfb_aes128, "aes128", Cfb<aes::Aes128>);
new_async_test!(cfb_aes192, "aes192", Cfb<aes::Aes192>);
new_async_test!(cfb_aes256, "aes256", Cfb<aes::Aes256>);
