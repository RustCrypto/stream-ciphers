use cfb8::Cfb8;

// tests vectors are from:
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
cipher::new_async_test!(cfb8_aes128, "aes128", Cfb8<aes::Aes128>);
cipher::new_async_test!(cfb8_aes192, "aes192", Cfb8<aes::Aes192>);
cipher::new_async_test!(cfb8_aes256, "aes256", Cfb8<aes::Aes256>);
