use cfb_mode::Cfb;

// tests vectors are from:
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
cipher::new_async_test!(cfb_aes128, "aes128", Cfb<aes::Aes128>);
cipher::new_async_test!(cfb_aes192, "aes192", Cfb<aes::Aes192>);
cipher::new_async_test!(cfb_aes256, "aes256", Cfb<aes::Aes256>);
