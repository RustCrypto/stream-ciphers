extern crate aes;
extern crate cfb_mode;

use cfb_mode::{Cfb};
use aes::Aes128;
use aes::block_cipher_trait::generic_array::GenericArray;

type AesCfb = Cfb<Aes128>;

#[test]
fn cfb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/aes128.ciphertext.bin");

    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);

    for n in 1..=plaintext.len() {
        let mut mode = AesCfb::new(key, iv);
        let mut buf = plaintext.to_vec();
        for chunk in buf.chunks_mut(n) {
            mode.encrypt(chunk);
        }
        assert_eq!(buf, &ciphertext[..], "encrypt: {}", n);
    }

    for n in 1..=plaintext.len() {
        let mut mode = AesCfb::new(key, iv);
        let mut buf = ciphertext.to_vec();
        for chunk in buf.chunks_mut(n) {
            mode.decrypt(chunk);
        }
        assert_eq!(buf, &plaintext[..], "decrypt: {}", n);
    }
}
