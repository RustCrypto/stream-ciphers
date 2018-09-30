extern crate aes;
extern crate cfb_mode;

use cfb_mode::{Cfb};
use aes::Aes128;

type AesCfb = Cfb<Aes128>;

#[test]
fn cfb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cfb-aes128.ciphertext.bin");

    let mode = AesCfb::new_var(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt(&mut pt);
    assert_eq!(pt, &ciphertext[..]);

    let mode = AesCfb::new_var(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt(&mut ct);
    assert_eq!(ct, &plaintext[..]);
}
