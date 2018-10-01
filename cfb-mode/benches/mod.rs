#![feature(test)]
extern crate test;
extern crate aes;
extern crate cfb_mode;

use test::Bencher;
use cfb_mode::{Cfb};
use aes::Aes128;

type AesCfb = Cfb<Aes128>;

#[inline(never)]
fn get_buf() -> Vec<u8> {
    vec![10; 100_000]
}

#[bench]
fn encrypt(b: &mut Bencher) {
    let key = include_bytes!("../tests/data/aes128.key.bin");
    let iv = include_bytes!("../tests/data/aes128.iv.bin");
    let mut cipher = AesCfb::new_var(key, iv).unwrap();
    let mut data = get_buf();

    b.iter(|| {
        cipher.encrypt(&mut data);
        test::black_box(&data);
    });

    b.bytes = data.len() as u64;
}

#[bench]
fn decrypt(b: &mut Bencher) {
    let key = include_bytes!("../tests/data/aes128.key.bin");
    let iv = include_bytes!("../tests/data/aes128.iv.bin");
    let mut cipher = AesCfb::new_var(key, iv).unwrap();
    let mut data = get_buf();

    b.iter(|| {
        cipher.decrypt(&mut data);
        test::black_box(&data);
    });

    b.bytes = data.len() as u64;
}
