#![feature(test)]
extern crate test;
extern crate aes;
extern crate cfb8;

use test::Bencher;
use cfb8::Cfb8;
use aes::Aes128;

type AesCfb8 = Cfb8<Aes128>;

#[inline(never)]
fn get_buf() -> Vec<u8> {
    vec![10; 100_000]
}

#[inline(never)]
fn get_key_iv() -> (&'static [u8], &'static [u8]) {
    (b"0123456789abcdef", b"0123456789abcdef")
}

#[bench]
fn encrypt(b: &mut Bencher) {
    let (key, iv) = get_key_iv();
    let mut cipher = AesCfb8::new_var(key, iv).unwrap();
    let mut data = get_buf();

    b.iter(|| {
        cipher.encrypt(&mut data);
        test::black_box(&data);
    });

    b.bytes = data.len() as u64;
}

#[bench]
fn decrypt(b: &mut Bencher) {
    let (key, iv) = get_key_iv();
    let mut cipher = AesCfb8::new_var(key, iv).unwrap();
    let mut data = get_buf();

    b.iter(|| {
        cipher.decrypt(&mut data);
        test::black_box(&data);
    });

    b.bytes = data.len() as u64;
}
