#![no_std]
#![feature(test)]
extern crate aes_ctr;
extern crate test;

use aes_ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
use aes_ctr::stream_cipher::StreamCipherCore;

#[bench]
pub fn aes128_ctr(bh: &mut test::Bencher) {
    let mut cipher = Aes128Ctr::new(&Default::default(), &Default::default());
    let mut data = [77u8; 10_000];
    bh.iter(|| {
        cipher.apply_keystream(&mut data);
        test::black_box(&data);
    });
    bh.bytes = data.len() as u64;
}

#[bench]
pub fn aes192_ctr(bh: &mut test::Bencher) {
    let mut cipher = Aes192Ctr::new(&Default::default(), &Default::default());
    let mut data = [77u8; 10_000];
    bh.iter(|| {
        cipher.apply_keystream(&mut data);
        test::black_box(&data);
    });
    bh.bytes = data.len() as u64;
}

#[bench]
pub fn aes256_ctr(bh: &mut test::Bencher) {
    let mut cipher = Aes256Ctr::new(&Default::default(), &Default::default());
    let mut data = [77u8; 10_000];
    bh.iter(|| {
        cipher.apply_keystream(&mut data);
        test::black_box(&data);
    });
    bh.bytes = data.len() as u64;
}
