#![no_std]
#![feature(test)]
extern crate ctr;
extern crate aes;
extern crate test;
extern crate stream_cipher;

use aes::Aes128;
use stream_cipher::StreamCipherCore;

type Aes128Ctr = ctr::Ctr128<Aes128>;

#[bench]
pub fn aes128_ctr(bh: &mut test::Bencher) {
    let mut cipher = Aes128Ctr::new(&Default::default(), &Default::default());
    let mut data = [77u8; 1_000_000];
    bh.iter(|| {
        cipher.apply_keystream(&mut data);
        test::black_box(&data);
    });
    bh.bytes = data.len() as u64;
}
