#![feature(test)]

use cipher::{
    Array,
    consts::{U4, U64},
};
extern crate test;

cipher::stream_cipher_bench!(
    salsa20::Salsa8;
    salsa8_bench1_16b 16;
    salsa8_bench1_64b 64;
    salsa8_bench2_256b 256;
    salsa8_bench3_1kib 1024;
    salsa8_bench4_16kib 16384;
);

cipher::stream_cipher_bench!(
    salsa20::Salsa12;
    salsa12_bench1_16b 16;
    salsa12_bench1_64b 64;
    salsa12_bench2_256b 256;
    salsa12_bench3_1kib 1024;
    salsa12_bench4_16kib 16384;
);

cipher::stream_cipher_bench!(
    salsa20::Salsa20;
    salsa20_bench1_16b 16;
    salsa20_bench1_64b 64;
    salsa20_bench2_256b 256;
    salsa20_bench3_1kib 1024;
    salsa20_bench4_16kib 16384;
);

#[bench]
fn salsa8_bench1_chaining_altn(b: &mut test::Bencher) {
    use salsa20::SalsaChaining;
    use std::hash::{BuildHasher, Hasher};

    let seed = std::hash::RandomState::new().build_hasher().finish();

    let mut buf = [0u32; 16];
    buf[0] = seed as u32;
    buf[1] = (seed >> 32) as u32;

    b.iter(|| {
        let mut cipher = salsa20::SalsaCore::<U4>::from_raw_state_cv(buf);
        cipher.write_keystream_block_cv(&mut buf);
        test::black_box(&buf);
    });

    b.bytes = buf.len() as u64 * core::mem::size_of::<u32>() as u64;
}

#[bench]
fn salsa8_bench1_chaining(b: &mut test::Bencher) {
    use cipher::StreamCipherCore;
    use std::hash::{BuildHasher, Hasher};

    let seed = std::hash::RandomState::new().build_hasher().finish();

    let mut buf = [0u32; 16];
    buf[0] = seed as u32;
    buf[1] = (seed >> 32) as u32;

    b.iter(|| {
        let mut cipher = salsa20::SalsaCore::<U4>::from_raw_state(buf);
        cipher.write_keystream_block(unsafe {
            core::mem::transmute::<&mut [u32; 16], &mut Array<u8, U64>>(&mut buf)
        });
        test::black_box(&buf);
    });

    b.bytes = buf.len() as u64 * core::mem::size_of::<u32>() as u64;
}
