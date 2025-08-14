#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    salsa20::Salsa8;
    salsa8_bench1_16b 16;
    salsa8_bench2_256b 256;
    salsa8_bench3_1kib 1024;
    salsa8_bench4_16kib 16384;
);

cipher::stream_cipher_bench!(
    salsa20::Salsa12;
    salsa12_bench1_16b 16;
    salsa12_bench2_256b 256;
    salsa12_bench3_1kib 1024;
    salsa12_bench4_16kib 16384;
);

cipher::stream_cipher_bench!(
    salsa20::Salsa20;
    salsa20_bench1_16b 16;
    salsa20_bench2_256b 256;
    salsa20_bench3_1kib 1024;
    salsa20_bench4_16kib 16384;
);

// ARM NEON-specific benchmarks for aarch64 targets
#[cfg(target_arch = "aarch64")]
mod neon_benchmarks {
    use super::*;
    use salsa20::{
        Salsa20,
        cipher::{KeyIvInit, StreamCipher},
    };
    use test::Bencher;

    #[bench]
    fn salsa20_neon_64b(b: &mut Bencher) {
        let key = Default::default();
        let nonce = Default::default();
        let mut cipher = Salsa20::new(&key, &nonce);
        let mut data = [0u8; 64];
        b.iter(|| cipher.apply_keystream(&mut data));
        b.bytes = 64;
    }

    #[bench]
    fn salsa20_neon_1kib(b: &mut Bencher) {
        let key = Default::default();
        let nonce = Default::default();
        let mut cipher = Salsa20::new(&key, &nonce);
        let mut data = [0u8; 1024];
        b.iter(|| cipher.apply_keystream(&mut data));
        b.bytes = 1024;
    }

    #[bench]
    fn salsa20_neon_16kib(b: &mut Bencher) {
        let key = Default::default();
        let nonce = Default::default();
        let mut cipher = Salsa20::new(&key, &nonce);
        let mut data = [0u8; 16384];
        b.iter(|| cipher.apply_keystream(&mut data));
        b.bytes = 16384;
    }
}
