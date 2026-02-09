//! Basic benchmarks
#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    // TODO: use `Key:` option instead after macro is fixed upstream
    Init: {
        use cipher::KeyInit;
        let key = test::black_box(Default::default());
        rc4::Rc4::<cipher::consts::U5>::new(&key)
    };
    rc4_bench1_16b 16;
    rc4_bench2_256b 256;
    rc4_bench3_1kib 1024;
    rc4_bench4_16kib 16384;
);
