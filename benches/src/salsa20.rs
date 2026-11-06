//! Salsa20 benchmark
use benches::{criterion_group_bench, Benchmarker};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa20,
};

const KB: usize = 1024;
fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("stream-cipher");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("apply_keystream", size), |b| {
            let key = Default::default();
            let nonce = Default::default();
            let mut cipher = Salsa20::new(&key, &nonce);
            b.iter(|| cipher.apply_keystream(&mut buf));
        });
    }

    group.finish();
}

criterion_group_bench!(benches, bench);

criterion_main!(benches);
