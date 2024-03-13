//! ChaCha20 benchmark
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use benches::{criterion_group_bench, Benchmarker};

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
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
            let mut cipher = ChaCha20::new(&key, &nonce);
            b.iter(|| cipher.apply_keystream(&mut buf));
        });
    }

    group.finish();
}

use chacha20::rand_core::{RngCore, SeedableRng};

fn bench_chacha20rng(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("ChaCha20Rng");
    
    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("fill_bytes", size), |b| {
            let mut rng = chacha20::ChaCha20Rng::from_seed([0u8; 32]);
            b.iter(|| rng.fill_bytes(&mut buf));
        });
    }

    group.finish();
}
criterion_group_bench!(
    benches_chacha20rng,
    bench_chacha20rng
);

criterion_group_bench!(
    benches,
    bench
);

criterion_main!(benches, benches_chacha20rng);