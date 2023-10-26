//! ChaCha20 benchmark
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};

const KB: usize = 1024;

fn bench(c: &mut Criterion<CyclesPerByte>) {
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

use chacha20::{
    ChaCha20Rng, rand_core::{SeedableRng, RngCore}
};
fn bench_chacha20rng(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("chacha20-ChaCha20Rng");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("fill_bytes", size), |b| {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            b.iter(|| rng.fill_bytes(&mut buf));
        });
    }

    group.finish();

    
    let mut original = c.benchmark_group("c2-chacha-ChaCha20Rng");

    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut buf = vec![0u8; *size];
        original.throughput(Throughput::Bytes(*size as u64));

        original.bench_function(BenchmarkId::new("fill_bytes", size), |b| {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
            b.iter(|| rng.fill_bytes(&mut buf));
        });
    }
    original.finish();
}

criterion_group!(
    name = benches_chacha20rng;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_chacha20rng
);

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);
criterion_main!(benches, benches_chacha20rng);
