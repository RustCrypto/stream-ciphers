//! ChaCha20 benchmark
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use criterion_cycles_per_byte::CyclesPerByte;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};

const KB: usize = 1024;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
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

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn bench(c: &mut Criterion) {
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

use chacha20::rand_core::{SeedableRng, RngCore};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn bench_chacha20rng(c: &mut Criterion<CyclesPerByte>) {
    // by using the same group twice, it should allow us to see a direct comparison
    // of both implementations
    // it seems like it needs to be manually switched using comments
    let mut chacha_x86 = c.benchmark_group("chacha-SIMD-comparison");

    // no SIMD first
    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut buf = vec![0u8; *size];

        chacha_x86.throughput(Throughput::Bytes(*size as u64));

        chacha_x86.bench_function(BenchmarkId::new("fill_bytes", size), |b| {
            let mut rng = chacha20::ChaCha20Rng::from_seed([0u8; 32].into());
            //let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
            b.iter(|| rng.fill_bytes(&mut buf));
        });
    }

    chacha_x86.finish();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn bench_chacha20rng(c: &mut Criterion) {
    // by using the same group twice, it should allow us to see a direct comparison
    // of both implementations
    // it seems like it needs to be manually switched using comments
    let mut chacha_aarch64 = c.benchmark_group("chacha-SIMD-comparison");

    // no SIMD first
    for size in &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB] {
        let mut buf = vec![0u8; *size];

        chacha_aarch64.throughput(Throughput::Bytes(*size as u64));

        chacha_aarch64.bench_function(BenchmarkId::new("fill_bytes", size), |b| {
            let mut rng = chacha20::ChaCha20Rng::from_seed([0u8; 32].into());
            //let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
            b.iter(|| rng.fill_bytes(&mut buf));
        });
    }

    chacha_aarch64.finish();
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
criterion_group!(
    name = benches_chacha20rng;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_chacha20rng
);

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
criterion_group!(
    name = benches_chacha20rng;
    config = Criterion::default();
    targets = bench_chacha20rng
);

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench
);
criterion_main!(benches, benches_chacha20rng);
