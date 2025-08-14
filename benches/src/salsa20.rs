//! Salsa20 benchmark
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use benches::{criterion_group_bench, Benchmarker};

use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa20,
};

const KB: usize = 1024;

fn bench_salsa20(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("salsa20-stream-cipher");

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

// ARM NEON-specific benchmarks for detailed performance analysis
#[cfg(target_arch = "aarch64")]
fn bench_salsa20_neon_validation(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("salsa20-neon-validation");

    // Test sizes that demonstrate NEON benefits
    for size in &[64, 256, 1024, 4096, 16384] {
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("neon_optimized", size), |b| {
            let key = [0x80u8; 32]; // Use non-zero key for realistic testing
            let nonce = [0u8; 8];
            let mut cipher = Salsa20::new(&key.into(), &nonce.into());
            b.iter(|| {
                cipher = Salsa20::new(&key.into(), &nonce.into()); // Reset for each iteration
                cipher.apply_keystream(&mut buf);
            });
        });
    }

    group.finish();
}

// Parallel block processing validation benchmark
#[cfg(target_arch = "aarch64")]
fn bench_salsa20_parallel_blocks(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("salsa20-parallel-blocks");

    // Test sizes that trigger parallel 4-block processing
    for size in &[256, 1024, 4096, 16384] { // 4+ blocks
        let mut buf = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("parallel_4_blocks", size), |b| {
            let key = [0x42u8; 32];
            let nonce = [0x24u8; 8];
            let mut cipher = Salsa20::new(&key.into(), &nonce.into());
            b.iter(|| {
                cipher = Salsa20::new(&key.into(), &nonce.into());
                cipher.apply_keystream(&mut buf);
            });
        });
    }

    group.finish();
}

// Cross-validation benchmark: ensure NEON produces same results as software
#[cfg(target_arch = "aarch64")]
fn bench_salsa20_correctness_validation(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("salsa20-correctness");

    let size = 1024;
    let mut buf = vec![0u8; size];

    group.throughput(Throughput::Bytes(size as u64));

    group.bench_function("neon_correctness_check", |b| {
        let key = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nonce = [0u8; 8];
        
        b.iter(|| {
            let mut cipher = Salsa20::new(&key.into(), &nonce.into());
            cipher.apply_keystream(&mut buf);
            
            // Validate first 16 bytes match expected ECRYPT test vector
            let expected = [0xe3, 0xbe, 0x8f, 0xdd, 0x8b, 0xec, 0xa2, 0xe3,
                           0xea, 0x8e, 0xf9, 0x47, 0x5b, 0x29, 0xa6, 0xe7];
            assert_eq!(&buf[0..16], &expected, "NEON implementation correctness check failed");
        });
    });

    group.finish();
}

criterion_group_bench!(
    benches_salsa20,
    bench_salsa20
);

#[cfg(target_arch = "aarch64")]
criterion_group_bench!(
    benches_salsa20_neon,
    bench_salsa20_neon_validation
);

#[cfg(target_arch = "aarch64")]
criterion_group_bench!(
    benches_salsa20_parallel,
    bench_salsa20_parallel_blocks
);

#[cfg(target_arch = "aarch64")]
criterion_group_bench!(
    benches_salsa20_correctness,
    bench_salsa20_correctness_validation
);

#[cfg(target_arch = "aarch64")]
criterion_main!(
    benches_salsa20,
    benches_salsa20_neon,
    benches_salsa20_parallel,
    benches_salsa20_correctness
);

#[cfg(not(target_arch = "aarch64"))]
criterion_main!(benches_salsa20);
