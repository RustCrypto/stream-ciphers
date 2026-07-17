//! Constant-time verification using dudect statistical timing tests.
//!
//! Run with: cargo run --release --example ctbench

use dudect_bencher::rand::{Rng, RngExt};
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use salsa20::cipher::{KeyIvInit, StreamCipher};

fn hsalsa20_key(runner: &mut CtRunner, rng: &mut BenchRng) {
    use salsa20::hsalsa;

    let input = [0x13u8; 16];
    let fixed_key = [0u8; 32];

    let mut inputs: Vec<([u8; 32], Class)> = Vec::with_capacity(100_000);
    for _ in 0..100_000 {
        if rng.random::<bool>() {
            inputs.push((fixed_key, Class::Left));
        } else {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            inputs.push((key, Class::Right));
        }
    }

    for (key, class) in &inputs {
        let key: salsa20::Key = (*key).into();
        let input: salsa20::cipher::array::Array<u8, salsa20::cipher::consts::U16> = input.into();
        runner.run_one(*class, || {
            let _ = hsalsa::<salsa20::cipher::typenum::U10>(&key, &input);
        });
    }
}

fn xsalsa20_key(runner: &mut CtRunner, rng: &mut BenchRng, size: usize, n: usize) {
    let nonce = [0x13u8; 24];
    let fixed_key = [0u8; 32];

    let mut inputs: Vec<([u8; 32], Class)> = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.random::<bool>() {
            inputs.push((fixed_key, Class::Left));
        } else {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            inputs.push((key, Class::Right));
        }
    }

    let mut buf = vec![0u8; size];
    for (key, class) in &inputs {
        buf.fill(0);
        let key = *key;
        let buf_ptr = buf.as_mut_ptr();
        let buf_len = buf.len();
        runner.run_one(*class, || {
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };
            let mut cipher = salsa20::XSalsa20::new((&key).into(), (&nonce).into());
            cipher.apply_keystream(buf);
        });
    }
}

fn xsalsa20_data(runner: &mut CtRunner, rng: &mut BenchRng, size: usize, n: usize) {
    let key = [0x42u8; 32];
    let nonce = [0x13u8; 24];

    let mut inputs: Vec<(Vec<u8>, Class)> = Vec::with_capacity(n);
    for _ in 0..n {
        if rng.random::<bool>() {
            inputs.push((vec![0u8; size], Class::Left));
        } else {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            inputs.push((data, Class::Right));
        }
    }

    let mut buf = vec![0u8; size];
    for (data, class) in &inputs {
        buf.copy_from_slice(data);
        let buf_ptr = buf.as_mut_ptr();
        let buf_len = buf.len();
        runner.run_one(*class, || {
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };
            let mut cipher = salsa20::XSalsa20::new((&key).into(), (&nonce).into());
            cipher.apply_keystream(buf);
        });
    }
}

fn xsalsa20_key_64(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_key(r, rng, 64, 100_000);
}
fn xsalsa20_key_256(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_key(r, rng, 256, 50_000);
}
fn xsalsa20_key_1024(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_key(r, rng, 1024, 10_000);
}
fn xsalsa20_key_4096(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_key(r, rng, 4096, 5_000);
}
fn xsalsa20_key_16384(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_key(r, rng, 16384, 2_000);
}
fn xsalsa20_key_65536(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_key(r, rng, 65536, 1_000);
}

fn xsalsa20_data_64(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_data(r, rng, 64, 100_000);
}
fn xsalsa20_data_256(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_data(r, rng, 256, 50_000);
}
fn xsalsa20_data_1024(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_data(r, rng, 1024, 10_000);
}
fn xsalsa20_data_4096(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_data(r, rng, 4096, 5_000);
}
fn xsalsa20_data_16384(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_data(r, rng, 16384, 2_000);
}
fn xsalsa20_data_65536(r: &mut CtRunner, rng: &mut BenchRng) {
    xsalsa20_data(r, rng, 65536, 1_000);
}

ctbench_main!(
    hsalsa20_key,
    xsalsa20_key_64,
    xsalsa20_key_256,
    xsalsa20_key_1024,
    xsalsa20_key_4096,
    xsalsa20_key_16384,
    xsalsa20_key_65536,
    xsalsa20_data_64,
    xsalsa20_data_256,
    xsalsa20_data_1024,
    xsalsa20_data_4096,
    xsalsa20_data_16384,
    xsalsa20_data_65536
);
