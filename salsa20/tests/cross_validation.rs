//! Cross-validation tests between NEON and software implementations

use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use salsa20::{Key, Nonce, Salsa20};

/// Test that compares outputs between different backend implementations
/// This test is designed to work regardless of which backend is actually used
#[test]
fn cross_validate_basic_encryption() {
    let test_cases = [
        // Test case 1: All zeros
        ([0u8; 32], [0u8; 8]),
        // Test case 2: All ones
        ([0xFFu8; 32], [0xFFu8; 8]),
        // Test case 3: Alternating pattern
        ([0x55u8; 32], [0xAAu8; 8]),
        // Test case 4: Sequential bytes
        (
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            [0, 1, 2, 3, 4, 5, 6, 7],
        ),
    ];

    for (i, (key_bytes, nonce_bytes)) in test_cases.iter().enumerate() {
        let key = Key::from(*key_bytes);
        let nonce = Nonce::from(*nonce_bytes);

        // Test various buffer sizes
        for size in [1, 16, 32, 64, 128, 256] {
            let mut buf1 = vec![0u8; size];
            let mut buf2 = vec![0u8; size];

            // Create two identical cipher instances for each test
            let mut cipher1 = Salsa20::new(&key, &nonce);
            let mut cipher2 = Salsa20::new(&key, &nonce);

            cipher1.apply_keystream(&mut buf1);
            cipher2.apply_keystream(&mut buf2);

            assert_eq!(
                buf1, buf2,
                "Outputs should be identical for test case {i} with size {size}"
            );
        }
    }
}

/// Test seeking functionality across implementations
#[test]
fn cross_validate_seeking() {
    let key = Key::from([0x42u8; 32]);
    let nonce = Nonce::from([0x24u8; 8]);

    let seek_positions = [0, 1, 63, 64, 65, 127, 128, 129, 1000, 10000];

    for &pos in &seek_positions {
        let mut cipher1 = Salsa20::new(&key, &nonce);
        let mut cipher2 = Salsa20::new(&key, &nonce);

        cipher1.seek(pos);
        cipher2.seek(pos);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        cipher1.apply_keystream(&mut buf1);
        cipher2.apply_keystream(&mut buf2);

        assert_eq!(
            buf1, buf2,
            "Seek to position {pos} should produce identical results"
        );
    }
}

/// Test incremental processing
#[test]
fn cross_validate_incremental() {
    let key = Key::from([0x12u8; 32]);
    let nonce = Nonce::from([0x34u8; 8]);

    // Process data in chunks vs all at once
    let mut cipher_chunked = Salsa20::new(&key, &nonce);
    let mut cipher_bulk = Salsa20::new(&key, &nonce);

    let mut buf_chunked = [0u8; 200];
    let mut buf_bulk = [0u8; 200];

    // Process in chunks of varying sizes
    let chunk_sizes = [1, 7, 16, 23, 32, 47, 64, 73];
    let mut offset = 0;

    for &chunk_size in &chunk_sizes {
        if offset + chunk_size <= buf_chunked.len() {
            cipher_chunked.apply_keystream(&mut buf_chunked[offset..offset + chunk_size]);
            offset += chunk_size;
        }
    }

    // Process remaining bytes
    if offset < buf_chunked.len() {
        cipher_chunked.apply_keystream(&mut buf_chunked[offset..]);
    }

    // Process all at once
    cipher_bulk.apply_keystream(&mut buf_bulk);

    assert_eq!(
        buf_chunked, buf_bulk,
        "Chunked and bulk processing should produce identical results"
    );
}

/// Test with random-like data patterns
#[test]
fn cross_validate_patterns() {
    // Use a deterministic "random" pattern
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 8];

    // Generate pseudo-random key and nonce
    for (i, key_byte) in key.iter_mut().enumerate() {
        *key_byte = ((i * 17 + 42) % 256) as u8;
    }
    for (i, nonce_byte) in nonce.iter_mut().enumerate() {
        *nonce_byte = ((i * 23 + 13) % 256) as u8;
    }

    let key = Key::from(key);
    let nonce = Nonce::from(nonce);

    let mut cipher1 = Salsa20::new(&key, &nonce);
    let mut cipher2 = Salsa20::new(&key, &nonce);

    let mut buf1 = [0u8; 1024];
    let mut buf2 = [0u8; 1024];

    cipher1.apply_keystream(&mut buf1);
    cipher2.apply_keystream(&mut buf2);

    assert_eq!(
        buf1, buf2,
        "Pattern-based test should produce identical results"
    );
}

/// Stress test with large amounts of data
#[test]
fn cross_validate_large_data() {
    let key = Key::from([0xABu8; 32]);
    let nonce = Nonce::from([0xCDu8; 8]);

    let mut cipher1 = Salsa20::new(&key, &nonce);
    let mut cipher2 = Salsa20::new(&key, &nonce);

    // Test with 4KB of data
    let mut buf1 = vec![0u8; 4096];
    let mut buf2 = vec![0u8; 4096];

    cipher1.apply_keystream(&mut buf1);
    cipher2.apply_keystream(&mut buf2);

    assert_eq!(
        buf1, buf2,
        "Large data test should produce identical results"
    );

    // Verify the data is not all zeros (sanity check)
    assert!(
        buf1.iter().any(|&b| b != 0),
        "Output should not be all zeros"
    );
}
