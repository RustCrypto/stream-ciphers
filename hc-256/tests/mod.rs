use cipher::{KeyIvInit, StreamCipher};
use hc_256::Hc256;
use hex_literal::hex;

const KEY_BYTES: usize = 256 / 8;

const IV_BYTES: usize = 256 / 8;

const KEY0: [u8; KEY_BYTES] = [0; KEY_BYTES];

const KEY1: [u8; KEY_BYTES] = hex!(
    "55000000000000000000000000000000"
    "00000000000000000000000000000000"
);

const IV0: [u8; IV_BYTES] = [0; KEY_BYTES];

const IV1: [u8; IV_BYTES] = hex!(
    "01000000000000000000000000000000"
    "00000000000000000000000000000000"
);

const EXPECTED_KEY0_IV0: [u8; 64] = hex!(
    "5b078985d8f6f30d42c5c02fa6b67951"
    "53f06534801f89f24e74248b720b4818"
    "cd9227ecebcf4dbf8dbf6977e4ae14fa"
    "e8504c7bc8a9f3ea6c0106f5327e6981"
);

const EXPECTED_KEY0_IV1: [u8; 64] = hex!(
    "afe2a2bf4f17cee9fec2058bd1b18bb1"
    "5fc042ee712b3101dd501fc60b082a50"
    "06c7feed41923d6348c4daa6ff6185af"
    "5a13045e34c44894f3e9e72ddf0b5237"
);

const EXPECTED_KEY1_IV0: [u8; 64] = hex!(
    "1c404afe4fe25fed958f9ad1ae36c06f"
    "88a65a3cc0abe223aeb3902f420ed3a8"
    "6c3af05944eb396efb79758f5e7a1370"
    "d8b7106dcdf7d0adda233472e6dd75f5"
);

#[test]
fn test_hc256_key0_iv0() {
    for n in 1..64 {
        let mut cipher = Hc256::new_from_slices(&KEY0, &IV0).unwrap();
        let mut buf = EXPECTED_KEY0_IV0;
        for chunk in buf.chunks_mut(n) {
            cipher.apply_keystream(chunk);
        }
        assert!(buf.iter().all(|&v| v == 0));
    }
}

#[test]
fn test_hc256_key0_iv1() {
    for n in 1..64 {
        let mut cipher = Hc256::new_from_slices(&KEY0, &IV1).unwrap();
        let mut buf = EXPECTED_KEY0_IV1;
        for chunk in buf.chunks_mut(n) {
            cipher.apply_keystream(chunk);
        }
        assert!(buf.iter().all(|&v| v == 0));
    }
}

#[test]
fn test_hc256_key1_iv0() {
    for n in 1..64 {
        let mut cipher = Hc256::new_from_slices(&KEY1, &IV0).unwrap();
        let mut buf = EXPECTED_KEY1_IV0;
        for chunk in buf.chunks_mut(n) {
            cipher.apply_keystream(chunk);
        }
        assert!(buf.iter().all(|&v| v == 0));
    }
}
