use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, blobby};
use salsa20::{Salsa20, Salsa20_16};

static DATA: &[u8] = include_bytes!("data/ecrypt.blb");
static DATA_16: &[u8] = include_bytes!("data/ecrypt16.blb");

/// ECRYPT test vectors:
/// https://github.com/das-labor/legacy/blob/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-256.64-verified.test-vectors
#[test]
fn salsa20_ecrypt() {
    let test_vectors = blobby::Blob4Iterator::new(DATA).unwrap();
    for test_vector in test_vectors {
        let [key, iv, pos, expected] = test_vector.unwrap();

        let key = key.try_into().unwrap();
        let iv = iv.try_into().unwrap();
        let pos = u32::from_be_bytes(pos.try_into().unwrap());

        let mut c = Salsa20::new(key, iv);
        c.seek(pos);

        let mut buf = [0u8; 64];
        c.apply_keystream(&mut buf);

        assert_eq!(buf, expected);
    }
}

/// ECRYPT test vectors:
/// https://github.com/das-labor/legacy/blob/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-128.64-verified.test-vectors
#[test]
fn salsa20_ecrypt16() {
    let test_vectors = blobby::Blob4Iterator::new(DATA_16).unwrap();
    for test_vector in test_vectors {
        let [key, iv, pos, expected] = test_vector.unwrap();

        println!("key length: {}", key.len());
        let key = key.try_into().unwrap();
        let iv = iv.try_into().unwrap();
        let pos = u32::from_be_bytes(pos.try_into().unwrap());

        let mut c = Salsa20_16::new(key, iv);
        c.seek(pos);

        let mut buf = [0u8; 64];
        c.apply_keystream(&mut buf);

        assert_eq!(buf, expected);
    }
}