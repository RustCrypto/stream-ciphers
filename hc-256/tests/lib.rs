use block_cipher::generic_array::GenericArray;
use hc_256::HC256;
use stream_cipher::NewStreamCipher;
use stream_cipher::StreamCipher;

#[cfg(test)]
const KEY_BYTES: usize = 256 / 8;

#[cfg(test)]
const IV_BYTES: usize = 256 / 8;

#[cfg(test)]
const PAPER_KEY0: [u8; KEY_BYTES] = [0; KEY_BYTES];

#[cfg(test)]
const PAPER_KEY1: [u8; KEY_BYTES] = [
    0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

#[cfg(test)]
const PAPER_IV0: [u8; IV_BYTES] = [0; KEY_BYTES];

#[cfg(test)]
const PAPER_IV1: [u8; IV_BYTES] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[cfg(test)]
const EXPECTED_PAPER_KEY0_IV0: [u8; 64] = [
    0x5b, 0x07, 0x89, 0x85, 0xd8, 0xf6, 0xf3, 0x0d, 0x42, 0xc5, 0xc0, 0x2f, 0xa6, 0xb6, 0x79, 0x51,
    0x53, 0xf0, 0x65, 0x34, 0x80, 0x1f, 0x89, 0xf2, 0x4e, 0x74, 0x24, 0x8b, 0x72, 0x0b, 0x48, 0x18,
    0xcd, 0x92, 0x27, 0xec, 0xeb, 0xcf, 0x4d, 0xbf, 0x8d, 0xbf, 0x69, 0x77, 0xe4, 0xae, 0x14, 0xfa,
    0xe8, 0x50, 0x4c, 0x7b, 0xc8, 0xa9, 0xf3, 0xea, 0x6c, 0x01, 0x06, 0xf5, 0x32, 0x7e, 0x69, 0x81,
];

#[cfg(test)]
const EXPECTED_PAPER_KEY0_IV1: [u8; 64] = [
    0xaf, 0xe2, 0xa2, 0xbf, 0x4f, 0x17, 0xce, 0xe9, 0xfe, 0xc2, 0x05, 0x8b, 0xd1, 0xb1, 0x8b, 0xb1,
    0x5f, 0xc0, 0x42, 0xee, 0x71, 0x2b, 0x31, 0x01, 0xdd, 0x50, 0x1f, 0xc6, 0x0b, 0x08, 0x2a, 0x50,
    0x06, 0xc7, 0xfe, 0xed, 0x41, 0x92, 0x3d, 0x63, 0x48, 0xc4, 0xda, 0xa6, 0xff, 0x61, 0x85, 0xaf,
    0x5a, 0x13, 0x04, 0x5e, 0x34, 0xc4, 0x48, 0x94, 0xf3, 0xe9, 0xe7, 0x2d, 0xdf, 0x0b, 0x52, 0x37,
];

#[cfg(test)]
const EXPECTED_PAPER_KEY1_IV0: [u8; 64] = [
    0x1c, 0x40, 0x4a, 0xfe, 0x4f, 0xe2, 0x5f, 0xed, 0x95, 0x8f, 0x9a, 0xd1, 0xae, 0x36, 0xc0, 0x6f,
    0x88, 0xa6, 0x5a, 0x3c, 0xc0, 0xab, 0xe2, 0x23, 0xae, 0xb3, 0x90, 0x2f, 0x42, 0x0e, 0xd3, 0xa8,
    0x6c, 0x3a, 0xf0, 0x59, 0x44, 0xeb, 0x39, 0x6e, 0xfb, 0x79, 0x75, 0x8f, 0x5e, 0x7a, 0x13, 0x70,
    0xd8, 0xb7, 0x10, 0x6d, 0xcd, 0xf7, 0xd0, 0xad, 0xda, 0x23, 0x34, 0x72, 0xe6, 0xdd, 0x75, 0xf5,
];

#[test]
fn test_key0_iv0() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf = [0; 64];

    cipher.encrypt(&mut buf);

    for i in 0..64 {
        assert_eq!(buf[i], EXPECTED_PAPER_KEY0_IV0[i])
    }
}

#[test]
fn test_key0_iv0_offset_1() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 1];
    let mut buf2 = [0; 63];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..1 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..63 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 1])
    }
}

#[test]
fn test_key0_iv0_offset_2() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 2];
    let mut buf2 = [0; 62];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..2 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..62 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 2])
    }
}

#[test]
fn test_key0_iv0_offset_3() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 3];
    let mut buf2 = [0; 61];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..3 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..61 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 3])
    }
}

#[test]
fn test_key0_iv0_offset_4() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 4];
    let mut buf2 = [0; 60];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..4 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..60 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 4])
    }
}

#[test]
fn test_key0_iv0_offset_5() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 5];
    let mut buf2 = [0; 59];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..5 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..59 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 5])
    }
}

#[test]
fn test_key0_iv0_offset_6() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 6];
    let mut buf2 = [0; 58];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..6 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..58 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 6])
    }
}

#[test]
fn test_key0_iv0_offset_7() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 7];
    let mut buf2 = [0; 57];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..7 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..57 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 7])
    }
}

#[test]
fn test_key0_iv0_offset_8() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf1 = [0; 8];
    let mut buf2 = [0; 56];

    cipher.encrypt(&mut buf1);
    cipher.encrypt(&mut buf2);

    for i in 0..8 {
        assert_eq!(buf1[i], EXPECTED_PAPER_KEY0_IV0[i])
    }

    for i in 0..56 {
        assert_eq!(buf2[i], EXPECTED_PAPER_KEY0_IV0[i + 8])
    }
}

#[test]
fn test_key1_iv0() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY1),
        &GenericArray::from(PAPER_IV0),
    );
    let mut buf = [0; 64];

    cipher.encrypt(&mut buf);

    for i in 0..64 {
        assert_eq!(buf[i], EXPECTED_PAPER_KEY1_IV0[i])
    }
}

#[test]
fn test_key0_iv1() {
    let mut cipher = HC256::new(
        &GenericArray::from(PAPER_KEY0),
        &GenericArray::from(PAPER_IV1),
    );
    let mut buf = [0; 64];

    cipher.encrypt(&mut buf);

    for i in 0..64 {
        assert_eq!(buf[i], EXPECTED_PAPER_KEY0_IV1[i])
    }
}
