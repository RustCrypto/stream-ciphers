//! Tests for ChaCha20 (IETF and "djb" versions) as well as XChaCha20
#[cfg(feature = "cipher")]
use chacha20::ChaCha20;

#[cfg(feature = "legacy")]
use chacha20::ChaCha20Legacy;

#[cfg(feature = "xchacha")]
use chacha20::XChaCha20;

// IETF version of ChaCha20 (96-bit nonce)
#[cfg(feature = "cipher")]
cipher::stream_cipher_test!(chacha20_core, "chacha20", ChaCha20);
#[cfg(feature = "cipher")]
cipher::stream_cipher_seek_test!(chacha20_seek, ChaCha20);
#[cfg(feature = "xchacha")]
cipher::stream_cipher_seek_test!(xchacha20_seek, XChaCha20);
#[cfg(feature = "legacy")]
cipher::stream_cipher_seek_test!(chacha20legacy_seek, ChaCha20Legacy);

#[cfg(feature = "cipher")]
mod chacha20test {
    use chacha20::{ChaCha20, KeyIvInit};
    use cipher::StreamCipher;
    use hex_literal::hex;

    //
    // ChaCha20 test vectors from:
    // <https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2>
    //

    const KEY: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const IV: [u8; 12] = hex!("000000000000004a00000000");

    const PLAINTEXT: [u8; 114] = hex!(
        "
        4c616469657320616e642047656e746c
        656d656e206f662074686520636c6173
        73206f66202739393a20496620492063
        6f756c64206f6666657220796f75206f
        6e6c79206f6e652074697020666f7220
        746865206675747572652c2073756e73
        637265656e20776f756c642062652069
        742e
        "
    );

    const KEYSTREAM: [u8; 114] = hex!(
        "
        224f51f3401bd9e12fde276fb8631ded8c131f823d2c06
        e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b
        9334794cba40c63e34cdea212c4cf07d41b769a6749f3f
        630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a
        c40c5945398b6eda1a832c89c167eacd901d7e2bf363
        "
    );

    const CIPHERTEXT: [u8; 114] = hex!(
        "
        6e2e359a2568f98041ba0728dd0d6981
        e97e7aec1d4360c20a27afccfd9fae0b
        f91b65c5524733ab8f593dabcd62b357
        1639d624e65152ab8f530c359f0861d8
        07ca0dbf500d6a6156a38e088a22b65e
        52bc514d16ccf806818ce91ab7793736
        5af90bbf74a35be6b40b8eedf2785e42
        874d
        "
    );

    #[test]
    fn chacha20_keystream() {
        let mut cipher = ChaCha20::new(&KEY.into(), &IV.into());

        // The test vectors omit the first 64-bytes of the keystream
        let mut prefix = [0u8; 64];
        cipher.apply_keystream(&mut prefix);

        let mut buf = [0u8; 114];
        cipher.apply_keystream(&mut buf);
        assert_eq!(&buf[..], &KEYSTREAM[..]);
    }

    #[test]
    fn chacha20_encryption() {
        let mut cipher = ChaCha20::new(&KEY.into(), &IV.into());
        let mut buf = PLAINTEXT;

        // The test vectors omit the first 64-bytes of the keystream
        let mut prefix = [0u8; 64];
        cipher.apply_keystream(&mut prefix);

        cipher.apply_keystream(&mut buf);
        assert_eq!(&buf[..], &CIPHERTEXT[..]);
    }
}

#[rustfmt::skip]
#[cfg(feature = "xchacha")]
mod xchacha20 {
    use chacha20::{Key, XChaCha20, XNonce};
    use cipher::{KeyIvInit, StreamCipher};
    use hex_literal::hex;

    cipher::stream_cipher_seek_test!(xchacha20_seek, XChaCha20);

    //
    // XChaCha20 test vectors from:
    // <https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03#appendix-A.2>
    //

    const KEY: [u8; 32] = hex!("
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
    ");

    const IV: [u8; 24] = hex!("
        404142434445464748494a4b4c4d4e4f5051525354555658
    ");

    const PLAINTEXT: [u8; 304] = hex!("
        5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973
        20616c736f206b6e6f776e2061732074686520417369617469632077696c6420
        646f672c2072656420646f672c20616e642077686973746c696e6720646f672e
        2049742069732061626f7574207468652073697a65206f662061204765726d61
        6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061
        206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c
        757369766520616e6420736b696c6c6564206a756d70657220697320636c6173
        736966696564207769746820776f6c7665732c20636f796f7465732c206a6163
        6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963
        2066616d696c792043616e696461652e
    ");

    const KEYSTREAM: [u8; 304] = hex!("
        29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4
        cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25
        5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221
        5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60
        7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd
        241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f
        a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00
        b3df507ca8c924f7017b7e712d15a2eb5c50484451e54e1b4b995bd8fdd94597
        bb94d7af0b2c04df10ba0890899ed9293a0f55b8bafa999264035f1d4fbe7fe0
        aafa109a62372027e50e10cdfecca127
    ");

    const CIPHERTEXT: [u8; 304] = hex!("
        7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87
        ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05
        3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f
        7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201
        12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc
        047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63
        d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73
        c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4
        d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683
        8a9c71f70b5b5907a66f7ea49aadc409
    ");

    #[test]
    fn xchacha20_keystream() {
        let mut cipher = XChaCha20::new(&Key::from(KEY), &XNonce::from(IV));

        // The test vectors omit the first 64-bytes of the keystream
        let mut prefix = [0u8; 64];
        cipher.apply_keystream(&mut prefix);

        let mut buf = [0u8; 304];
        cipher.apply_keystream(&mut buf);
        assert_eq!(&buf[..], &KEYSTREAM[..]);
    }

    #[test]
    fn xchacha20_encryption() {
        let mut cipher = XChaCha20::new(&Key::from(KEY), &XNonce::from(IV));
        let mut buf = PLAINTEXT;

        // The test vectors omit the first 64-bytes of the keystream
        let mut prefix = [0u8; 64];
        cipher.apply_keystream(&mut prefix);

        cipher.apply_keystream(&mut buf);
        assert_eq!(&buf[..], &CIPHERTEXT[..]);
    }
}

// Legacy "djb" version of ChaCha20 (64-bit nonce)
#[cfg(feature = "legacy")]
#[rustfmt::skip]
mod legacy {
    use chacha20::{ChaCha20Legacy, LegacyNonce};
    use cipher::{StreamCipher, StreamCipherSeek, KeyIvInit};
    use hex_literal::hex;

    cipher::stream_cipher_test!(chacha20_legacy_core, "chacha20-legacy", ChaCha20Legacy);
    cipher::stream_cipher_seek_test!(chacha20_legacy_seek, ChaCha20Legacy);

    const KEY_LONG: [u8; 32] = hex!("
        0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
    ");

    const IV_LONG: [u8; 8] = hex!("0301040105090206");

    const EXPECTED_LONG: [u8; 256] = hex!("
        deeb6b9d06dff3e091bf3ad4f4d492b6dd98246f69691802e466e03bad235787
        0f1c6c010b6c2e650c4bf58d2d35c72ab639437069a384e03100078cc1d735a0
        db4e8f474ee6291460fd9197c77ed87b4c64e0d9ac685bd1c56cce021f3819cd
        13f49c9a3053603602582a060e59c2fbee90ab0bf7bb102d819ced03969d3bae
        71034fe598246583336aa744d8168e5dfff5c6d10270f125a4130e719717e783
        c0858b6f7964437173ea1d7556c158bc7a99e74a34d93da6bf72ac9736a215ac
        aefd4ec031f3f13f099e3d811d83a2cf1d544a68d2752409cc6be852b0511a2e
        32f69aa0be91b30981584a1c56ce7546cca24d8cfdfca525d6b15eea83b6b686
    ");

    #[test]
    #[ignore]
    fn chacha20_offsets() {
        for idx in 0..256 {
            for middle in idx..256 {
                for last in middle..256 {
                    let mut cipher =
                        ChaCha20Legacy::new(&KEY_LONG.into(), &LegacyNonce::from(IV_LONG));
                    let mut buf = [0; 256];

                    cipher.seek(idx as u64);
                    cipher.apply_keystream(&mut buf[idx..middle]);
                    cipher.apply_keystream(&mut buf[middle..last]);

                    for k in idx..last {
                        assert_eq!(buf[k], EXPECTED_LONG[k])
                    }
                }
            }
        }
    }
}

#[cfg(feature = "rng")]
mod rng_tests {
    use chacha20::{
        ChaCha20Rng,
        rand_core::{RngCore, SeedableRng},
    };
    use hex_literal::hex;

    const KEY: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn test_rng_output() {
        let mut rng = ChaCha20Rng::from_seed(KEY);
        let mut bytes = [0u8; 13];

        rng.fill_bytes(&mut bytes);
        assert_eq!(
            bytes,
            [177, 105, 126, 159, 198, 70, 30, 25, 131, 209, 49, 207, 105]
        );

        rng.fill_bytes(&mut bytes);
        assert_eq!(
            bytes,
            [167, 163, 252, 19, 79, 20, 152, 128, 232, 187, 43, 93, 35]
        );
    }

    #[test]
    fn test_chacha_true_values_a() {
        // Test vectors 1 and 2 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8,
            0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815,
            0x69b687c3, 0x8665eeb2,
        ];
        assert_eq!(results, expected);

        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612,
            0xed7aee32, 0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51,
            0x1f0ae1ac, 0x6f4d794b,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_true_values_b() {
        // Test vector 3 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Skip block 0
        for _ in 0..16 {
            rng.next_u32();
        }

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8,
            0x5aaa49c9, 0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8,
            0xebdd4aa6, 0xa0136c00,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_true_values_c() {
        // Test vector 4 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [
            0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let expected = [
            0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1,
            0xcaf09aae, 0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5,
            0x87f47473, 0x96f0992e,
        ];
        let expected_end = 3 * 16;
        let mut results = [0u32; 16];

        // Test block 2 by skipping block 0 and 1
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        for _ in 0..32 {
            rng1.next_u32();
        }
        for i in results.iter_mut() {
            *i = rng1.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng1.get_word_pos(), expected_end);

        // Test block 2 by using `set_word_pos`
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        rng2.set_word_pos(2 * 16);
        for i in results.iter_mut() {
            *i = rng2.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng2.get_word_pos(), expected_end);

        // Test block 2 by using `set_block_pos` and u32
        let mut rng3 = ChaCha20Rng::from_seed(seed);
        rng3.set_block_pos(2);
        results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng3.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng3.get_word_pos(), expected_end);

        // Test block 2 by using `set_block_pos` and [u8; 8]
        let mut rng4 = ChaCha20Rng::from_seed(seed);
        rng4.set_block_pos([2, 0, 0, 0, 0, 0, 0, 0]);
        results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng4.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng4.get_word_pos(), expected_end);

        // Test skipping behaviour with other types
        let mut buf = [0u8; 32];
        rng2.fill_bytes(&mut buf[..]);
        assert_eq!(rng2.get_word_pos(), expected_end + 8);
        rng2.fill_bytes(&mut buf[0..25]);
        assert_eq!(rng2.get_word_pos(), expected_end + 15);
        rng2.next_u64();
        assert_eq!(rng2.get_word_pos(), expected_end + 17);
        rng2.next_u32();
        rng2.next_u64();
        assert_eq!(rng2.get_word_pos(), expected_end + 20);
        rng2.fill_bytes(&mut buf[0..1]);
        assert_eq!(rng2.get_word_pos(), expected_end + 21);
    }

    #[test]
    fn test_chacha_multiple_blocks() {
        let seed = [
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Store the 17*i-th 32-bit word,
        // i.e., the i-th word of the i-th 16-word block
        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
            for _ in 0..16 {
                rng.next_u32();
            }
        }
        let expected = [
            0xf225c81a, 0x6ab1be57, 0x04d42951, 0x70858036, 0x49884684, 0x64efec72, 0x4be2d186,
            0x3615b384, 0x11cfa18e, 0xd3c50049, 0x75c775f6, 0x434c6530, 0x2c5bad8f, 0x898881dc,
            0x5f1c86d9, 0xc1f8e7f4,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_true_bytes() {
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut results = [0u8; 32];
        rng.fill_bytes(&mut results);
        let expected = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_construction() {
        let seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        assert_eq!(rng1.next_u32(), 137206642);

        assert_eq!(rng1.get_seed(), seed);

        let mut rng2 = ChaCha20Rng::from_rng(&mut rng1);
        assert_eq!(rng2.next_u32(), 1325750369);
    }

    #[test]
    fn test_chacha_nonce() {
        use hex_literal::hex;
        // Test vector 5 from
        // https://www.rfc-editor.org/rfc/rfc8439#section-2.3.2
        let seed = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut rng = ChaCha20Rng::from_seed(seed);

        let stream_id = hex!("0000004a00000000");
        rng.set_stream(stream_id);
        rng.set_block_pos(hex!("0000000000000009"));

        // The test vectors omit the first 64-bytes of the keystream
        let mut discard_first_64 = [0u8; 64];
        rng.fill_bytes(&mut discard_first_64);

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(results, expected);
    }

    #[test]
    fn test_chacha_nonce_2() {
        // Test vector 5 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        // Although we do not support setting a nonce, we try it here anyway so
        // we can use this test vector.
        let seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        // 96-bit nonce in LE order is: 0,0,0,0, 0,0,0,0, 0,0,0,2
        rng.set_stream(2u64 << (24 + 32));

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef, 0x88228b1a, 0x96a4dfb3, 0x5b76ab72,
            0xc727ee54, 0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297, 0x99c28f5f, 0x628314e8,
            0x398a19fa, 0x6ded1b53,
        ];
        assert_eq!(results, expected);
    }

    #[test]
    fn stream_id_endianness() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        assert_eq!(rng.get_word_pos(), 0);
        rng.set_stream([3, 3333]);
        assert_eq!(rng.get_word_pos(), 0);
        let expected = 1152671828;
        assert_eq!(rng.next_u32(), expected);
        let mut word_pos = rng.get_word_pos();

        assert_eq!(word_pos, 1);

        rng.set_stream(1234567);
        // these `word_pos == 0` might need to be changed if set_stream changes again
        assert_eq!(rng.get_word_pos(), 0);
        let mut block = [0u32; 16];
        for word in 0..block.len() {
            block[word] = rng.next_u32();
        }
        assert_eq!(rng.get_word_pos(), 16);
        // new `get_block_pos`
        assert_eq!(rng.get_block_pos(), 1);
        rng.set_stream(1234567);
        assert_eq!(rng.get_block_pos(), 0);
        assert_eq!(rng.get_word_pos(), 0);

        let expected = 3110319182;
        rng.set_word_pos(65); // old set_stream added 64 to the word_pos
        assert!(rng.next_u32() == expected);
        rng.set_word_pos(word_pos);

        word_pos = rng.get_word_pos();
        assert_eq!(word_pos, 2);
        rng.set_stream([1, 2, 3, 4, 5, 6, 7, 8]);
        rng.set_word_pos(130); // old set_stream added another 64 to the word_pos
        let expected = 3790367479;
        assert_eq!(rng.next_u32(), expected);
        rng.set_word_pos(word_pos);
    }

    /// Test vector 9 from https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/ChaCha20/counter-overflow.txt
    #[test]
    fn counter_wrap_1() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let block_pos = 18446744073709551615;
        assert_eq!(block_pos, u64::MAX);
        rng.set_block_pos(block_pos);

        let mut output = [0u8; 64 * 3];
        rng.fill_bytes(&mut output);
        let expected = hex!(
            "d7918cd8620cf832532652c04c01a553092cfb32e7b3f2f5467ae9674a2e9eec17368ec8027a357c0c51e6ea747121fec45284be0f099d2b3328845607b1768976b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
        );
        assert_eq!(expected, output);
    }

    /// Counts how many bytes were incorrect, and returns:
    ///
    /// (`index_of_first_incorrect_word`, `num_incorrect_bytes`)
    fn count_incorrect_bytes(expected: &[u8], output: &[u8]) -> (Option<usize>, u32) {
        assert_eq!(expected.len(), output.len());
        let mut num_incorrect_bytes = 0;
        let mut index_of_first_incorrect_word = None;
        expected
            .iter()
            .enumerate()
            .zip(output.iter())
            .for_each(|((i, a), b)| {
                if a.ne(b) {
                    if index_of_first_incorrect_word.is_none() {
                        index_of_first_incorrect_word = Some(i / 4)
                    }
                    num_incorrect_bytes += 1;
                }
            });
        (index_of_first_incorrect_word, num_incorrect_bytes)
    }

    /// Test vector 8 from https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/ciphers/ChaCha20/counter-overflow.txt
    #[test]
    fn counter_overflow_and_diagnostics() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let block_pos = 4294967295;
        assert_eq!(block_pos, u32::MAX as u64);
        rng.set_block_pos(4294967295);

        let mut output = [0u8; 64 * 4];
        rng.fill_bytes(&mut output[..64 * 3]);
        let block_before_overflow = hex!(
            "ace4cd09e294d1912d4ad205d06f95d9c2f2bfcf453e8753f128765b62215f4d92c74f2f626c6a640c0b1284d839ec81f1696281dafc3e684593937023b58b1d"
        );
        let first_block_after_overflow = hex!(
            "3db41d3aa0d329285de6f225e6e24bd59c9a17006943d5c9b680e3873bdc683a5819469899989690c281cd17c96159af0682b5b903468a61f50228cf09622b5a"
        );
        let second_block_after_overflow = hex!(
            "46f0f6efee15c8f1b198cb49d92b990867905159440cc723916dc0012826981039ce1766aa2542b05db3bd809ab142489d5dbfe1273e7399637b4b3213768aaa"
        );
        assert!(
            output[..64].eq(&block_before_overflow),
            "The first parblock was incorrect before overflow, indicating that ChaCha was not implemented correctly for this backend. Check the rounds() fn or the functions that it calls"
        );

        rng.set_block_pos(u32::MAX as u64 - 1);
        let mut skipped_blocks = [0u8; 64 * 3];
        rng.fill_bytes(&mut skipped_blocks);
        rng.fill_bytes(&mut output[64 * 3..]);

        output.chunks_exact(64).enumerate().skip(1).zip(&[first_block_after_overflow, second_block_after_overflow, second_block_after_overflow]).for_each(|((i, a), b)| {
            let (index_of_first_incorrect_word, num_incorrect_bytes) = count_incorrect_bytes(a, b);
            let msg = if num_incorrect_bytes == 0 {
                "The block was correct and this will not be shown"
            } else if num_incorrect_bytes > 32 {
                "Most of the block was incorrect, indicating an issue with the counter using 32-bit addition towards the beginning of fn rounds()"
            } else if num_incorrect_bytes <= 8 && matches!(index_of_first_incorrect_word, Some(12 | 13)) {
                "When the state was added to the results/res buffer at the end of fn rounds, the counter was probably incremented in 32-bit fashion for this parblock"
            } else {
                // this is probably unreachable in the event of a failed assertion, but it depends on the seed
                "Some of the block was incorrect"
            };
            assert!(a.eq(b), "PARBLOCK #{} uses incorrect counter addition\nDiagnostic = {}\nnum_incorrect_bytes = {}\nindex_of_first_incorrect_word = {:?}", i + 1, msg, num_incorrect_bytes, index_of_first_incorrect_word);
        });
    }
}
