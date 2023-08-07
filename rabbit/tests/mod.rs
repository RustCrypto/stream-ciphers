use cipher::{KeyInit, KeyIvInit, StreamCipher};
use hex_literal::hex;
use rabbit::{Rabbit, RabbitKeyOnly};

// RFC4503 Appendix A. A.1. Testing without IV Setup (page 7)
#[test]
fn test_rabbit_key_only() {
    let tests = [
        (
            hex!("00000000000000000000000000000000"),
            hex!(
                "02F74A1C26456BF5ECD6A536F05457B1"
                "A78AC689476C697B390C9CC515D8E888"
                "96D6731688D168DA51D40C70C3A116F4"
            ),
        ),
        (
            hex!("ACC351DCF162FC3BFE363D2E29132891"),
            hex!(
                "9C51E28784C37FE9A127F63EC8F32D3D"
                "19FC5485AA53BF96885B40F461CD76F5"
                "5E4C4D20203BE58A5043DBFB737454E5"
            ),
        ),
        (
            hex!("43009BC001ABE9E933C7E08715749583"),
            hex!(
                "9B60D002FD5CEB32ACCD41A0CD0DB10C"
                "AD3EFF4C1192707B5A01170FCA9FFC95"
                "2874943AAD4741923F7FFC8BDEE54996"
            ),
        ),
    ];
    for (key, ks) in tests.iter() {
        for n in 1..ks.len() {
            let mut rabbit = RabbitKeyOnly::new_from_slice(key).unwrap();
            let mut d = *ks;
            for chunk in d.chunks_mut(n) {
                rabbit.apply_keystream(chunk);
            }
            assert!(d.iter().all(|&v| v == 0));
        }
    }
}
// RFC4503 Appendix A. A.2. Testing with IV Setup (page 7)
#[test]
fn test_rabbit_key_iv() {
    let key = &hex!("00000000000000000000000000000000");
    let tests = [
        (
            hex!("0000000000000000"),
            hex!(
                "EDB70567375DCD7CD89554F85E27A7C6"
                "8D4ADC7032298F7BD4EFF504ACA6295F"
                "668FBF478ADB2BE51E6CDE292B82DE2A"
            ),
        ),
        (
            hex!("597E26C175F573C3"),
            hex!(
                "6D7D012292CCDCE0E2120058B94ECD1F"
                "2E6F93EDFF99247B012521D1104E5FA7"
                "A79B0212D0BD56233938E793C312C1EB"
            ),
        ),
        (
            hex!("2717F4D21A56EBA6"),
            hex!(
                "4D1051A123AFB670BF8D8505C8D85A44"
                "035BC3ACC667AEAE5B2CF44779F2C896"
                "CB5115F034F03D31171CA75F89FCCB9F"
            ),
        ),
    ];
    for (iv, ks) in tests.iter() {
        for n in 1..ks.len() {
            let mut rabbit = Rabbit::new_from_slices(key, iv).unwrap();
            let mut d = *ks;
            for chunk in d.chunks_mut(n) {
                rabbit.apply_keystream(chunk);
            }
            assert!(d.iter().all(|&v| v == 0));
        }
    }
}
