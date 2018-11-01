extern crate aes;
extern crate cfb8;
extern crate blobby;

use cfb8::Cfb8;

macro_rules! new_test_async {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            use blobby::Blob4Iterator;

            fn run_test(key: &[u8], iv: &[u8], plaintext: &[u8], ciphertext: &[u8])
                -> Option<&'static str>
            {
                for n in 1..=plaintext.len() {
                    let mut mode = <$cipher>::new_var(key, iv).unwrap();
                    let mut buf = plaintext.to_vec();
                    for chunk in buf.chunks_mut(n) {
                        mode.encrypt(chunk);
                    }
                    if buf != &ciphertext[..] { return Some("encrypt"); }
                }

                for n in 1..=plaintext.len() {
                    let mut mode = <$cipher>::new_var(key, iv).unwrap();
                    let mut buf = ciphertext.to_vec();
                    for chunk in buf.chunks_mut(n) {
                        mode.decrypt(chunk);
                    }
                    if buf != &plaintext[..] { return Some("decrypt"); }
                }

                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let key = row[0];
                let iv = row[1];
                let plaintext = row[2];
                let ciphertext = row[3];
                if let Some(desc) = run_test(key, iv, plaintext, ciphertext) {
                    panic!("\n\
                        Failed test №{}: {}\n\
                        key:\t{:?}\n\
                        iv:\t{:?}\n\
                        plaintext:\t{:?}\n\
                        ciphertext:\t{:?}\n",
                        i, desc, key, iv, plaintext, ciphertext,
                    );
                }
            }

        }
    }
}

// tests vectors are from:
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
new_test_async!(cfb8_aes128, "aes128", Cfb8<aes::Aes128>);
new_test_async!(cfb8_aes192, "aes192", Cfb8<aes::Aes192>);
new_test_async!(cfb8_aes256, "aes256", Cfb8<aes::Aes256>);
