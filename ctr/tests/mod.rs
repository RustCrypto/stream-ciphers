extern crate aes;
extern crate blobby;
extern crate ctr;
#[macro_use]
extern crate stream_cipher;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use stream_cipher::SyncStreamCipher;

type Aes128Ctr = ctr::Ctr128<aes::Aes128>;
type Aes256Ctr = ctr::Ctr128<aes::Aes256>;

new_sync_test!(aes128_ctr_core, Aes128Ctr, "aes128-ctr");
new_seek_test!(aes128_ctr_seek, Aes128Ctr, "aes128-ctr");
new_sync_test!(aes256_ctr_core, Aes256Ctr, "aes256-ctr");
new_seek_test!(aes256_ctr_seek, Aes256Ctr, "aes256-ctr");

#[test]
fn test_from_cipher() {
    let data = include_bytes!("data/aes128-ctr.blb");
    for row in blobby::Blob4Iterator::new(data).unwrap() {
        let key = row[0];
        let iv = GenericArray::from_slice(row[1]);
        let plaintext = row[2];
        let ciphertext = row[3];

        let block_cipher = aes::Aes128::new_varkey(key).unwrap();
        let mut cipher = ctr::Ctr128::from_cipher(block_cipher, iv);

        let mut buf = plaintext.to_vec();
        cipher.apply_keystream(&mut buf);
        assert_eq!(&buf, &ciphertext);
    }
}
