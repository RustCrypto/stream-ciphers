//! XSalsa20 is an extended nonce variant of Salsa20

use crate::{block::quarter_round, Salsa20, CONSTANTS};
use core::convert::TryInto;
use stream_cipher::generic_array::{
    typenum::{U16, U24, U32},
    GenericArray,
};
use stream_cipher::{LoopError, NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};

/// XSalsa20 is a Salsa20 variant with an extended 192-bit (24-byte) nonce.
///
/// Based on the paper "Extending the Salsa20 Nonce":
///
/// <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>
///
/// The `xsalsa20` Cargo feature must be enabled in order to use this
/// (which it is by default).
pub struct XSalsa20(Salsa20);

impl NewStreamCipher for XSalsa20 {
    /// Key size in bytes
    type KeySize = U32;

    /// Nonce size in bytes
    type NonceSize = U24;

    #[allow(unused_mut, clippy::let_and_return)]
    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut subkey = hsalsa20(key, iv[..16].as_ref().into());
        let mut padded_iv = GenericArray::default();
        padded_iv.copy_from_slice(&iv[16..]);

        let mut result = XSalsa20(Salsa20::new(&subkey, &padded_iv));

        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            subkey.as_mut_slice().zeroize();
        }

        result
    }
}

impl SyncStreamCipher for XSalsa20 {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.0.try_apply_keystream(data)
    }
}

impl SyncStreamCipherSeek for XSalsa20 {
    fn current_pos(&self) -> u64 {
        self.0.current_pos()
    }

    fn seek(&mut self, pos: u64) {
        self.0.seek(pos);
    }
}

/// HSalsa20 takes 512-bits of input:
///
/// * Constants (`u32` x 4)
/// * Key (`u32` x 8)
/// * Nonce (`u32` x 4)
///
/// It produces 256-bits of output suitable for use as a Salsa20 key
///
/// For more information on HSalsa20, see:
///
/// <http://cr.yp.to/snuffle/xsalsa-20110204.pdf>
fn hsalsa20(key: &GenericArray<u8, U32>, input: &GenericArray<u8, U16>) -> GenericArray<u8, U32> {
    let mut state = [0u32; 16];

    state[0] = CONSTANTS[0];
    state[5] = CONSTANTS[1];
    state[10] = CONSTANTS[2];
    state[15] = CONSTANTS[3];

    for (i, chunk) in key.chunks(4).take(4).enumerate() {
        state[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    for (i, chunk) in key.chunks(4).skip(4).enumerate() {
        state[11 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    for (i, chunk) in input.chunks(4).enumerate() {
        state[6 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // 20 rounds consisting of 10 column rounds and 10 diagonal rounds
    for _ in 0..10 {
        // column rounds
        quarter_round(0, 4, 8, 12, &mut state);
        quarter_round(5, 9, 13, 1, &mut state);
        quarter_round(10, 14, 2, 6, &mut state);
        quarter_round(15, 3, 7, 11, &mut state);

        // diagonal rounds
        quarter_round(0, 1, 2, 3, &mut state);
        quarter_round(5, 6, 7, 4, &mut state);
        quarter_round(10, 11, 8, 9, &mut state);
        quarter_round(15, 12, 13, 14, &mut state);
    }

    let mut output = GenericArray::default();
    let key_idx: [usize; 8] = [0, 5, 10, 15, 6, 7, 8, 9];

    for (i, chunk) in output.chunks_mut(4).enumerate() {
        chunk.copy_from_slice(&state[key_idx[i]].to_le_bytes());
    }

    output
}
