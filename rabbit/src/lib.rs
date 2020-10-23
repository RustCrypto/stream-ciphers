//! This crate implements the Rabbit Stream Cipher Algorithm as described in [RFC 4503][1]
//!
//! [1]: https://tools.ietf.org/html/rfc4503#section-2.3

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![no_std]

pub use cipher;
use cipher::{
    stream::consts::{U16, U8},
    stream::LoopError,
    NewStreamCipher, SyncStreamCipher,
};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use core::{cmp::min, mem::replace};

/// RFC 4503. 2.3.  Key Setup Scheme (page 2).
pub const KEY_BYTE_LEN: usize = 16;
/// RFC 4503. 2.4.  IV Setup Scheme (page 2-3).
pub const IV_BYTE_LEN: usize = 8;

/// RFC 4503. 2.1.  Notation (page 2).
const WORDSIZE: u64 = 1 << 32;

const MESSAGE_BLOCK_BYTE_LEN: usize = 16;

/// RFC 4503. 2.5.  Counter System (page 3).
const A: [u32; 8] = [
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3,
];

/// Rabbit Stream Cipher Key.
pub type Key = cipher::stream::Key<Rabbit>;

/// Rabbit Stream Cipher Initialization Vector. See RFC 4503 3.2. Initialization Vector (page 5).
///
/// > It is possible to run Rabbit without the IV setup.  However, in this
/// > case, the generator must never be reset under the same key, since
/// > this would destroy its security (for a recent example, see [4]).
/// > However, in order to guarantee synchronization between sender and
/// > receiver, ciphers are frequently reset in practice.  This means that
/// > both sender and receiver set the inner state of the cipher back to a
/// > known value and then derive the new encryption state using an IV.  If
/// > this is done, it is important to make sure that no IV is ever reused
/// > under the same key.
///
/// [4]: http://eprint.iacr.org/2005/007.pdf
pub type Iv = cipher::stream::Nonce<Rabbit>;

/// RFC 4503. 2.2.  Inner State (page 2).
#[derive(Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
#[cfg_attr(feature = "zeroize", zeroize(drop))]
struct State {
    state_vars: [u32; 8],
    counter_vars: [u32; 8],
    carry_bit: u8,
}

/// RFC 4503. 2.3.  Key Setup Scheme (page 2).
fn setup_key(state: &mut State, key: [u8; KEY_BYTE_LEN]) {
    let mut k = [0u16; 8];

    k[0] = (key[0x0] as u16) | ((key[0x1] as u16) << 8);
    k[1] = (key[0x2] as u16) | ((key[0x3] as u16) << 8);
    k[2] = (key[0x4] as u16) | ((key[0x5] as u16) << 8);
    k[3] = (key[0x6] as u16) | ((key[0x7] as u16) << 8);
    k[4] = (key[0x8] as u16) | ((key[0x9] as u16) << 8);
    k[5] = (key[0xA] as u16) | ((key[0xB] as u16) << 8);
    k[6] = (key[0xC] as u16) | ((key[0xD] as u16) << 8);
    k[7] = (key[0xE] as u16) | ((key[0xF] as u16) << 8);

    for j in 0..8 {
        if j % 2 == 0 {
            state.state_vars[j] = ((k[(j + 1) % 8] as u32) << 16) | (k[j] as u32);
            state.counter_vars[j] = ((k[(j + 4) % 8] as u32) << 16) | (k[(j + 5) % 8] as u32);
        } else {
            state.state_vars[j] = ((k[(j + 5) % 8] as u32) << 16) | (k[(j + 4) % 8] as u32);
            state.counter_vars[j] = ((k[j] as u32) << 16) | (k[(j + 1) % 8] as u32);
        }
    }

    #[cfg(feature = "zeroize")]
    k.zeroize();

    for _ in 0..4 {
        next_state(state);
    }

    for j in 0..8 {
        state.counter_vars[j] ^= state.state_vars[(j + 4) % 8];
    }
}

/// RFC 4503. 2.4.  IV Setup Scheme (page 2-3).
fn setup_iv(state: &mut State, iv: [u8; IV_BYTE_LEN]) {
    let mut i = [0_u32; 4];

    i[0] = iv[0] as u32 | (iv[1] as u32) << 8 | (iv[2] as u32) << 16 | (iv[3] as u32) << 24;
    i[2] = iv[4] as u32 | (iv[5] as u32) << 8 | (iv[6] as u32) << 16 | (iv[7] as u32) << 24;
    i[1] = (i[0] >> 16) | (i[2] & 0xFFFF0000);
    i[3] = (i[2] << 16) | (i[0] & 0x0000FFFF);

    state.counter_vars[0] ^= i[0];
    state.counter_vars[1] ^= i[1];
    state.counter_vars[2] ^= i[2];
    state.counter_vars[3] ^= i[3];
    state.counter_vars[4] ^= i[0];
    state.counter_vars[5] ^= i[1];
    state.counter_vars[6] ^= i[2];
    state.counter_vars[7] ^= i[3];

    #[cfg(feature = "zeroize")]
    i.zeroize();

    for _ in 0..4 {
        next_state(state);
    }
}

/// RFC 4503. 2.5.  Counter System (page 3).
fn counter_update(state: &mut State) {
    #[allow(unused_mut, clippy::needless_range_loop)]
    for j in 0..8 {
        let mut temp = state.counter_vars[j] as u64 + A[j] as u64 + state.carry_bit as u64;
        state.carry_bit = ((temp / WORDSIZE) as u8) & 0b1;
        state.counter_vars[j] = (temp % WORDSIZE) as u32;
        #[cfg(feature = "zeroize")]
        temp.zeroize();
    }
}

/// RFC 4503. 2.6. Next-State Function (page 3-4).
fn next_state(state: &mut State) {
    let mut g = [0u32; 8];

    counter_update(state);

    #[allow(clippy::needless_range_loop)]
    for j in 0..8 {
        let u_plus_v = state.state_vars[j] as u64 + state.counter_vars[j] as u64;
        let square_uv = (u_plus_v % WORDSIZE) * (u_plus_v % WORDSIZE);
        g[j] = (square_uv ^ (square_uv >> 32)) as u32;
    }

    state.state_vars[0] = g[0]
        .wrapping_add(g[7].rotate_left(16))
        .wrapping_add(g[6].rotate_left(16));
    state.state_vars[1] = g[1].wrapping_add(g[0].rotate_left(8)).wrapping_add(g[7]);
    state.state_vars[2] = g[2]
        .wrapping_add(g[1].rotate_left(16))
        .wrapping_add(g[0].rotate_left(16));
    state.state_vars[3] = g[3].wrapping_add(g[2].rotate_left(8)).wrapping_add(g[1]);
    state.state_vars[4] = g[4]
        .wrapping_add(g[3].rotate_left(16))
        .wrapping_add(g[2].rotate_left(16));
    state.state_vars[5] = g[5].wrapping_add(g[4].rotate_left(8)).wrapping_add(g[3]);
    state.state_vars[6] = g[6]
        .wrapping_add(g[5].rotate_left(16))
        .wrapping_add(g[4].rotate_left(16));
    state.state_vars[7] = g[7].wrapping_add(g[6].rotate_left(8)).wrapping_add(g[5]);

    #[cfg(feature = "zeroize")]
    g.zeroize();
}

/// RFC 4503. 2.7. Extraction Scheme (page 4).
fn extract(state: &State) -> [u8; 16] {
    let mut s = [0u8; 16];

    let mut tmp = [0_u16; 8];

    tmp[0] = ((state.state_vars[0]) ^ (state.state_vars[5] >> 16)) as u16;
    tmp[1] = ((state.state_vars[0] >> 16) ^ (state.state_vars[3])) as u16;
    tmp[2] = ((state.state_vars[2]) ^ (state.state_vars[7] >> 16)) as u16;
    tmp[3] = ((state.state_vars[2] >> 16) ^ (state.state_vars[5])) as u16;
    tmp[4] = ((state.state_vars[4]) ^ (state.state_vars[1] >> 16)) as u16;
    tmp[5] = ((state.state_vars[4] >> 16) ^ (state.state_vars[7])) as u16;
    tmp[6] = ((state.state_vars[6]) ^ (state.state_vars[3] >> 16)) as u16;
    tmp[7] = ((state.state_vars[6] >> 16) ^ (state.state_vars[1])) as u16;

    s[0x0] = tmp[0] as u8;
    s[0x1] = (tmp[0] >> 8) as u8;
    s[0x2] = tmp[1] as u8;
    s[0x3] = (tmp[1] >> 8) as u8;
    s[0x4] = tmp[2] as u8;
    s[0x5] = (tmp[2] >> 8) as u8;
    s[0x6] = tmp[3] as u8;
    s[0x7] = (tmp[3] >> 8) as u8;
    s[0x8] = tmp[4] as u8;
    s[0x9] = (tmp[4] >> 8) as u8;
    s[0xA] = tmp[5] as u8;
    s[0xB] = (tmp[5] >> 8) as u8;
    s[0xC] = tmp[6] as u8;
    s[0xD] = (tmp[6] >> 8) as u8;
    s[0xE] = tmp[7] as u8;
    s[0xF] = (tmp[7] >> 8) as u8;

    #[cfg(feature = "zeroize")]
    tmp.zeroize();

    s
}

/// Rabbit stream cipher state.
#[cfg_attr(feature = "zeroize", derive(Zeroize))]
#[cfg_attr(feature = "zeroize", zeroize(drop))]
pub struct Rabbit {
    master_state: State,
    state: State,
    block: [u8; 16],
    block_idx: usize,
    block_num: u64,
}

impl Rabbit {
    /// Creates an empty rabbit state, then setups the given `key` on it.
    ///
    /// See RFC 4503 3.2. Initialization Vector (page 5).
    #[allow(unused_mut)]
    pub fn setup_without_iv(mut key: [u8; KEY_BYTE_LEN]) -> Rabbit {
        let mut master_state = Default::default();
        setup_key(&mut master_state, key);
        #[cfg(feature = "zeroize")]
        key.zeroize();

        let mut state = master_state.clone();
        next_state(&mut state);
        Rabbit {
            master_state,
            block: extract(&state),
            state,
            block_idx: 0,
            block_num: 0,
        }
    }

    /// Creates an empty rabbit state, then setups the given `key` and `iv` on it.
    #[allow(unused_mut)]
    pub fn setup(key: [u8; KEY_BYTE_LEN], mut iv: [u8; IV_BYTE_LEN]) -> Rabbit {
        let mut this = Self::setup_without_iv(key);
        this.state = this.master_state.clone();
        setup_iv(&mut this.state, iv);
        #[cfg(feature = "zeroize")]
        iv.zeroize();

        next_state(&mut this.state);
        this.block = extract(&this.state);
        this
    }

    /// Restores master state (iv will be lost).
    pub fn reset(&mut self) {
        self.state = self.master_state.clone();
        next_state(&mut self.state);
        self.block = extract(&self.state);
        self.block_idx = 0;
        self.block_num = 0;
    }

    /// Restores master state, than setups initialization vector `iv` on it.
    #[allow(unused_mut)]
    pub fn reinit(&mut self, mut iv: [u8; IV_BYTE_LEN]) {
        self.state = self.master_state.clone();
        setup_iv(&mut self.state, iv);
        #[cfg(feature = "zeroize")]
        iv.zeroize();

        next_state(&mut self.state);
        self.block = extract(&self.state);
        self.block_idx = 0;
        self.block_num = 0;
    }

    /// Encrypts bytes of `data` inplace.
    ///
    /// Returns:
    ///
    /// *   `true` – OK;
    /// *   `false` – max message length (16 * 2⁶⁴ bytes) was exceeded. `data` is not affected.
    pub fn encrypt_inplace(&mut self, data: &mut [u8]) -> bool {
        if !self.check_keystream_len(data.len()) {
            return false;
        }

        let prefix_len = min(
            (MESSAGE_BLOCK_BYTE_LEN - (self.block_idx as usize)) % MESSAGE_BLOCK_BYTE_LEN,
            data.len(),
        );
        let num_blocks = (data.len() - prefix_len) / MESSAGE_BLOCK_BYTE_LEN;
        let suffix_len = (data.len() - prefix_len) % MESSAGE_BLOCK_BYTE_LEN;

        let mut i = 0;
        let mut block_buf = [0_u8; MESSAGE_BLOCK_BYTE_LEN];

        for _ in 0..prefix_len {
            data[i] ^= self.get_s_byte();
            i += 1;
        }

        for _ in 0..num_blocks {
            block_buf.copy_from_slice(&data[i..i + MESSAGE_BLOCK_BYTE_LEN]);

            let lhs = u128::from_le_bytes(block_buf);
            let mut rhs = u128::from_le_bytes(self.get_s_block());

            rhs ^= lhs;

            (&mut data[i..i + MESSAGE_BLOCK_BYTE_LEN]).copy_from_slice(&rhs.to_le_bytes());

            i += MESSAGE_BLOCK_BYTE_LEN;
        }

        #[cfg(feature = "zeroize")]
        block_buf.zeroize();

        for _ in 0..suffix_len {
            data[i] ^= self.get_s_byte();
            i += 1;
        }

        true
    }

    /// Decrypts bytes of `data` inplace (see [`Rabbit::encrypt_inplace`]).
    #[inline(always)]
    pub fn decrypt_inplace(&mut self, data: &mut [u8]) -> bool {
        self.encrypt_inplace(data)
    }

    /// Returns `true` if keystream length is enough to encrypt `required` number of bytes.
    fn check_keystream_len(&self, required: usize) -> bool {
        let blocks_required = required / MESSAGE_BLOCK_BYTE_LEN;
        let blocks_remainig = u64::MAX - self.block_num;
        match blocks_remainig.cmp(&(blocks_required as u64)) {
            core::cmp::Ordering::Greater => true,
            core::cmp::Ordering::Equal => {
                let bytes_required = required % MESSAGE_BLOCK_BYTE_LEN;
                let bytes_remining = 0x10 - self.block_idx;
                match bytes_remining.cmp(&bytes_required) {
                    core::cmp::Ordering::Equal | core::cmp::Ordering::Greater => true,
                    core::cmp::Ordering::Less => false,
                }
            }
            core::cmp::Ordering::Less => false,
        }
    }

    /// Will consume the next byte of the keystream. The keystream will be moved one byte further.
    ///
    /// # Security Considerations
    ///
    /// Make sure to call this only if there is enough bytes in the keystream
    /// (see [`Rabbit::check_keystream_len`], RFC 4503 3.1. Message Length (page 5)).
    fn get_s_byte(&mut self) -> u8 {
        let byte = self.block[self.block_idx as usize];

        self.block_idx = (self.block_idx + 1) % MESSAGE_BLOCK_BYTE_LEN;
        if self.block_idx == 0 {
            #[cfg(feature = "zeroize")]
            self.block.zeroize();
            next_state(&mut self.state);
            self.block = extract(&self.state);
            self.block_num += 1;
        }

        byte
    }

    /// Will consume the next block of the keystream. The keystream will be moved one block further.
    ///
    /// # Requires
    ///
    /// *   `self.buf_idx == 0`
    ///
    /// # Security Considerations
    ///
    /// Make sure to call this only if there is enough bytes in the keystream
    /// (see [`Rabbit::check_keystream_len`], RFC 4503 3.1. Message Length (page 5)).
    fn get_s_block(&mut self) -> [u8; 16] {
        debug_assert_eq!(self.block_idx, 0, "Block is partially consumed");
        next_state(&mut self.state);
        self.block_num += 1;
        replace(&mut self.block, extract(&self.state))
    }
}

impl NewStreamCipher for Rabbit {
    type KeySize = U16;
    type NonceSize = U8;

    fn new(key: &cipher::stream::Key<Self>, iv: &cipher::stream::Nonce<Self>) -> Self {
        Self::setup((*key).into(), (*iv).into())
    }
}

impl SyncStreamCipher for Rabbit {
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        if self.encrypt_inplace(data) {
            Ok(())
        } else {
            Err(LoopError)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! test_raw {
        ($name:ident $wrap_name:ident $stream_name:ident
         key  = [$kf:expr, $ke:expr, $kd:expr, $kc:expr,
                 $kb:expr, $ka:expr, $k9:expr, $k8:expr,
                 $k7:expr, $k6:expr, $k5:expr, $k4:expr,
                 $k3:expr, $k2:expr, $k1:expr, $k0:expr]
         S[0] = [$s0f:expr, $s0e:expr, $s0d:expr, $s0c:expr,
                 $s0b:expr, $s0a:expr, $s09:expr, $s08:expr,
                 $s07:expr, $s06:expr, $s05:expr, $s04:expr,
                 $s03:expr, $s02:expr, $s01:expr, $s00:expr]
         S[1] = [$s1f:expr, $s1e:expr, $s1d:expr, $s1c:expr,
                 $s1b:expr, $s1a:expr, $s19:expr, $s18:expr,
                 $s17:expr, $s16:expr, $s15:expr, $s14:expr,
                 $s13:expr, $s12:expr, $s11:expr, $s10:expr]
         S[2] = [$s2f:expr, $s2e:expr, $s2d:expr, $s2c:expr,
                 $s2b:expr, $s2a:expr, $s29:expr, $s28:expr,
                 $s27:expr, $s26:expr, $s25:expr, $s24:expr,
                 $s23:expr, $s22:expr, $s21:expr, $s20:expr]) => {
            #[test]
            fn $name() {
                let key = [
                    $k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7, $k8, $k9, $ka, $kb, $kc, $kd, $ke, $kf,
                ];
                let s0 = [
                    $s00, $s01, $s02, $s03, $s04, $s05, $s06, $s07, $s08, $s09, $s0a, $s0b, $s0c,
                    $s0d, $s0e, $s0f,
                ];
                let s1 = [
                    $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19, $s1a, $s1b, $s1c,
                    $s1d, $s1e, $s1f,
                ];
                let s2 = [
                    $s20, $s21, $s22, $s23, $s24, $s25, $s26, $s27, $s28, $s29, $s2a, $s2b, $s2c,
                    $s2d, $s2e, $s2f,
                ];
                let mut state = Default::default();
                setup_key(&mut state, key);
                next_state(&mut state);
                assert_eq!(extract(&state), s0);
                next_state(&mut state);
                assert_eq!(extract(&state), s1);
                next_state(&mut state);
                assert_eq!(extract(&state), s2);
            }

            #[test]
            fn $wrap_name() {
                let key = [
                    $k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7, $k8, $k9, $ka, $kb, $kc, $kd, $ke, $kf,
                ];
                let s = [
                    $s00, $s01, $s02, $s03, $s04, $s05, $s06, $s07, $s08, $s09, $s0a, $s0b, $s0c,
                    $s0d, $s0e, $s0f, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19,
                    $s1a, $s1b, $s1c, $s1d, $s1e, $s1f, $s20, $s21, $s22, $s23, $s24, $s25, $s26,
                    $s27, $s28, $s29, $s2a, $s2b, $s2c, $s2d, $s2e, $s2f,
                ];

                let mut d;

                for n in 0..48 {
                    let s = &s[0..n];

                    d = [0; 48];
                    let mut rabbit = Rabbit::setup_without_iv(key);
                    rabbit.encrypt_inplace(&mut d[0..n]);
                    assert_eq!(&s[..], &d[0..n]);
                    assert_eq!(rabbit.block_num, (s.len() / MESSAGE_BLOCK_BYTE_LEN) as u64);

                    d = [0; 48];
                    rabbit.reset();
                    rabbit.encrypt_inplace(&mut d[0..n]);
                    assert_eq!(&s[..], &d[0..n]);
                    assert_eq!(rabbit.block_num, (s.len() / MESSAGE_BLOCK_BYTE_LEN) as u64);
                }
            }
        };
        ($name:ident $wrap_name:ident $stream_name:ident
         key  = [$kf:expr, $ke:expr, $kd:expr, $kc:expr,
                 $kb:expr, $ka:expr, $k9:expr, $k8:expr,
                 $k7:expr, $k6:expr, $k5:expr, $k4:expr,
                 $k3:expr, $k2:expr, $k1:expr, $k0:expr]
         iv   = [$iv7:expr, $iv6:expr, $iv5:expr, $iv4:expr,
                 $iv3:expr, $iv2:expr, $iv1:expr, $iv0:expr]
         S[0] = [$s0f:expr, $s0e:expr, $s0d:expr, $s0c:expr,
                 $s0b:expr, $s0a:expr, $s09:expr, $s08:expr,
                 $s07:expr, $s06:expr, $s05:expr, $s04:expr,
                 $s03:expr, $s02:expr, $s01:expr, $s00:expr]
         S[1] = [$s1f:expr, $s1e:expr, $s1d:expr, $s1c:expr,
                 $s1b:expr, $s1a:expr, $s19:expr, $s18:expr,
                 $s17:expr, $s16:expr, $s15:expr, $s14:expr,
                 $s13:expr, $s12:expr, $s11:expr, $s10:expr]
         S[2] = [$s2f:expr, $s2e:expr, $s2d:expr, $s2c:expr,
                 $s2b:expr, $s2a:expr, $s29:expr, $s28:expr,
                 $s27:expr, $s26:expr, $s25:expr, $s24:expr,
                 $s23:expr, $s22:expr, $s21:expr, $s20:expr]) => {
            #[test]
            fn $name() {
                let key = [
                    $k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7, $k8, $k9, $ka, $kb, $kc, $kd, $ke, $kf,
                ];
                let iv = [$iv0, $iv1, $iv2, $iv3, $iv4, $iv5, $iv6, $iv7];
                let s0 = [
                    $s00, $s01, $s02, $s03, $s04, $s05, $s06, $s07, $s08, $s09, $s0a, $s0b, $s0c,
                    $s0d, $s0e, $s0f,
                ];
                let s1 = [
                    $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19, $s1a, $s1b, $s1c,
                    $s1d, $s1e, $s1f,
                ];
                let s2 = [
                    $s20, $s21, $s22, $s23, $s24, $s25, $s26, $s27, $s28, $s29, $s2a, $s2b, $s2c,
                    $s2d, $s2e, $s2f,
                ];
                let mut state = Default::default();
                setup_key(&mut state, key);
                setup_iv(&mut state, iv);
                next_state(&mut state);
                assert_eq!(extract(&state), s0);
                next_state(&mut state);
                assert_eq!(extract(&state), s1);
                next_state(&mut state);
                assert_eq!(extract(&state), s2);
            }

            #[test]
            fn $wrap_name() {
                let key = [
                    $k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7, $k8, $k9, $ka, $kb, $kc, $kd, $ke, $kf,
                ];
                let iv = [$iv0, $iv1, $iv2, $iv3, $iv4, $iv5, $iv6, $iv7];
                let s = [
                    $s00, $s01, $s02, $s03, $s04, $s05, $s06, $s07, $s08, $s09, $s0a, $s0b, $s0c,
                    $s0d, $s0e, $s0f, $s10, $s11, $s12, $s13, $s14, $s15, $s16, $s17, $s18, $s19,
                    $s1a, $s1b, $s1c, $s1d, $s1e, $s1f, $s20, $s21, $s22, $s23, $s24, $s25, $s26,
                    $s27, $s28, $s29, $s2a, $s2b, $s2c, $s2d, $s2e, $s2f,
                ];

                let mut d;

                for n in 0..48 {
                    let s = &s[0..n];

                    d = [0; 48];
                    let mut rabbit = Rabbit::setup(key, iv);
                    rabbit.encrypt_inplace(&mut d[0..n]);
                    assert_eq!(&s[..], &d[0..n]);
                    assert_eq!(rabbit.block_num, (s.len() / MESSAGE_BLOCK_BYTE_LEN) as u64);

                    d = [0; 48];
                    rabbit.reinit(iv);
                    rabbit.encrypt_inplace(&mut d[0..n]);
                    assert_eq!(&s[..], &d[0..n]);
                    assert_eq!(rabbit.block_num, (s.len() / MESSAGE_BLOCK_BYTE_LEN) as u64);
                }
            }
        };
    }

    // RFC4503 Appendix A. A.1. Testing without IV Setup (page 7)
    test_raw! {
        without_iv_setup1
        wrapped_without_iv1
        stream_without_iv1
        key  = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
        S[0] = [0xB1,0x57,0x54,0xF0,0x36,0xA5,0xD6,0xEC,0xF5,0x6B,0x45,0x26,0x1C,0x4A,0xF7,0x02]
        S[1] = [0x88,0xE8,0xD8,0x15,0xC5,0x9C,0x0C,0x39,0x7B,0x69,0x6C,0x47,0x89,0xC6,0x8A,0xA7]
        S[2] = [0xF4,0x16,0xA1,0xC3,0x70,0x0C,0xD4,0x51,0xDA,0x68,0xD1,0x88,0x16,0x73,0xD6,0x96]
    }

    // RFC4503 Appendix A. A.1. Testing without IV Setup (page 7)
    test_raw! {
        without_iv_setup2
        wrapped_without_iv2
        stream_without_iv2
        key  = [0x91,0x28,0x13,0x29,0x2E,0x3D,0x36,0xFE,0x3B,0xFC,0x62,0xF1,0xDC,0x51,0xC3,0xAC]
        S[0] = [0x3D,0x2D,0xF3,0xC8,0x3E,0xF6,0x27,0xA1,0xE9,0x7F,0xC3,0x84,0x87,0xE2,0x51,0x9C]
        S[1] = [0xF5,0x76,0xCD,0x61,0xF4,0x40,0x5B,0x88,0x96,0xBF,0x53,0xAA,0x85,0x54,0xFC,0x19]
        S[2] = [0xE5,0x54,0x74,0x73,0xFB,0xDB,0x43,0x50,0x8A,0xE5,0x3B,0x20,0x20,0x4D,0x4C,0x5E]
    }

    // RFC4503 Appendix A. A.1. Testing without IV Setup (page 7)
    test_raw! {
        without_iv_setup3
        wrapped_without_iv3
        stream_without_iv3
        key  = [0x83,0x95,0x74,0x15,0x87,0xE0,0xC7,0x33,0xE9,0xE9,0xAB,0x01,0xC0,0x9B,0x00,0x43]
        S[0] = [0x0C,0xB1,0x0D,0xCD,0xA0,0x41,0xCD,0xAC,0x32,0xEB,0x5C,0xFD,0x02,0xD0,0x60,0x9B]
        S[1] = [0x95,0xFC,0x9F,0xCA,0x0F,0x17,0x01,0x5A,0x7B,0x70,0x92,0x11,0x4C,0xFF,0x3E,0xAD]
        S[2] = [0x96,0x49,0xE5,0xDE,0x8B,0xFC,0x7F,0x3F,0x92,0x41,0x47,0xAD,0x3A,0x94,0x74,0x28]
    }

    // RFC4503 Appendix A. A.2. Testing with IV Setup (page 7)
    test_raw! {
        with_iv_setup1
        wrapped_with_iv1
        stream_with_iv1
        key  = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
        iv   = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
        S[0] = [0xC6,0xA7,0x27,0x5E,0xF8,0x54,0x95,0xD8,0x7C,0xCD,0x5D,0x37,0x67,0x05,0xB7,0xED]
        S[1] = [0x5F,0x29,0xA6,0xAC,0x04,0xF5,0xEF,0xD4,0x7B,0x8F,0x29,0x32,0x70,0xDC,0x4A,0x8D]
        S[2] = [0x2A,0xDE,0x82,0x2B,0x29,0xDE,0x6C,0x1E,0xE5,0x2B,0xDB,0x8A,0x47,0xBF,0x8F,0x66]
    }

    // RFC4503 Appendix A. A.2. Testing with IV Setup (page 7)
    test_raw! {
        with_iv_setup2
        wrapped_with_iv2
        stream_with_iv2
        key  = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
        iv   = [0xC3,0x73,0xF5,0x75,0xC1,0x26,0x7E,0x59]
        S[0] = [0x1F,0xCD,0x4E,0xB9,0x58,0x00,0x12,0xE2,0xE0,0xDC,0xCC,0x92,0x22,0x01,0x7D,0x6D]
        S[1] = [0xA7,0x5F,0x4E,0x10,0xD1,0x21,0x25,0x01,0x7B,0x24,0x99,0xFF,0xED,0x93,0x6F,0x2E]
        S[2] = [0xEB,0xC1,0x12,0xC3,0x93,0xE7,0x38,0x39,0x23,0x56,0xBD,0xD0,0x12,0x02,0x9B,0xA7]
    }

    // RFC4503 Appendix A. A.2. Testing with IV Setup (page 7)
    test_raw! {
        with_iv_setup3
        wrapped_with_iv3
        stream_with_iv3
        key  = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
        iv   = [0xA6,0xEB,0x56,0x1A,0xD2,0xF4,0x17,0x27]
        S[0] = [0x44,0x5A,0xD8,0xC8,0x05,0x85,0x8D,0xBF,0x70,0xB6,0xAF,0x23,0xA1,0x51,0x10,0x4D]
        S[1] = [0x96,0xC8,0xF2,0x79,0x47,0xF4,0x2C,0x5B,0xAE,0xAE,0x67,0xC6,0xAC,0xC3,0x5B,0x03]
        S[2] = [0x9F,0xCB,0xFC,0x89,0x5F,0xA7,0x1C,0x17,0x31,0x3D,0xF0,0x34,0xF0,0x15,0x51,0xCB]
    }
}
