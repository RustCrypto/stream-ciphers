//! Generic implementation of CTR mode with a 32-bit counter
//! (big or little endian), generic over block ciphers.

use core::{convert::TryInto, marker::PhantomData, mem};
use stream_cipher::{
    block_cipher::{Block, BlockCipher},
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    FromBlockCipher, LoopError, SyncStreamCipher,
};

/// Internal buffer for a given block cipher
type BlockBuffer<B> = GenericArray<Block<B>, <B as BlockCipher>::ParBlocks>;

/// CTR mode with a 32-bit big endian counter.
///
/// Used by e.g. AES-GCM.
pub struct Ctr32BE<B>
where
    B: BlockCipher,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    Block<B>: Copy,
{
    ctr: Ctr32<B, BigEndian>,
}

/// CTR mode with a 32-bit little endian counter.
///
/// Used by e.g. AES-GCM-SIV.
pub struct Ctr32LE<B>
where
    B: BlockCipher,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    Block<B>: Copy,
{
    ctr: Ctr32<B, LittleEndian>,
}

impl<B> FromBlockCipher for Ctr32BE<B>
where
    B: BlockCipher,
    B::ParBlocks: ArrayLength<Block<B>>,
    Block<B>: Copy,
{
    type BlockCipher = B;
    type NonceSize = B::BlockSize;

    #[inline]
    fn from_block_cipher(cipher: B, nonce: &Block<B>) -> Self {
        Self {
            ctr: Ctr32::new(cipher, *nonce),
        }
    }
}

impl<B> FromBlockCipher for Ctr32LE<B>
where
    B: BlockCipher,
    B::ParBlocks: ArrayLength<Block<B>>,
    Block<B>: Copy,
{
    type BlockCipher = B;
    type NonceSize = B::BlockSize;

    #[inline]
    fn from_block_cipher(cipher: B, nonce: &Block<B>) -> Self {
        let mut counter_block = *nonce;
        counter_block[15] |= 0x80;

        Self {
            ctr: Ctr32::new(cipher, counter_block),
        }
    }
}

/// Implement `stream-cipher` traits for the given `Ctr32*` type
macro_rules! impl_ctr32 {
    ($ctr32:tt) => {
        impl<B> SyncStreamCipher for $ctr32<B>
        where
            B: BlockCipher,
            B::ParBlocks: ArrayLength<Block<B>>,
            Block<B>: Copy,
        {
            #[inline]
            fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
                // TODO(tarcieri): data volume limits
                self.ctr.apply_keystream(data);
                Ok(())
            }
        }

        impl<B> $ctr32<B>
        where
            B: BlockCipher,
            B::ParBlocks: ArrayLength<Block<B>>,
            Block<B>: Copy,
        {
            /// Seek to the given NIST SP800-38D counter value.
            ///
            /// Note: the serialized counter value is 1 larger than the argument value.
            // TODO(tarcieri): implement `SyncStreamCipherSeek`
            #[inline]
            pub fn seek_ctr(&mut self, pos: u32) {
                self.ctr.seek(pos);
            }

            /// Get the current NIST SP800-38D counter value.
            // TODO(tarcieri): implement `SyncStreamCipherSeek`
            #[inline]
            pub fn current_ctr(&self) -> u32 {
                self.ctr.current_pos()
            }
        }
    };
}

impl_ctr32!(Ctr32BE);
impl_ctr32!(Ctr32LE);

/// Inner CTR mode implementation with a 32-bit counter, generic over
/// block ciphers and endianness.
struct Ctr32<B, E>
where
    B: BlockCipher,
    B::ParBlocks: ArrayLength<Block<B>>,
    E: Endianness<B>,
    Block<B>: Copy,
{
    /// Cipher
    cipher: B,

    /// Keystream buffer
    buffer: BlockBuffer<B>,

    /// Current CTR value
    counter_block: Block<B>,

    /// Base value of the counter
    base_counter: u32,

    /// Endianness
    endianness: PhantomData<E>,
}

impl<B, E> Ctr32<B, E>
where
    B: BlockCipher,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
    E: Endianness<B>,
    Block<B>: Copy,
{
    /// Instantiate a new CTR instance
    pub fn new(cipher: B, counter_block: Block<B>) -> Self {
        Self {
            cipher,
            buffer: unsafe { mem::zeroed() },
            counter_block,
            base_counter: E::get_counter(&counter_block),
            endianness: PhantomData,
        }
    }

    /// "Seek" to the given NIST SP800-38D counter value.
    #[inline]
    pub fn seek(&mut self, new_counter_value: u32) {
        E::set_counter(
            &mut self.counter_block,
            new_counter_value.wrapping_add(self.base_counter),
        );
    }

    /// Get the current NIST SP800-38D counter value.
    #[inline]
    pub fn current_pos(&self) -> u32 {
        E::get_counter(&self.counter_block).wrapping_sub(self.base_counter)
    }

    /// Apply CTR keystream to the given input buffer
    #[inline]
    pub fn apply_keystream(&mut self, msg: &mut [u8]) {
        for chunk in msg.chunks_mut(B::BlockSize::to_usize() * B::ParBlocks::to_usize()) {
            self.apply_keystream_blocks(chunk);
        }
    }

    /// Apply `B::ParBlocks` parallel blocks of keystream to the input buffer
    fn apply_keystream_blocks(&mut self, msg: &mut [u8]) {
        let mut counter = E::get_counter(&self.counter_block);
        let n_blocks = msg.chunks(B::BlockSize::to_usize()).count();
        debug_assert!(n_blocks <= B::ParBlocks::to_usize());

        for block in self.buffer.iter_mut().take(n_blocks) {
            *block = self.counter_block;
            counter = counter.wrapping_add(1);
            E::set_counter(&mut self.counter_block, counter);
        }

        if n_blocks == 1 {
            self.cipher.encrypt_block(&mut self.buffer[0]);
        } else {
            self.cipher.encrypt_blocks(&mut self.buffer);
        }

        for (i, chunk) in msg.chunks_mut(B::BlockSize::to_usize()).enumerate() {
            let keystream_block = &self.buffer[i];

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream_block[i];
            }
        }
    }
}

/// Endianness-related functionality
trait Endianness<B: BlockCipher> {
    /// Get the counter value from a block
    fn get_counter(block: &Block<B>) -> u32;

    /// Set the counter inside of a block to the given value
    fn set_counter(block: &mut Block<B>, counter: u32);
}

/// Big endian 32-bit counter
struct BigEndian;

impl<B: BlockCipher> Endianness<B> for BigEndian {
    #[inline]
    fn get_counter(block: &Block<B>) -> u32 {
        let offset = B::BlockSize::to_usize() - mem::size_of::<u32>();
        u32::from_be_bytes(block[offset..].try_into().unwrap())
    }

    #[inline]
    fn set_counter(block: &mut Block<B>, value: u32) {
        let offset = B::BlockSize::to_usize() - mem::size_of::<u32>();
        block[offset..].copy_from_slice(&value.to_be_bytes());
    }
}

/// Little endian 32-bit counter
struct LittleEndian;

impl<B: BlockCipher> Endianness<B> for LittleEndian {
    #[inline]
    fn get_counter(block: &Block<B>) -> u32 {
        u32::from_le_bytes(block[..mem::size_of::<u32>()].try_into().unwrap())
    }

    #[inline]
    fn set_counter(block: &mut Block<B>, value: u32) {
        block[..mem::size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
    }
}

/// AES-128-CTR tests
///
/// NOTE: these test vectors were generated by first integration testing the
/// implementation in the contexts of AES-GCM and AES-GCM-SIV, with the former
/// tested against the NIST CAVS vectors, and the latter against the RFC8452
/// test vectors.
#[cfg(test)]
mod tests {
    use hex_literal::hex;
    const KEY: &[u8; 16] = &hex!("000102030405060708090A0B0C0D0E0F");

    mod be {
        use super::{hex, KEY};
        use stream_cipher::{NewStreamCipher, SyncStreamCipher};

        type Aes128Ctr = crate::Ctr32BE<aes::Aes128>;

        const NONCE1: &[u8; 16] = &hex!("11111111111111111111111111111111");
        const NONCE2: &[u8; 16] = &hex!("222222222222222222222222FFFFFFFE");

        #[test]
        fn counter_incr() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE1.into());
            assert_eq!(ctr.current_ctr(), 0);

            let mut buffer = [0u8; 64];
            ctr.apply_keystream(&mut buffer);

            assert_eq!(ctr.current_ctr(), 4);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "35D14E6D3E3A279CF01E343E34E7DED36EEADB04F42E2251AB4377F257856DBA
                     0AB37657B9C2AA09762E518FC9395D5304E96C34CCD2F0A95CDE7321852D90C0"
                )[..]
            );
        }

        #[test]
        fn counter_seek() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE1.into());
            ctr.seek_ctr(1);
            assert_eq!(ctr.current_ctr(), 1);

            let mut buffer = [0u8; 64];
            ctr.apply_keystream(&mut buffer);

            assert_eq!(ctr.current_ctr(), 5);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "6EEADB04F42E2251AB4377F257856DBA0AB37657B9C2AA09762E518FC9395D53
                     04E96C34CCD2F0A95CDE7321852D90C0F7441EAB3811A03FDBD162AEC402F5AA"
                )[..]
            );
        }

        #[test]
        fn keystream_xor() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE1.into());
            let mut buffer = [1u8; 64];

            ctr.apply_keystream(&mut buffer);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "34D04F6C3F3B269DF11F353F35E6DFD26FEBDA05F52F2350AA4276F356846CBB
                     0BB27756B8C3AB08772F508EC8385C5205E86D35CDD3F1A85DDF7220842C91C1"
                )[..]
            );
        }

        #[test]
        fn counter_wrap() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE2.into());
            assert_eq!(ctr.current_ctr(), 0);

            let mut buffer = [0u8; 64];
            ctr.apply_keystream(&mut buffer);

            assert_eq!(ctr.current_ctr(), 4);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "58FC849D1CF53C54C63E1B1D15CB3C8AAA335F72135585E9FF943F4DAC77CB63
                     BD1AE8716BE69C3B4D886B222B9B4E1E67548EF896A96E2746D8CA6476D8B183"
                )[..]
            );
        }
    }

    mod le {
        use super::{hex, KEY};
        use stream_cipher::{NewStreamCipher, SyncStreamCipher};

        type Aes128Ctr = crate::Ctr32LE<aes::Aes128>;

        const NONCE1: &[u8; 16] = &hex!("11111111111111111111111111111111");
        const NONCE2: &[u8; 16] = &hex!("FEFFFFFF222222222222222222222222");

        #[test]
        fn counter_incr() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE1.into());
            assert_eq!(ctr.current_ctr(), 0);

            let mut buffer = [0u8; 64];
            ctr.apply_keystream(&mut buffer);

            assert_eq!(ctr.current_ctr(), 4);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "2A0680B210CAD45E886D7EF6DAB357C9F18B39AFF6930FDB2D9FCE34261FF699
                     EB96774669D24B560C9AD028C5C39C4580775A82065256B4787DC91C6942B700"
                )[..]
            );
        }

        #[test]
        fn counter_seek() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE1.into());
            ctr.seek_ctr(1);
            assert_eq!(ctr.current_ctr(), 1);

            let mut buffer = [0u8; 64];
            ctr.apply_keystream(&mut buffer);

            assert_eq!(ctr.current_ctr(), 5);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "F18B39AFF6930FDB2D9FCE34261FF699EB96774669D24B560C9AD028C5C39C45
                     80775A82065256B4787DC91C6942B7001564DDA1B07DCED9201AB71BAF06905B"
                )[..]
            );
        }

        #[test]
        fn keystream_xor() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE1.into());
            let mut buffer = [1u8; 64];

            ctr.apply_keystream(&mut buffer);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "2B0781B311CBD55F896C7FF7DBB256C8F08A38AEF7920EDA2C9ECF35271EF798
                     EA97764768D34A570D9BD129C4C29D4481765B83075357B5797CC81D6843B601"
                )[..]
            );
        }

        #[test]
        fn counter_wrap() {
            let mut ctr = Aes128Ctr::new(KEY.into(), NONCE2.into());
            assert_eq!(ctr.current_ctr(), 0);

            let mut buffer = [0u8; 64];
            ctr.apply_keystream(&mut buffer);

            assert_eq!(ctr.current_ctr(), 4);
            assert_eq!(
                &buffer[..],
                &hex!(
                    "A1E649D8B382293DC28375C42443BB6A226BAADC9E9CCA8214F56E07A4024E06
                     6355A0DA2E08FB00112FFA38C26189EE55DD5B0B130ED87096FE01B59A665A60"
                )[..]
            );
        }
    }
}
