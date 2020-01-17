//! Block RNG based on rand_core::BlockRng

use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{CryptoRng, Error, RngCore, SeedableRng};

use crate::{
    block::{Block, BUFFER_SIZE},
    KEY_SIZE,
};

macro_rules! impl_chacha_rng {
    ($name:ident, $core:ident, $rounds:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name(BlockRng<$core>);

        impl SeedableRng for $name {
            type Seed = [u8; KEY_SIZE];

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                let core = $core::from_seed(seed);
                Self(BlockRng::new(core))
            }
        }

        impl RngCore for $name {
            #[inline]
            fn next_u32(&mut self) -> u32 {
                self.0.next_u32()
            }

            #[inline]
            fn next_u64(&mut self) -> u64 {
                self.0.next_u64()
            }

            #[inline]
            fn fill_bytes(&mut self, bytes: &mut [u8]) {
                self.0.fill_bytes(bytes)
            }

            #[inline]
            fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
                self.0.try_fill_bytes(bytes)
            }
        }

        impl CryptoRng for $name {}

        #[doc = "Core random number generator, for use with [`rand_core::block::BlockRng`]"]
        #[derive(Clone, Debug)]
        pub struct $core {
            block: Block,
            counter: u64,
        }

        impl SeedableRng for $core {
            type Seed = [u8; KEY_SIZE];

            #[inline]
            fn from_seed(seed: Self::Seed) -> Self {
                let block = Block::new(&seed, Default::default(), $rounds);
                Self { block, counter: 0 }
            }
        }

        impl BlockRngCore for $core {
            type Item = u32;
            type Results = [u32; BUFFER_SIZE / 4];

            fn generate(&mut self, results: &mut Self::Results) {
                // TODO(tarcieri): eliminate unsafety (replace w\ [u8; BLOCK_SIZE)
                self.block.generate(self.counter, &mut unsafe {
                    *(results.as_mut_ptr() as *mut [u8; BUFFER_SIZE])
                });
                self.counter += 1;
            }
        }

        impl CryptoRng for $core {}
    }
}

impl_chacha_rng!(
    ChaCha8Rng,
    ChaCha8RngCore,
    8,
    "Random number generator over the ChaCha8 stream cipher."
);

impl_chacha_rng!(
    ChaCha12Rng,
    ChaCha12RngCore,
    12,
    "Random number generator over the ChaCha12 stream cipher."
);

impl_chacha_rng!(
    ChaCha20Rng,
    ChaCha20RngCore,
    20,
    "Random number generator over the ChaCha20 stream cipher."
);
