//! Block RNG based on rand_core::BlockRng

use core::slice;
use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{Error, RngCore, SeedableRng};

use crate::{block::Block, BLOCK_SIZE, KEY_SIZE, STATE_WORDS};

/// Random number generator over the ChaCha20 stream cipher.
#[derive(Clone, Debug)]
pub struct ChaCha20Rng(BlockRng<ChaCha20RngCore>);

impl SeedableRng for ChaCha20Rng {
    type Seed = [u8; KEY_SIZE];

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        let core = ChaCha20RngCore::from_seed(seed);
        Self(BlockRng::new(core))
    }
}

impl RngCore for ChaCha20Rng {
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

/// Core of the [`ChaCha20Rng`] random number generator, for use with
/// [`rand_core::block::BlockRng`].
#[derive(Clone, Debug)]
pub struct ChaCha20RngCore {
    block: Block,
    counter: u64,
}

impl SeedableRng for ChaCha20RngCore {
    type Seed = [u8; KEY_SIZE];

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        let block = Block::new(&seed, Default::default(), 20);
        Self { block, counter: 0 }
    }
}

impl BlockRngCore for ChaCha20RngCore {
    type Item = u32;
    type Results = [u32; STATE_WORDS];

    fn generate(&mut self, results: &mut Self::Results) {
        // TODO(tarcieri): eliminate unsafety (replace w\ [u8; BLOCK_SIZE)
        self.block.generate(self.counter, unsafe {
            slice::from_raw_parts_mut(results.as_mut_ptr() as *mut u8, BLOCK_SIZE)
        });
        self.counter += 1;
    }
}
