//! Equivalence tests between `rand_chacha` and `chacha20` RNGs.

#![cfg(feature = "rand_core")]

use proptest::prelude::*;
use rand_chacha::rand_core::{RngCore as OldRngCore, SeedableRng as OldSeedableRng};
use rand_core::{RngCore, SeedableRng};

// Number of reads to perform from the RNG in equivalence tests
const NREADS: usize = 16;

type Seed = <chacha20::ChaCha20Rng as SeedableRng>::Seed;

proptest! {
    #[test]
    fn rand_chacha_equivalence(
        seed in any::<Seed>(),
        reads in any::<[u16; NREADS]>()
    ) {
        let mut rng = chacha20::ChaCha20Rng::from_seed(seed);
        let mut reference_rng = rand_chacha::ChaCha20Rng::from_seed(seed);

        for nbytes in reads {
            let nbytes = nbytes as usize;

            let mut expected = [0u8; u16::MAX as usize];
            reference_rng.fill_bytes(&mut expected[..nbytes]);

            let mut actual = [0u8; u16::MAX as usize];
            rng.fill_bytes(&mut actual[..nbytes]);

            prop_assert_eq!(&expected[..nbytes], &actual[..nbytes]);
        }
    }
}
