//! Autodetection support for AVX2 CPU intrinsics on x86 CPUs, with fallback
//! to the SSE2 backend when it's unavailable (the `sse2` target feature is
//! enabled-by-default on all x86(_64) CPUs)

use crate::{rounds::Rounds, IV_SIZE, KEY_SIZE, BLOCK_SIZE};
use super::{avx2, sse2};

/// Size of buffers passed to `generate` and `apply_keystream` for this
/// backend, which operates on two blocks in parallel for optimal performance.
pub(crate) const BUFFER_SIZE: usize = BLOCK_SIZE * 2;

cpuid_bool::new!(avx2_cpuid, "avx2");

pub struct State<R: Rounds> {
    inner: Inner<R>,
    token: avx2_cpuid::InitToken,
}

union Inner<R: Rounds> {
    avx2: avx2::State<R>,
    sse2: sse2::State<R>,
}

impl<R: Rounds> State<R> {
    /// Initialize ChaCha block function with the given key size, IV, and
    /// number of rounds.
    #[inline]
    pub(crate) fn new(key: &[u8; KEY_SIZE], iv: [u8; IV_SIZE]) -> Self {
        let (token, avx2_present) = avx2_cpuid::init_get();

        let inner = if avx2_present {
            Inner {
                avx2: avx2::State::new(key, iv),
            }
        } else {
            Inner {
                sse2: sse2::State::new(key, iv),
            }
        };

        Self { inner, token }
    }

    #[inline]
    pub(crate) fn generate(&self, counter: u64, output: &mut [u8]) {
        if self.token.get() {
            unsafe { self.inner.avx2.generate(counter, output) }
        } else {
            unsafe { self.inner.sse2.generate(counter, output) }
        }
    }

    #[inline]
    #[cfg(feature = "cipher")]
    pub(crate) fn apply_keystream(&self, counter: u64, output: &mut [u8]) {
        if self.token.get() {
            unsafe { self.inner.avx2.apply_keystream(counter, output) }
        } else {
            unsafe { self.inner.sse2.apply_keystream(counter, output) }
        }
    }
}

impl<R: Rounds> Clone for State<R> {
    fn clone(&self) -> Self {
        let inner = if self.token.get() {
            Inner {
                avx2: unsafe { self.inner.avx2 },
            }
        } else {
            Inner {
                sse2: unsafe { self.inner.sse2 },
            }
        };

        Self {
            inner,
            token: self.token,
        }
    }
}
