//! Autodetection support for AVX2 CPU intrinsics on x86 CPUs, with fallback
//! to the SSE2 backend when it's unavailable (the `sse2` target feature is
//! enabled-by-default on all x86(_64) CPUs)

use crate::{rounds::Rounds, IV_SIZE, KEY_SIZE, BLOCK_SIZE};
use super::{avx2, sse2};
use core::mem::ManuallyDrop;

/// Size of buffers passed to `generate` and `apply_keystream` for this
/// backend, which operates on two blocks in parallel for optimal performance.
pub(crate) const BUFFER_SIZE: usize = BLOCK_SIZE * 2;

cpuid_bool::new!(avx2_cpuid, "avx2");

/// The ChaCha20 core function.
pub struct Core<R: Rounds> {
    inner: Inner<R>,
    token: avx2_cpuid::InitToken,
}

union Inner<R: Rounds> {
    avx2: ManuallyDrop<avx2::Core<R>>,
    sse2: ManuallyDrop<sse2::Core<R>>,
}

impl<R: Rounds> Core<R> {
    /// Initialize ChaCha core function with the given key size, IV, and
    /// number of rounds.
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE], iv: [u8; IV_SIZE]) -> Self {
        let (token, avx2_present) = avx2_cpuid::init_get();

        let inner = if avx2_present {
            Inner {
                avx2: ManuallyDrop::new(avx2::Core::new(key, iv)),
            }
        } else {
            Inner {
                sse2: ManuallyDrop::new(sse2::Core::new(key, iv)),
            }
        };

        Self { inner, token }
    }

    /// Generate output, overwriting data already in the buffer
    #[inline]
    pub fn generate(&self, counter: u64, output: &mut [u8]) {
        if self.token.get() {
            unsafe { (*self.inner.avx2).generate(counter, output) }
        } else {
            unsafe { (*self.inner.sse2).generate(counter, output) }
        }
    }

    /// Apply generated keystream to the output buffer
    #[inline]
    #[cfg(feature = "cipher")]
    pub fn apply_keystream(&self, counter: u64, output: &mut [u8]) {
        if self.token.get() {
            unsafe { (*self.inner.avx2).apply_keystream(counter, output) }
        } else {
            unsafe { (*self.inner.sse2).apply_keystream(counter, output) }
        }
    }
}

impl<R: Rounds> Clone for Core<R> {
    fn clone(&self) -> Self {
        let inner = if self.token.get() {
            Inner {
                avx2: ManuallyDrop::new(unsafe { (*self.inner.avx2).clone() }),
            }
        } else {
            Inner {
                sse2: ManuallyDrop::new(unsafe { (*self.inner.sse2).clone() }),
            }
        };

        Self {
            inner,
            token: self.token,
        }
    }
}
