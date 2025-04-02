//! Distinguishing features of ChaCha variants.
//!
//! To be revisited for the 64-bit counter.

/// A trait that distinguishes some ChaCha variants
pub trait Variant: Clone {
    /// the size of the Nonce in u32s
    const NONCE_INDEX: usize;
    /// the number of u32s used for the counter
    const COUNTER_SIZE: usize;
    /// the maximum counter value with available keystream
    const MAX_USABLE_COUNTER: u64 = (u64::MAX >> ((2 - Self::COUNTER_SIZE) * 32));
}

#[derive(Clone)]
/// The details pertaining to the IETF variant
pub struct Ietf();
impl Variant for Ietf {
    const NONCE_INDEX: usize = 13;
    const COUNTER_SIZE: usize = 1;
}

#[derive(Clone)]
#[cfg(feature = "xchacha")]
pub struct XChaCha();

#[cfg(feature = "xchacha")]
impl Variant for XChaCha {
    const NONCE_INDEX: usize = 14;
    const COUNTER_SIZE: usize = 2;
}

#[derive(Clone)]
#[cfg(feature = "legacy")]
pub struct Legacy();

#[cfg(feature = "legacy")]
impl Variant for Legacy {
    const NONCE_INDEX: usize = 14;
    const COUNTER_SIZE: usize = 2;
}
