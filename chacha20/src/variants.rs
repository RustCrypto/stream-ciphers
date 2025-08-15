//! Distinguishing features of ChaCha variants.
//!
//! To be revisited for the 64-bit counter.

/// A trait that distinguishes some ChaCha variants
pub trait Variant: Clone {
    /// the size of the Nonce in u32s
    const NONCE_INDEX: usize;
    const COUNTER_MAX: u64;
}

#[derive(Clone)]
/// The details pertaining to the IETF variant
pub struct Ietf();
impl Variant for Ietf {
    const NONCE_INDEX: usize = 13;
    const COUNTER_MAX: u64 = u32::MAX as u64;
}

#[derive(Clone)]
#[cfg(feature = "legacy")]
pub struct Legacy();

#[cfg(feature = "legacy")]
impl Variant for Legacy {
    const NONCE_INDEX: usize = 14;
    const COUNTER_MAX: u64 = u64::MAX;
}
