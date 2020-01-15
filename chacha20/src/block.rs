//! The ChaCha20 block function. Defined in RFC 8439 Section 2.3.
//!
//! <https://tools.ietf.org/html/rfc8439#section-2.3>

pub(crate) mod soft;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
mod sse2;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
)))]
pub(crate) use self::soft::Block;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
pub(crate) use self::sse2::Block;

use core::fmt::{self, Debug};

/// Common debug impl for all blocks
impl Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Block {{  .. }}")
    }
}
