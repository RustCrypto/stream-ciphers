//! Error types.
use core::fmt;
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Debug)]
pub struct InvalidKeyIvLength;

impl fmt::Display for InvalidKeyIvLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid length of key or IV")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKeyIvLength {
    fn description(&self) -> &str {
        "invalid length of key or IV"
    }
}
