//! Error types.
use core::fmt;
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Debug)]
pub struct InvalidKeyIvLength;

#[derive(Copy, Clone, Debug)]
pub struct InvalidMessageLength;

impl fmt::Display for InvalidKeyIvLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid length of key or IV")
    }
}

impl fmt::Display for InvalidMessageLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("message length is not multiple of the cipher block size")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKeyIvLength {
    fn description(&self) -> &str {
        "invalid length of key or IV"
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidMessageLength {
    fn description(&self) -> &str {
        "message length is not multiple of the cipher block size"
    }
}
