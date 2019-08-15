use aes_soft::{Aes128, Aes192, Aes256};
use ctr::Ctr128;

/// AES-128 in CTR mode
pub type Aes128Ctr = Ctr128<Aes128>;
/// AES-192 in CTR mode
pub type Aes192Ctr = Ctr128<Aes192>;
/// AES-256 in CTR mode
pub type Aes256Ctr = Ctr128<Aes256>;
