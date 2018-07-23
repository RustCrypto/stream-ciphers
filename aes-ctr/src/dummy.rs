use ctr::Ctr128;
use aes_soft::{Aes128, Aes192, Aes256};

pub type Aes128Ctr = Ctr128<Aes128>;
pub type Aes192Ctr = Ctr128<Aes192>;
pub type Aes256Ctr = Ctr128<Aes256>;
