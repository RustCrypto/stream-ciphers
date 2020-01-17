# RustCrypto: stream ciphers
[![Build Status](https://travis-ci.org/RustCrypto/stream-ciphers.svg?branch=master)](https://travis-ci.org/RustCrypto/stream-ciphers) [![dependency status](https://deps.rs/repo/github/RustCrypto/stream-ciphers/status.svg)](https://deps.rs/repo/github/RustCrypto/stream-ciphers)

Collection of [stream cipher][1] algorithms written in pure Rust.

## Warnings

Crates in this repository do not provide any authentification! Thus ciphertext
integrity is not verified, which can lead to serious vulnerabilities!

Crates have not yet received any formal cryptographic and security reviews.

**USE AT YOUR OWN RISK.**

## Crates
| Name | Crates.io | Documentation |
| ---- | :--------:| :------------:|
| `aes-ctr` | [![crates.io](https://img.shields.io/crates/v/aes-ctr.svg)](https://crates.io/crates/aes-ctr) | [![Documentation](https://docs.rs/aes-ctr/badge.svg)](https://docs.rs/aes-ctr) |
| `cfb-mode` | [![crates.io](https://img.shields.io/crates/v/cfb-mode.svg)](https://crates.io/crates/cfb-mode) | [![Documentation](https://docs.rs/cfb-mode/badge.svg)](https://docs.rs/cfb-mode) |
| `cfb8` | [![crates.io](https://img.shields.io/crates/v/cfb8.svg)](https://crates.io/crates/cfb8) | [![Documentation](https://docs.rs/cfb8/badge.svg)](https://docs.rs/cfb8) |
| `chacha20` | [![crates.io](https://img.shields.io/crates/v/chacha20.svg)](https://crates.io/crates/chacha20) | [![Documentation](https://docs.rs/chacha20/badge.svg)](https://docs.rs/chacha20) |
| `ctr` | [![crates.io](https://img.shields.io/crates/v/ctr.svg)](https://crates.io/crates/ctr) | [![Documentation](https://docs.rs/ctr/badge.svg)](https://docs.rs/ctr) |
| `hc-256` | [![crates.io](https://img.shields.io/crates/v/hc-256.svg)](https://crates.io/crates/hc-256) | [![Documentation](https://docs.rs/hc-256/badge.svg)](https://docs.rs/hc-256) |
| `ofb` | [![crates.io](https://img.shields.io/crates/v/ofb.svg)](https://crates.io/crates/ofb) | [![Documentation](https://docs.rs/ofb/badge.svg)](https://docs.rs/ofb) |
| `salsa20` | [![crates.io](https://img.shields.io/crates/v/salsa20.svg)](https://crates.io/crates/salsa20) | [![Documentation](https://docs.rs/salsa20/badge.svg)](https://docs.rs/salsa20) |


### Minimum Rust version
All crates in this repository support Rust 1.27 or higher except for the
`chacha20` and `salsa20` crates, which require Rust 1.34+.

In future minimum supported Rust version can be changed, but it will be done
with the minor version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the
[`stream-cipher`][2] crate.

Let's use AES-128-OFB to demonstrate usage of synchronous stream cipher:
```rust
extern crate aes;
extern crate ofb;

use aes::Aes128;
use ofb::Ofb;
// import relevant traits
use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};

// OFB mode implementation is generic over block ciphers
// we will create a type alias for convenience
type AesOfb = Ofb<Aes128>;

let key = b"very secret key.";
let iv = b"unique init vect";
let plaintext = b"The quick brown fox jumps over the lazy dog.";

let mut buffer = plaintext.to_vec();
// create cipher instance
let mut cipher = AesOfb::new_var(key, iv)?;
// apply keystream (encrypt)
cipher.apply_keystream(&mut buffer);
// and decrypt it back
AesOfb::new_var(key, iv)?.apply_keystream(&mut buffer);
// stream ciphers can be used with streaming messages
let mut cipher = AesOfb::new_var(key, iv).unwrap();
for chunk in buffer.chunks_mut(3) {
    cipher.apply_keystream(chunk);
}
```

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[1]: https://en.wikipedia.org/wiki/Stream_cipher
[2]: https://docs.rs/stream-cipher
