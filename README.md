# RustCrypto stream ciphers [![Build Status](https://travis-ci.org/RustCrypto/stream-ciphers.svg?branch=master)](https://travis-ci.org/RustCrypto/stream-ciphers)
Collection of stream cipher algorithms written in pure Rust.

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
| `ctr` | [![crates.io](https://img.shields.io/crates/v/ctr.svg)](https://crates.io/crates/ctr) | [![Documentation](https://docs.rs/ctr/badge.svg)](https://docs.rs/ctr) |


### Minimum Rust version
All crates in this repository support Rust 1.27 or higher. In future minimum
supported Rust version can be changed, but it will be done with the minor
version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
