# Salsa20

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

[Salsa20][1] is a [stream cipher][2] which is designed to support
high-performance software implementations.

This crate also contains an implementation of [XSalsa20][3]: a variant
of Salsa20 with an extended 192-bit (24-byte) nonce, gated under the
`xsalsa20` Cargo feature (on-by-default).

[Documentation][docs-link]

## Security Warning

This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
is not verified, which can lead to serious vulnerabilities!

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

USE AT YOUR OWN RISK!

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/salsa20.svg
[crate-link]: https://crates.io/crates/salsa20
[docs-image]: https://docs.rs/salsa20/badge.svg
[docs-link]: https://docs.rs/salsa20/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.27+-blue.svg
[build-image]: https://travis-ci.org/RustCrypto/stream-ciphers.svg?branch=master
[build-link]: https://travis-ci.org/RustCrypto/stream-ciphers

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Salsa20
[2]: https://en.wikipedia.org/wiki/Stream_cipher
[3]: https://cr.yp.to/snuffle/xsalsa-20081128.pdf
