# RustCrypto: HC-256 Stream Cipher

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Pure Rust implementation of the [HC-256 Stream Cipher][1].

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

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

[crate-image]: https://img.shields.io/crates/v/hc-256.svg
[crate-link]: https://crates.io/crates/hc-256
[docs-image]: https://docs.rs/hc-256/badge.svg
[docs-link]: https://docs.rs/hc-256/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/hc-256.yml?query=branch:master
[build-image]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/hc-256.yml/badge.svg?branch=master
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/HC-256
