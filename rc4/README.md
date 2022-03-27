# RustCrypto: Rc4 Stream Cipher Algorithm

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Pure Rust implementation of the [Rc4 Stream Cipher Algorithm][1].

[Documentation][docs-link]

## ⚠️ Security Warning

This crate is provided for the purposes of legacy interoperability with
protocols and systems which mandate the use of RC4.

However, RC4 is [cryptographically broken and unsuitable for further use][2]!!!

[RFC7465][3] and [RFC8758][4] prohibit the use of RC4 in TLS and SSH protocols
respectively, noting that cryptographic weaknesses in the cipher's design make
it practical to recover repeatedly encrypted plaintexts.

**USE AT YOUR OWN RISK!**

## Minimum Supported Rust Version

Rust **1.56** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

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

[crate-image]: https://img.shields.io/crates/v/Rc4.svg
[crate-link]: https://crates.io/crates/Rc4
[docs-image]: https://docs.rs/Rc4/badge.svg
[docs-link]: https://docs.rs/Rc4/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[build-image]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rc4.yml/badge.svg
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rc4.yml
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/RC4
[2]: https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_alfardan.pdf
[3]: https://datatracker.ietf.org/doc/html/rfc7465
[4]: https://datatracker.ietf.org/doc/html/rfc8758
