# RustCrypto: RC4

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Pure Rust implementation of the [RC4 stream cipher][1].

## 🚨 Warning: Cryptographically Broken 🚨

RC4 is [cryptographically broken and unsuitable for further use][2]!

[RFC7465][3] and [RFC8758][4] prohibit the use of RC4 in TLS and SSH protocols
respectively, noting that cryptographic weaknesses in the cipher's design make
it practical to recover repeatedly encrypted plaintexts.

This crate is provided for the purposes of legacy interoperability with
protocols and systems which continue to mandate the use of RC4. It should not be
relied on for security/confidentiality.

**USE AT YOUR OWN RISK!**

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

[crate-image]: https://img.shields.io/crates/v/rc4.svg
[crate-link]: https://crates.io/crates/rc4
[docs-image]: https://docs.rs/rc4/badge.svg
[docs-link]: https://docs.rs/rc4/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[build-image]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rc4.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rc4.yml?query=branch:master
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/RC4
[2]: https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_alfardan.pdf
[3]: https://datatracker.ietf.org/doc/html/rfc7465
[4]: https://datatracker.ietf.org/doc/html/rfc8758
