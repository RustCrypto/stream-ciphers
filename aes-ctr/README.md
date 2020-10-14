# RustCrypto: AES-CTR

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Pure Rust implementation of the [Advanced Encryption Standard (AES)][1]
in [Counter Mode][2].

Provides a high-performance implementation based on AES-NI and other x86(-64)
CPU intrinsics when available, or otherwise falls back on a bitsliced software
implementation and the [`ctr`][3] crate.

[Documentation][docs-link]

### ⚠️ Security Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

To avoid this, use an [AEAD][4] mode based on AES, such as [AES-GCM][5] or
[AES-GCM-SIV][6].

See the [RustCrypto/AEADs][7] repository for more information.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.41** or higher.

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

[crate-image]: https://img.shields.io/crates/v/aes-ctr.svg
[crate-link]: https://crates.io/crates/aes-ctr
[docs-image]: https://docs.rs/aes-ctr/badge.svg
[docs-link]: https://docs.rs/aes-ctr/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[build-image]: https://github.com/RustCrypto/stream-ciphers/workflows/aes-ctr/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions?query=workflow%3Aaes-ctr
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
[3]: https://github.com/RustCrypto/stream-ciphers/tree/master/ctr
[4]: https://en.wikipedia.org/wiki/Authenticated_encryption
[5]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
[6]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv
[7]: https://github.com/RustCrypto/AEADs
