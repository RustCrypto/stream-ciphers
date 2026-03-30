# RustCrypto: stream ciphers

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]
[![HAZMAT][hazmat-image]][hazmat-link]

Collection of [stream ciphers] written in pure Rust.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

Crates in this repository do not ensure ciphertexts are authentic (i.e. by
using a MAC to verify ciphertext integrity), which can lead to serious
vulnerabilities if used incorrectly!

Aside from the `chacha20` crate, no crates in this repository have yet
received any formal cryptographic and security reviews/audits.

**USE AT YOUR OWN RISK!**

## Crates
| Name     | Crate name | Crates.io | Docs | MSRV | Security |
|----------|------------|-----------|------|------|----------|
| [ChaCha] | [`chacha20`] | [![crates.io](https://img.shields.io/crates/v/chacha20.svg)](https://crates.io/crates/chacha20) | [![Documentation](https://docs.rs/chacha20/badge.svg)](https://docs.rs/chacha20) | ![MSRV 1.85][msrv-1.85] | 💚 |
| [HC-256] | [`hc-256`]   | [![crates.io](https://img.shields.io/crates/v/hc-256.svg)](https://crates.io/crates/hc-256) | [![Documentation](https://docs.rs/hc-256/badge.svg)](https://docs.rs/hc-256) | ![MSRV 1.85][msrv-1.85] | [💛](https://link.springer.com/chapter/10.1007/978-3-642-04846-3_4) |
| [Rabbit] | [`rabbit`]  | [![crates.io](https://img.shields.io/crates/v/rabbit.svg)](https://crates.io/crates/rabbit) | [![Documentation](https://docs.rs/rabbit/badge.svg)](https://docs.rs/rabbit) | ![MSRV 1.85][msrv-1.85] | [💛](https://eprint.iacr.org/2013/780.pdf) |
| [RC4]    | [`rc4`]  | [![crates.io](https://img.shields.io/crates/v/rc4.svg)](https://crates.io/crates/rc4) | [![Documentation](https://docs.rs/rc4/badge.svg)](https://docs.rs/rc4) | ![MSRV 1.85][msrv-1.85] | [💔](https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_alfardan.pdf) |
| [Salsa20] | [`salsa20`]  | [![crates.io](https://img.shields.io/crates/v/salsa20.svg)](https://crates.io/crates/salsa20) | [![Documentation](https://docs.rs/salsa20/badge.svg)](https://docs.rs/salsa20) | ![MSRV 1.85][msrv-1.85] | 💚 |

### Security Level Legend

The following describes the security level ratings associated with each hash function (i.e. algorithms, not the specific implementation):

| Heart          | Description |
|----------------|-------------|
| :green_heart:  | No known successful attacks |
| :yellow_heart: | Theoretical break: security lower than claimed |
| :broken_heart: | Attack demonstrated in practice: avoid if at all possible |

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[deps-image]: https://deps.rs/repo/github/RustCrypto/stream-ciphers/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/stream-ciphers
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[msrv-1.85]: https://img.shields.io/badge/rustc-1.85.0+-blue.svg

[//]: # (footnotes)

[stream ciphers]: https://en.wikipedia.org/wiki/Stream_cipher
[`cipher`]: https://docs.rs/cipher

[//]: # (crates)

[`chacha20`]: ./chacha20
[`hc-256`]: ./hc-256
[`rabbit`]: ./rabbit
[`rc4`]: ./rc4
[`salsa20`]: ./salsa20

[//]: # (links)

[ChaCha]: https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
[HC-256]: https://en.wikipedia.org/wiki/HC-256
[Rabbit]: https://en.wikipedia.org/wiki/Rabbit_(cipher)
[RC4]: https://en.wikipedia.org/wiki/RC4
[Salsa20]: https://en.wikipedia.org/wiki/Salsa20
