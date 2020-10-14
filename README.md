# RustCrypto: stream ciphers ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link] [![HAZMAT][hazmat-image]][hazmat-link]

Collection of [stream cipher][1] algorithms written in pure Rust.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

Crates in this repository do not ensure ciphertexts are authentic (i.e. by
using a MAC to verify ciphertext integrity), which can lead to serious
vulnerabilities if used incorrectly!

Aside from the `chacha20` crate, no crates in this repository have yet
received any formal cryptographic and security reviews/audits.

**USE AT YOUR OWN RISK!**

## Crates
| Name | Crates.io | Documentation | Build Status |
|------|-----------|---------------|--------------|
| `aes-ctr` | [![crates.io](https://img.shields.io/crates/v/aes-ctr.svg)](https://crates.io/crates/aes-ctr) | [![Documentation](https://docs.rs/aes-ctr/badge.svg)](https://docs.rs/aes-ctr) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/aes-ctr/badge.svg?branch=master&event=push)
| `cfb-mode` | [![crates.io](https://img.shields.io/crates/v/cfb-mode.svg)](https://crates.io/crates/cfb-mode) | [![Documentation](https://docs.rs/cfb-mode/badge.svg)](https://docs.rs/cfb-mode) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/cfb-mode/badge.svg?branch=master&event=push)
| `cfb8` | [![crates.io](https://img.shields.io/crates/v/cfb8.svg)](https://crates.io/crates/cfb8) | [![Documentation](https://docs.rs/cfb8/badge.svg)](https://docs.rs/cfb8) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/cfb-mode/badge.svg?branch=master&event=push)
| `chacha20` | [![crates.io](https://img.shields.io/crates/v/chacha20.svg)](https://crates.io/crates/chacha20) | [![Documentation](https://docs.rs/chacha20/badge.svg)](https://docs.rs/chacha20) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/chacha20/badge.svg?branch=master&event=push)
| `ctr` | [![crates.io](https://img.shields.io/crates/v/ctr.svg)](https://crates.io/crates/ctr) | [![Documentation](https://docs.rs/ctr/badge.svg)](https://docs.rs/ctr) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/ctr/badge.svg?branch=master&event=push)
| `hc-256` | [![crates.io](https://img.shields.io/crates/v/hc-256.svg)](https://crates.io/crates/hc-256) | [![Documentation](https://docs.rs/hc-256/badge.svg)](https://docs.rs/hc-256) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/hc-256/badge.svg?branch=master&event=push)
| `ofb` | [![crates.io](https://img.shields.io/crates/v/ofb.svg)](https://crates.io/crates/ofb) | [![Documentation](https://docs.rs/ofb/badge.svg)](https://docs.rs/ofb) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/ofb/badge.svg?branch=master&event=push)
| `salsa20` | [![crates.io](https://img.shields.io/crates/v/salsa20.svg)](https://crates.io/crates/salsa20) | [![Documentation](https://docs.rs/salsa20/badge.svg)](https://docs.rs/salsa20) | ![build](https://github.com/RustCrypto/stream-ciphers/workflows/salsa20/badge.svg?branch=master)


## Minimum Supported Rust Version

Rust **1.41** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the
[`stream-cipher`][2] crate.

Let's use AES-128-OFB to demonstrate usage of synchronous stream cipher:

```rust
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

[//]: # (badges)

[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Stream_cipher
[2]: https://docs.rs/stream-cipher
