# RustCrypto: HC-256 Stream Cipher

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Implementation of the [HC-256] stream cipher.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

USE AT YOUR OWN RISK!

# Examples

```rust
use hc_256::Hc256;
use hc_256::cipher::{KeyIvInit, StreamCipher};
use hex_literal::hex;

let key = [0x42; 32];
let nonce = [0x24; 32];
let plaintext = hex!("000102030405060708090A0B0C0D0E0F");
let ciphertext = hex!("ca982177325cd40ebc208045066c420f");

// Key and IV must be references to the `Array` type.
// Here we use the `Into` trait to convert arrays into it.
let mut cipher = Hc256::new(&key.into(), &nonce.into());

let mut buffer = plaintext;

// apply keystream (encrypt)
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, ciphertext);

let ciphertext = buffer;

// decrypt ciphertext by applying keystream again
let mut cipher = Hc256::new(&key.into(), &nonce.into());
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, plaintext);

// stream ciphers can be used with streaming messages
let mut cipher = Hc256::new(&key.into(), &nonce.into());
for chunk in buffer.chunks_mut(3) {
    cipher.apply_keystream(chunk);
}
assert_eq!(buffer, ciphertext);
```

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
[build-image]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/hc-256.yml/badge.svg
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/hc-256.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg

[//]: # (footnotes)

[HC-256]: https://en.wikipedia.org/wiki/HC-256
