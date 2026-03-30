# RustCrypto: Rabbit Stream Cipher Algorithm

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Implementation of the [Rabbit] stream cipher ([RFC 4503]).

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

**USE AT YOUR OWN RISK!**


## Examples

```rust
use rabbit::Rabbit;
use rabbit::cipher::{KeyIvInit, StreamCipher};
use hex_literal::hex;

let key = [0x42; 16];
let nonce = [0x24; 8];
let plaintext = hex!("000102030405060708090A0B0C0D0E0F");
let ciphertext = hex!("10298496ceda18ee0e257cbb1ab43bcc");

// Key and IV must be references to the `Array` type.
// Here we use the `Into` trait to convert arrays into it.
let mut cipher = Rabbit::new(&key.into(), &nonce.into());

let mut buffer = plaintext;

// apply keystream (encrypt)
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, ciphertext);

let ciphertext = buffer;

// decrypt ciphertext by applying keystream again
let mut cipher = Rabbit::new(&key.into(), &nonce.into());
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, plaintext);

// stream ciphers can be used with streaming messages
let mut cipher = Rabbit::new(&key.into(), &nonce.into());
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

[crate-image]: https://img.shields.io/crates/v/rabbit.svg
[crate-link]: https://crates.io/crates/rabbit
[docs-image]: https://docs.rs/rabbit/badge.svg
[docs-link]: https://docs.rs/rabbit/
[build-image]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rabbit.yml/badge.svg
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rabbit.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[Rabbit]: https://en.wikipedia.org/wiki/Rabbit_(cipher)
[RFC 4503]: https://tools.ietf.org/html/rfc4503
