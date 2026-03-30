# RustCrypto: RC4

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
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

## Examples

```rust
use hex_literal::hex;
use rc4::{consts::*, KeyInit, StreamCipher};
use rc4::{Key, Rc4};

let mut rc4 = Rc4::<U3>::new(b"Key".into());
let mut data = b"Plaintext".to_vec();
rc4.apply_keystream(&mut data);
assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);

let mut rc4 = Rc4::<U4>::new(b"Wiki".into());
let mut data = b"pedia".to_vec();
rc4.apply_keystream(&mut data);
assert_eq!(data, [0x10, 0x21, 0xBF, 0x04, 0x20]);

let key = Key::<U6>::from_slice(b"Secret");
let mut rc4 = Rc4::<_>::new(key);
let mut data = b"Attack at dawn".to_vec();
rc4.apply_keystream(&mut data);
assert_eq!(
    data,
    [0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5]
);
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

[crate-image]: https://img.shields.io/crates/v/rc4.svg
[crate-link]: https://crates.io/crates/rc4
[docs-image]: https://docs.rs/rc4/badge.svg
[docs-link]: https://docs.rs/rc4/
[build-image]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rc4.yml/badge.svg
[build-link]: https://github.com/RustCrypto/stream-ciphers/actions/workflows/rc4.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/RC4
[2]: https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_alfardan.pdf
[3]: https://datatracker.ietf.org/doc/html/rfc7465
[4]: https://datatracker.ietf.org/doc/html/rfc8758
