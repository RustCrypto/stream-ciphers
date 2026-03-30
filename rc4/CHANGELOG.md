# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (2026-03-30)
### Changed
- Bump `cipher` from `0.4` to `0.5` ([#338])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#397])
- Relax MSRV policy and allow MSRV bumps in patch releases
- `Rc4` can be initialized with key sizes from 1 to 256 bytes using
  `KeyInit::new_from_slice` ([#557])

### Removed
- `std` feature ([#397])
- `KeySize` type parameter from `Rc4` type ([#557])
- `Rc4Core` type ([#557])

[#290]: https://github.com/RustCrypto/stream-ciphers/pull/290
[#324]: https://github.com/RustCrypto/stream-ciphers/pull/324
[#397]: https://github.com/RustCrypto/stream-ciphers/pull/397
[#557]: https://github.com/RustCrypto/stream-ciphers/pull/557

## 0.1.0 (2022-03-29)
- Initial release
