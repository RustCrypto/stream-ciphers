# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## UNRELEASED
### Fixed
- Minimal versions build ([#290])
- Hc256Core h2 function ([#324])

### Changed
- Bump `cipher` from `0.4` to `0.5` ([#338])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#397])
- Relax MSRV policy and allow MSRV bumps in patch releases

### Removed
- `std` feature ([#397])

[#290]: https://github.com/RustCrypto/stream-ciphers/pull/290
[#324]: https://github.com/RustCrypto/stream-ciphers/pull/324
[#338]: https://github.com/RustCrypto/stream-ciphers/pull/338
[#397]: https://github.com/RustCrypto/stream-ciphers/pull/397

## 0.5.0 (2022-02-10)
### Changed
- Bump `cipher` dependency to v0.4 ([#276])

[#276]: https://github.com/RustCrypto/stream-ciphers/pull/276

## 0.4.1 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 ([#256])

[#256]: https://github.com/RustCrypto/stream-ciphers/pull/256

## 0.4.0 (2021-04-29)
### Changed
- Bump `cipher` crate dependency to v0.3 release ([#226])

### Fixed
- Avoid pulling in `alloc` feature of `zeroize` ([#190])

[#190]: https://github.com/RustCrypto/stream-ciphers/pull/190
[#226]: https://github.com/RustCrypto/stream-ciphers/pull/226

## 0.3.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#177])

[#177]: https://github.com/RustCrypto/stream-ciphers/pull/177

## 0.2.0 (2020-08-25)
### Changed
- Bump `stream-cipher` dependency to v0.7, rename `HC256` to `Hc256` ([#161], [#164])

[#161]: https://github.com/RustCrypto/stream-ciphers/pull/161
[#164]: https://github.com/RustCrypto/stream-ciphers/pull/164

## 0.1.0 (2020-06-08)
### Changed
- Bump `stream-cipher` dependency to v0.4 ([#122])
- Upgrade to Rust 2018 edition ([#122])

[#122]: https://github.com/RustCrypto/stream-ciphers/pull/122

## 0.0.1 (2019-10-02)
- Initial release
