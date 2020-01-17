# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2020-01-17)
### Changed
- Replace `salsa20-core` with `ctr`-derived buffering; MSRV 1.34+ ([#94])

[#94]: https://github.com/RustCrypto/stream-ciphers/pull/94

## 0.3.0 (2019-10-01)
### Added
- XSalsa20 ([#54])

[#54]: https://github.com/RustCrypto/stream-ciphers/pull/44

## 0.2.0 (2019-08-18)
### Added
- Improve documentation ([#17])
- Impl `SyncStreamCipher` ([#39])

### Changed
- Refactoring ([#38], [#44])

### Fixed
- Fix broken Cargo feature attributes ([#21])

[#44]: https://github.com/RustCrypto/stream-ciphers/pull/44
[#39]: https://github.com/RustCrypto/stream-ciphers/pull/39
[#38]: https://github.com/RustCrypto/stream-ciphers/pull/38
[#21]: https://github.com/RustCrypto/stream-ciphers/pull/21
[#17]: https://github.com/RustCrypto/stream-ciphers/pull/17

## 0.1.1 (2019-06-30)

### Added
- `#![no_std]` support

[#19]: https://github.com/RustCrypto/stream-ciphers/pull/19

## 0.1.0 (2019-06-24)

- Initial release
