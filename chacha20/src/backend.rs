//! Backends providing the ChaCha20 core function.
//!
//! Defined in RFC 8439 Section 2.3:
//! <https://tools.ietf.org/html/rfc8439#section-2.3>

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2",
        not(feature = "force-soft")
    ))] {
        pub(crate) mod autodetect;
        pub(crate) mod avx2;
        pub(crate) mod sse2;

        pub(crate) use self::autodetect::BUFFER_SIZE;
        pub use self::autodetect::Core;

        #[cfg(feature = "xchacha")]
        pub(crate) mod soft;
    } else {
        pub(crate) mod soft;
        pub(crate) use self::soft::BUFFER_SIZE;
        pub use self::soft::Core;
    }
}
