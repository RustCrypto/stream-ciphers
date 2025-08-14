use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        pub(crate) mod soft;
        pub(crate) mod sse2;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))] {
        pub(crate) mod soft;
        pub(crate) mod neon;
    } else {
        pub(crate) mod soft;
    }
}
