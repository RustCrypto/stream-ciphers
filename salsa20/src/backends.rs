use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        pub(crate) mod sse2;
        pub(crate) mod soft;
    } else {
        pub(crate) mod soft;
    }
}
