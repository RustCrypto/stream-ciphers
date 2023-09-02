use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(salsa20_force_soft)] {
        pub(crate) mod soft;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        cfg_if! {
            if #[cfg(salsa20_force_sse2)] {
                pub(crate) mod sse2;
            } else {
                pub(crate) mod soft;
            }
        }
    } else {
        pub(crate) mod soft;
    }
}
