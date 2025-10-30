use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_feature = "sse2", any(target_arch = "x86", target_arch = "x86_64")))] {
        pub(crate) mod sse2;
        pub(crate) type Backend<'a, R> = sse2::Backend<'a, R>;
    } else {
        pub(crate) mod soft;
        pub(crate) type Backend<'a, R> = soft::Backend<'a, R>;
    }
}

#[inline]
#[allow(clippy::many_single_char_names)]
pub(crate) fn quarter_round(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    state: &mut [u32; crate::STATE_WORDS],
) {
    let a = crate::DATA_LAYOUT_INVERSE[a];
    let b = crate::DATA_LAYOUT_INVERSE[b];
    let c = crate::DATA_LAYOUT_INVERSE[c];
    let d = crate::DATA_LAYOUT_INVERSE[d];
    state[b] ^= state[a].wrapping_add(state[d]).rotate_left(7);
    state[c] ^= state[b].wrapping_add(state[a]).rotate_left(9);
    state[d] ^= state[c].wrapping_add(state[b]).rotate_left(13);
    state[a] ^= state[d].wrapping_add(state[c]).rotate_left(18);
}
