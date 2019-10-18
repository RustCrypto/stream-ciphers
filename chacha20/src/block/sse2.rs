#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use salsa20_core::{CONSTANTS, IV_WORDS, KEY_WORDS, STATE_WORDS};

pub(crate) struct Block {
    v0: __m128i,
    v1: __m128i,
    v2: __m128i,
    v3: __m128i,
}

impl Block {
    #[target_feature(enable = "sse2")]
    pub(crate) unsafe fn generate(
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let vs = init(key, iv, counter);

        let mut block = Self {
            v0: vs[0],
            v1: vs[1],
            v2: vs[2],
            v3: vs[3],
        };

        block.rounds();
        block.finish(key, iv, counter)
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    pub unsafe fn rounds(&mut self) {
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);

        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        double_quarter_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn finish(
        mut self,
        key: &[u32; KEY_WORDS],
        iv: [u32; IV_WORDS],
        counter: u64,
    ) -> [u32; STATE_WORDS] {
        let vs = init(key, iv, counter);

        self.v0 = _mm_add_epi32(self.v0, vs[0]);
        self.v1 = _mm_add_epi32(self.v1, vs[1]);
        self.v2 = _mm_add_epi32(self.v2, vs[2]);
        self.v3 = _mm_add_epi32(self.v3, vs[3]);

        store(self.v0, self.v1, self.v2, self.v3)
    }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn init(key: &[u32; KEY_WORDS], iv: [u32; IV_WORDS], counter: u64) -> [__m128i; 4] {
    let v0 = _mm_loadu_si128(CONSTANTS.as_ptr() as *const __m128i);
    let v1 = _mm_loadu_si128(key.as_ptr().offset(0) as *const __m128i);
    let v2 = _mm_loadu_si128(key.as_ptr().offset(4) as *const __m128i);
    let v3 = _mm_set_epi32(
        iv[1] as i32,
        iv[0] as i32,
        ((counter >> 32) & 0xffff_ffff) as i32,
        (counter & 0xffff_ffff) as i32,
    );

    [v0, v1, v2, v3]
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn store(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> [u32; STATE_WORDS] {
    let mut state = [0u32; STATE_WORDS];

    _mm_storeu_si128(state.as_mut_ptr().offset(0x0) as *mut __m128i, v0);
    _mm_storeu_si128(state.as_mut_ptr().offset(0x4) as *mut __m128i, v1);
    _mm_storeu_si128(state.as_mut_ptr().offset(0x8) as *mut __m128i, v2);
    _mm_storeu_si128(state.as_mut_ptr().offset(0xc) as *mut __m128i, v3);

    state
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn double_quarter_round(
    v0: &mut __m128i,
    v1: &mut __m128i,
    v2: &mut __m128i,
    v3: &mut __m128i,
) {
    add_xor_rot(v0, v1, v2, v3);
    rows_to_cols(v0, v1, v2, v3);
    add_xor_rot(v0, v1, v2, v3);
    cols_to_rows(v0, v1, v2, v3);
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rows_to_cols(_v0: &mut __m128i, v1: &mut __m128i, v2: &mut __m128i, v3: &mut __m128i) {
    // v1 >>>= 32; v2 >>>= 64; v3 >>>= 96;
    *v1 = _mm_shuffle_epi32(*v1, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    *v2 = _mm_shuffle_epi32(*v2, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    *v3 = _mm_shuffle_epi32(*v3, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn cols_to_rows(_v0: &mut __m128i, v1: &mut __m128i, v2: &mut __m128i, v3: &mut __m128i) {
    // v1 <<<= 32; v2 <<<= 64; v3 <<<= 96;
    *v1 = _mm_shuffle_epi32(*v1, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    *v2 = _mm_shuffle_epi32(*v2, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
    *v3 = _mm_shuffle_epi32(*v3, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn add_xor_rot(v0: &mut __m128i, v1: &mut __m128i, v2: &mut __m128i, v3: &mut __m128i) {
    // v0 += v1; v3 ^= v0; v3 <<<= (16, 16, 16, 16);
    *v0 = _mm_add_epi32(*v0, *v1);
    *v3 = _mm_xor_si128(*v3, *v0);
    *v3 = _mm_xor_si128(_mm_slli_epi32(*v3, 16), _mm_srli_epi32(*v3, 16));

    // v2 += v3; v1 ^= v2; v1 <<<= (12, 12, 12, 12);
    *v2 = _mm_add_epi32(*v2, *v3);
    *v1 = _mm_xor_si128(*v1, *v2);
    *v1 = _mm_xor_si128(_mm_slli_epi32(*v1, 12), _mm_srli_epi32(*v1, 20));

    // v0 += v1; v3 ^= v0; v3 <<<= (8, 8, 8, 8);
    *v0 = _mm_add_epi32(*v0, *v1);
    *v3 = _mm_xor_si128(*v3, *v0);
    *v3 = _mm_xor_si128(_mm_slli_epi32(*v3, 8), _mm_srli_epi32(*v3, 24));

    // v2 += v3; v1 ^= v2; v1 <<<= (7, 7, 7, 7);
    *v2 = _mm_add_epi32(*v2, *v3);
    *v1 = _mm_xor_si128(*v1, *v2);
    *v1 = _mm_xor_si128(_mm_slli_epi32(*v1, 7), _mm_srli_epi32(*v1, 25));
}

#[cfg(all(test, target_feature = "sse2"))]
mod tests {
    use super::super::Block as ScalarBlock;
    use super::*;

    // random inputs for testing
    const R_CNT: u64 = 0x9fe625b6d23a8fa8u64;
    const R_IV: [u32; IV_WORDS] = [0x4aa8962f, 0x94bc92f8];
    const R_KEY: [u32; KEY_WORDS] = [
        0x9972f211, 0xef6d79e1, 0x586adc0b, 0x9458011f, 0x3f691992, 0x721635e9, 0x940dd163,
        0x1134316d,
    ];

    #[test]
    fn init_and_store() {
        unsafe {
            let vs = init(&R_KEY, R_IV, R_CNT);
            let state = store(vs[0], vs[1], vs[2], vs[3]);

            assert_eq!(
                state.as_ref(),
                &[
                    1634760805, 857760878, 2036477234, 1797285236, 2574447121, 4016929249,
                    1483398155, 2488795423, 1063852434, 1914058217, 2483933539, 288633197,
                    3527053224, 2682660278, 1252562479, 2495386360
                ]
            );
        }
    }

    #[test]
    fn init_and_finish() {
        unsafe {
            let vs = init(&R_KEY, R_IV, R_CNT);
            let block = Block {
                v0: vs[0],
                v1: vs[1],
                v2: vs[2],
                v3: vs[3],
            };

            assert_eq!(
                block.finish(&R_KEY, R_IV, R_CNT).as_ref(),
                &[
                    3269521610, 1715521756, 4072954468, 3594570472, 853926946, 3738891202,
                    2966796310, 682623550, 2127704868, 3828116434, 672899782, 577266394,
                    2759139152, 1070353260, 2505124958, 695805424
                ]
            );
        }
    }

    #[test]
    fn init_and_double_round() {
        unsafe {
            let vs = init(&R_KEY, R_IV, R_CNT);
            let mut v0 = vs[0];
            let mut v1 = vs[1];
            let mut v2 = vs[2];
            let mut v3 = vs[3];
            double_quarter_round(&mut v0, &mut v1, &mut v2, &mut v3);
            let state = store(v0, v1, v2, v3);

            assert_eq!(
                state.as_ref(),
                &[
                    562456049, 3130322832, 1534507163, 1938142593, 1427879055, 3727017100,
                    1549525649, 2358041203, 1010155040, 657444539, 2865892668, 2826477124,
                    737507996, 3254278724, 3376929372, 928763221
                ]
            );
        }
    }

    #[test]
    fn generate_vs_scalar_impl() {
        let scalar_result = ScalarBlock::generate(&R_KEY, R_IV, R_CNT);
        let simd_result = unsafe { Block::generate(&R_KEY, R_IV, R_CNT) };

        assert_eq!(scalar_result, simd_result)
    }
}
