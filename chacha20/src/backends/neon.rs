//! NEON-optimized implementation for aarch64 CPUs.
//!
//! Adapted from the Crypto++ `chacha_simd` implementation by Jack Lloyd and
//! Jeffrey Walton (public domain).

use crate::{Rounds, Variant, STATE_WORDS};
use core::{arch::aarch64::*, marker::PhantomData, mem::size_of};

#[cfg(feature = "rand_core")]
use crate::ChaChaCore;

#[cfg(feature = "cipher")]
use crate::chacha::Block;

#[cfg(feature = "cipher")]
use cipher::{
    consts::{U4, U64},
    BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamBackend, StreamClosure,
};

struct Backend<R: Rounds, V: Variant> {
    state: [uint32x4_t; 4],
    ctrs: [uint32x4_t; 4],
    _pd: PhantomData<R>,
    _variant: PhantomData<V>,
}

impl<R: Rounds, V: Variant> Backend<R, V> {
    #[inline]
    unsafe fn new(state: &mut [u32; STATE_WORDS]) -> Self {
        let state = [
            vld1q_u32(state.as_ptr().offset(0)),
            vld1q_u32(state.as_ptr().offset(4)),
            vld1q_u32(state.as_ptr().offset(8)),
            vld1q_u32(state.as_ptr().offset(12)),
        ];
        let ctrs = [
            vld1q_u32([1, 0, 0, 0].as_ptr()),
            vld1q_u32([2, 0, 0, 0].as_ptr()),
            vld1q_u32([3, 0, 0, 0].as_ptr()),
            vld1q_u32([4, 0, 0, 0].as_ptr()),
        ];
        Backend::<R, V> {
            state,
            ctrs,
            _pd: PhantomData,
            _variant: PhantomData,
        }
    }
}

#[inline]
#[cfg(feature = "cipher")]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn inner<R, F, V>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Rounds,
    F: StreamClosure<BlockSize = U64>,
    V: Variant,
{
    let mut backend = Backend::<R, V>::new(state);

    f.call(&mut backend);

    if core::mem::size_of::<V::Counter>() == 4 {
        // handle 32-bit counter
        vst1q_u32(state.as_mut_ptr().offset(12), backend.state[3]);
    } else {
        vst1q_u64(
            state.as_mut_ptr().offset(12) as *mut u64,
            vreinterpretq_u64_u32(backend.state[3]),
        );
    }
}

#[inline]
#[cfg(feature = "rand_core")]
#[target_feature(enable = "neon")]
/// Sets up backend and blindly writes 4 blocks to dest_ptr.
#[cfg(feature = "rng")]
pub(crate) unsafe fn rng_inner<R, V>(core: &mut ChaChaCore<R, V>, buffer: &mut [u32; 64])
where
    R: Rounds,
    V: Variant,
{
    let mut backend = Backend::<R, V>::new(&mut core.state);

    backend.write_par_ks_blocks(buffer);

    vst1q_u32(core.state.as_mut_ptr().offset(12), backend.state[3]);
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> BlockSizeUser for Backend<R, V> {
    type BlockSize = U64;
}
#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> ParBlocksSizeUser for Backend<R, V> {
    type ParBlocksSize = U4;
}

/// Adds a counter row with either 32-bit or 64-bit addition
macro_rules! add_counter {
    ($a:expr, $b:expr, $variant:ty) => {
        if size_of::<<$variant>::Counter>() == 4 {
            vaddq_u32($a, $b)
        } else {
            vreinterpretq_u32_u64(vaddq_u64(
                vreinterpretq_u64_u32($a),
                vreinterpretq_u64_u32($b),
            ))
        }
    };
}

/// Evaluates to `a = a + b`, where the operands are u32x4s
macro_rules! add_assign_vec {
    ($a:expr, $b:expr) => {
        $a = vaddq_u32($a, $b)
    };
}

#[cfg(feature = "cipher")]
impl<R: Rounds, V: Variant> StreamBackend for Backend<R, V> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block) {
        let state3 = self.state[3];
        let mut par = ParBlocks::<Self>::default();
        self.gen_par_ks_blocks(&mut par);
        *block = par[0];
        unsafe {
            self.state[3] = add_counter!(state3, vld1q_u32([1, 0, 0, 0].as_ptr()), V);
        }
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, dest: &mut ParBlocks<Self>) {
        unsafe {
            let mut blocks = [
                [self.state[0], self.state[1], self.state[2], self.state[3]],
                [
                    self.state[0],
                    self.state[1],
                    self.state[2],
                    add_counter!(self.state[3], self.ctrs[0], V),
                ],
                [
                    self.state[0],
                    self.state[1],
                    self.state[2],
                    add_counter!(self.state[3], self.ctrs[1], V),
                ],
                [
                    self.state[0],
                    self.state[1],
                    self.state[2],
                    add_counter!(self.state[3], self.ctrs[2], V),
                ],
            ];

            for _ in 0..R::COUNT {
                double_quarter_round(&mut blocks);
            }

            // write first block, with no special counter requirements
            for state_row in 0..4 {
                // add state
                add_assign_vec!(blocks[0][state_row], self.state[state_row]);
                // write
                vst1q_u8(
                    dest[0]
                        .as_mut_ptr()
                        .offset((state_row as isize) << 4 as isize),
                    vreinterpretq_u8_u32(blocks[0][state_row as usize]),
                );
            }

            // write blocks with adjusted counters
            for block in 1..4 {
                // add state with adjusted counter
                for state_row in 0..3 {
                    add_assign_vec!(blocks[block][state_row], self.state[state_row]);
                }
                add_assign_vec!(
                    blocks[block][3],
                    add_counter!(self.state[3], self.ctrs[block - 1], V)
                );

                // write
                for state_row in 0..4 {
                    vst1q_u8(
                        dest[block].as_mut_ptr().offset(state_row << 4 as usize),
                        vreinterpretq_u8_u32(blocks[block][state_row as usize]),
                    );
                }
            }
            self.state[3] = add_counter!(self.state[3], self.ctrs[3], V);
        }
    }
}

macro_rules! rotate_left {
    ($v:expr, 8) => {{
        let maskb = [3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
        let mask = vld1q_u8(maskb.as_ptr());

        $v = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32($v), mask))
    }};
    ($v:expr, 16) => {
        $v = vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32($v)))
    };
    ($v:expr, $r:literal) => {
        $v = vorrq_u32(vshlq_n_u32($v, $r), vshrq_n_u32($v, 32 - $r))
    };
}

macro_rules! extract {
    ($v:expr, $s:literal) => {
        $v = vextq_u32($v, $v, $s)
    };
}

impl<R: Rounds, V: Variant> Backend<R, V> {
    #[inline(always)]
    /// Generates `num_blocks` blocks and blindly writes them to `dest_ptr`
    ///
    /// `num_blocks` must be greater than 0, and less than or equal to 4.
    ///
    /// # Safety
    /// `dest_ptr` must have at least `64 * num_blocks` bytes available to be
    /// overwritten, or else it could produce undefined behavior
    #[cfg(feature = "rng")]
    unsafe fn write_par_ks_blocks(&mut self, buffer: &mut [u32; 64]) {
        let mut blocks = [
            [self.state[0], self.state[1], self.state[2], self.state[3]],
            [
                self.state[0],
                self.state[1],
                self.state[2],
                add_counter!(self.state[3], self.ctrs[0], V),
            ],
            [
                self.state[0],
                self.state[1],
                self.state[2],
                add_counter!(self.state[3], self.ctrs[1], V),
            ],
            [
                self.state[0],
                self.state[1],
                self.state[2],
                add_counter!(self.state[3], self.ctrs[2], V),
            ],
        ];

        for _ in 0..R::COUNT {
            double_quarter_round(&mut blocks);
        }

        let mut dest_ptr = buffer.as_mut_ptr() as *mut u8;
        for block in 0..4 {
            // add state to block
            for state_row in 0..4 {
                add_assign_vec!(blocks[block][state_row], self.state[state_row]);
            }
            if block > 0 {
                blocks[block][3] = add_counter!(blocks[block][3], self.ctrs[block - 1], V);
            }
            // write blocks to buffer
            for state_row in 0..4 {
                vst1q_u8(
                    dest_ptr.offset(state_row << 4),
                    vreinterpretq_u8_u32(blocks[block][state_row as usize]),
                );
            }
            dest_ptr = dest_ptr.add(64);
        }
        self.state[3] = add_counter!(self.state[3], self.ctrs[3], V);
    }
}

#[inline]
unsafe fn double_quarter_round(blocks: &mut [[uint32x4_t; 4]; 4]) {
    add_xor_rot(blocks);
    rows_to_cols(blocks);
    add_xor_rot(blocks);
    cols_to_rows(blocks);
}

#[inline]
unsafe fn add_xor_rot(blocks: &mut [[uint32x4_t; 4]; 4]) {
    /// Evaluates to `a = a ^ b`, where the operands are u32x4s
    macro_rules! xor_assign_vec {
        ($a:expr, $b:expr) => {
            $a = veorq_u32($a, $b)
        };
    }
    for block in blocks.iter_mut() {
        // this part of the code cannot be reduced much more without having
        // to deal with some problems regarding `rotate_left` requiring the second
        // argument to be a const, and const arrays cannot be indexed by non-consts
        add_assign_vec!(block[0], block[1]);
        xor_assign_vec!(block[3], block[0]);
        rotate_left!(block[3], 16);

        add_assign_vec!(block[2], block[3]);
        xor_assign_vec!(block[1], block[2]);
        rotate_left!(block[1], 12);

        add_assign_vec!(block[0], block[1]);
        xor_assign_vec!(block[3], block[0]);
        rotate_left!(block[3], 8);

        add_assign_vec!(block[2], block[3]);
        xor_assign_vec!(block[1], block[2]);
        rotate_left!(block[1], 7);
    }
}

#[inline]
unsafe fn rows_to_cols(blocks: &mut [[uint32x4_t; 4]; 4]) {
    for block in blocks.iter_mut() {
        extract!(block[1], 1);
        extract!(block[2], 2);
        extract!(block[3], 3);
    }
}

#[inline]
unsafe fn cols_to_rows(blocks: &mut [[uint32x4_t; 4]; 4]) {
    for block in blocks.iter_mut() {
        extract!(block[1], 3);
        extract!(block[2], 2);
        extract!(block[3], 1);
    }
}
