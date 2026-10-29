//! BLAKE2s, and the many-lane arrangement of it that BLAKE2sp wants.
//!
//! The compression function is RFC 7693 section 3.2, unchanged. What this
//! module adds is the observation BLAKE2sp's dealing makes available: while
//! a group of 512 bytes gives EVERY leaf exactly one block, all eight
//! leaves are at the same counter and none of them is at its last block, so
//! their compressions differ only in the state and the message. Four of
//! them therefore fit the lanes of one 128-bit register with no
//! cross-lane work at all, and the round is the scalar round with every
//! word four wide.
//!
//! Only whole groups go through the lane kernel. Each leaf's FINAL block is
//! its own length, carries the last-block flag and (for leaf 7) the
//! last-node flag, so it is compressed one at a time in [`Leaves::finish`]
//! where those differences are cheap: there are eight of them in all.
//!
//! This is one of the two modules spec L section 7 allows `unsafe` in. It
//! is one intrinsic call per line, and the safety obligation of every one
//! is the target feature plus a slice length checked by the caller.
#![allow(unsafe_code)]

/// The x86-64 eight-lane kernel, behind run-time detection.
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86;

/// Whether this CPU runs the eight-lane x86-64 kernel, which is when the
/// seam in `carry/wiring.rs` builds the `Lanes` arm off aarch64.
#[cfg(target_arch = "x86_64")]
pub(crate) fn wide_kernel() -> bool {
    x86::form().is_some()
}

/// Bytes per BLAKE2s block.
pub(crate) const BLOCK: usize = 64;
/// Leaves, which is the format's fanout.
pub(crate) const LEAVES: usize = 8;
/// Bytes that fill one block in every leaf.
pub(crate) const GROUP: usize = BLOCK * LEAVES;
/// The leaf and root digest length, which is also the inner length.
pub(crate) const DIGEST: usize = 32;
/// Leaves one vector kernel advances at once.
const LANES: usize = 4;

/// RFC 7693 section 2.6.
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// RFC 7693 section 2.7, the ten permutations BLAKE2s uses.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The starting chaining value for a node with these tree parameters
/// (RFC 7693 section 2.8): digest 32, key 0, fanout 8, depth 2, leaf
/// length 0, the node's offset and depth, inner length 32, no salt and no
/// personalisation.
fn initial(node_offset: u64, node_depth: u8) -> [u32; 8] {
    let mut param = [0u8; 32];
    param[0] = DIGEST as u8;
    param[2] = LEAVES as u8;
    param[3] = 2;
    param[8..14].copy_from_slice(&node_offset.to_le_bytes()[..6]);
    param[14] = node_depth;
    param[15] = DIGEST as u8;
    let mut h = IV;
    let (words, _) = param.as_chunks::<4>();
    for (word, bytes) in h.iter_mut().zip(words) {
        *word ^= u32::from_le_bytes(*bytes);
    }
    h
}

/// One BLAKE2s compression, scalar (RFC 7693 section 3.2).
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK], counter: u64, last: bool, last_node: bool) {
    let (words, _) = block.as_chunks::<4>();
    let m: [u32; 16] = std::array::from_fn(|i| u32::from_le_bytes(words[i]));
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u32;
    v[13] ^= (counter >> 32) as u32;
    if last {
        v[14] = !v[14];
    }
    if last_node {
        v[15] = !v[15];
    }
    #[inline(always)]
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (i, word) in h.iter_mut().enumerate() {
        *word ^= v[i] ^ v[i + 8];
    }
}

/// Advance four leaves of one half through every group, no block final.
///
/// `half` picks leaves 0 to 3 or 4 to 7; the group's dealing puts each
/// half's four blocks side by side, so one half of one group is a
/// contiguous 256-byte run. `counter` is what every leaf has compressed
/// before this call. This is the arm a worker runs when the two halves are
/// on two threads; one thread runs [`absorb_both`] instead.
// Live with the `parallel` feature only, which the default build has.
#[allow(dead_code)]
fn absorb_half(states: &mut [[u32; 8]; LANES], groups: &[u8], half: usize, counter: u64) {
    debug_assert!(groups.len().is_multiple_of(GROUP));
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is guaranteed by the target architecture, and the
        // kernel reads only inside `groups`, a whole number of groups.
        unsafe { neon::half(states, groups, half, counter) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut counter = counter;
        // `as_chunks`, not `chunks_exact`: the chunk width is a constant,
        // so the compiler carries it in the type and no length check runs
        // per group. Only a non-aarch64 build selects this arm, which is
        // why clippy had never said so on a box here.
        for group in groups.as_chunks::<GROUP>().0 {
            counter += BLOCK as u64;
            for (lane, state) in states.iter_mut().enumerate() {
                let at = (half * LANES + lane) * BLOCK;
                let block: &[u8; BLOCK] = group[at..at + BLOCK].try_into().expect("one block");
                compress(state, block, counter, false, false);
            }
        }
    }
}

/// MEASURING ONLY (feature `b2sp-x86-team`): the smallest batch the leaf
/// team arm takes. Under it a leaf's share is a few tens of microseconds
/// of scalar work, which a task's hand-over would be most of.
#[cfg(all(feature = "b2sp-x86-team", feature = "parallel"))]
const TEAM_ARM_MIN: usize = 256 * 1024;

/// MEASURING ONLY: whether `RARKIT_B2SP_X86_TEAM=1` asks for the leaf team
/// arm, read once.
#[cfg(all(feature = "b2sp-x86-team", feature = "parallel"))]
fn team_arm() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("RARKIT_B2SP_X86_TEAM").is_ok_and(|v| v.trim() == "1"))
}

/// MEASURING ONLY: advance the eight leaves through every group as EIGHT
/// tasks of the caller's pool, each the scalar compression over its own
/// leaf's blocks, read where they lie at a stride of one group. The leaves
/// share nothing, so the digest is the one-thread kernel's.
///
/// What it is for: the retake of 19 Sep 2026's decline of a leaf team on
/// x86-64, which was taken against a scalar one-thread kernel, against the
/// eight-lane AVX-512VL kernel that has run there since 28 Sep.
#[cfg(all(feature = "b2sp-x86-team", feature = "parallel"))]
fn absorb_team(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
    debug_assert!(groups.len().is_multiple_of(GROUP));
    rayon::scope(|scope| {
        for (half, states) in halves.iter_mut().enumerate() {
            for (lane, state) in states.iter_mut().enumerate() {
                scope.spawn(move |_| {
                    let at = (half * LANES + lane) * BLOCK;
                    let mut counter = counter;
                    for group in groups.as_chunks::<GROUP>().0 {
                        counter += BLOCK as u64;
                        let block: &[u8; BLOCK] =
                            group[at..at + BLOCK].try_into().expect("one block");
                        compress(state, block, counter, false, false);
                    }
                });
            }
        }
    });
}

/// Advance all eight leaves through every group, on one thread.
///
/// The two halves share no state, so their rounds interleave into one
/// instruction stream. That is the whole point: a BLAKE2s round is a short
/// chain of dependent adds, exclusive-ors and rotations, and four lanes
/// alone leave the pipelines waiting on it. Eight lanes in flight fill
/// them.
fn absorb_both(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
    debug_assert!(groups.len().is_multiple_of(GROUP));
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: as in `absorb_half`.
        unsafe { neon::both(halves, groups, counter) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let (first, second) = halves.split_at_mut(1);
        absorb_half(&mut first[0], groups, 0, counter);
        absorb_half(&mut second[0], groups, 1, counter);
    }
}

/// The NEON kernels.
#[cfg(target_arch = "aarch64")]
mod neon {
    use super::{BLOCK, GROUP, IV, LANES, SIGMA};
    use std::arch::aarch64::*;

    /// `x` rotated right by 16 in every lane: one byte-reverse, where the
    /// shift pair would be three instructions and a longer chain.
    #[inline(always)]
    unsafe fn ror16(x: uint32x4_t) -> uint32x4_t {
        // SAFETY: NEON, enabled by the caller's target feature.
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }
    /// `x` rotated right by `N`, as a shift and a shift-right-and-insert.
    #[inline(always)]
    unsafe fn ror12(x: uint32x4_t) -> uint32x4_t {
        // SAFETY: as above.
        unsafe { vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x) }
    }
    /// The byte permutation `ror8` is, as a table for [`vqtbl1q_u8`].
    ///
    /// Rotating a little-endian `u32` right by eight bits moves byte 1
    /// into byte 0 and byte 0 up to byte 3, which is a permutation of
    /// whole bytes and therefore one `tbl` rather than the shift pair the
    /// other two rotates need. Spelled out per lane so it reads as the
    /// permutation it is.
    const ROR8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

    /// `x` rotated right by 8 in every lane, as one table lookup.
    ///
    /// The shift pair this replaces was two instructions of the seventeen
    /// a `g` runs; `ror16` is already a single `rev32` for the same
    /// reason, and `ror12` and `ror7` are not byte permutations and keep
    /// the pair.
    #[inline(always)]
    unsafe fn ror8(x: uint32x4_t, table: uint8x16_t) -> uint32x4_t {
        // SAFETY: as above; `vqtbl1q_u8` indexes a 16-byte table with
        // sixteen in-range indices, which `ROR8` is by construction.
        unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), table)) }
    }
    #[inline(always)]
    unsafe fn ror7(x: uint32x4_t) -> uint32x4_t {
        // SAFETY: as above.
        unsafe { vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x) }
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn g(
        v: &mut [uint32x4_t; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: uint32x4_t,
        y: uint32x4_t,
        ror8_table: uint8x16_t,
    ) {
        // SAFETY: NEON, enabled by the caller's target feature; every
        // index the callers pass is inside `v`.
        unsafe {
            v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), x);
            v[d] = ror16(veorq_u32(v[d], v[a]));
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = ror12(veorq_u32(v[b], v[c]));
            v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), y);
            v[d] = ror8(veorq_u32(v[d], v[a]), ror8_table);
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = ror7(veorq_u32(v[b], v[c]));
        }
    }

    /// One half's four blocks of one group, transposed into `m` so that
    /// lane `l` holds leaf `l`'s word.
    #[inline(always)]
    unsafe fn gather(m: &mut [u32; 16 * LANES], blocks: *const u8) {
        // SAFETY: NEON; `blocks` points at 256 readable bytes and `m` has
        // room for sixteen lane words.
        unsafe {
            for quarter in 0..4 {
                let row =
                    |lane: usize| vld1q_u32(blocks.add(lane * BLOCK + quarter * 16) as *const u32);
                let (a, b, c, d) = (row(0), row(1), row(2), row(3));
                let (t0, t1) = (vtrn1q_u32(a, b), vtrn2q_u32(a, b));
                let (t2, t3) = (vtrn1q_u32(c, d), vtrn2q_u32(c, d));
                let at = m.as_mut_ptr().add(quarter * 4 * LANES);
                vst1q_u32(at, vcombine_u32(vget_low_u32(t0), vget_low_u32(t2)));
                vst1q_u32(
                    at.add(LANES),
                    vcombine_u32(vget_low_u32(t1), vget_low_u32(t3)),
                );
                vst1q_u32(
                    at.add(2 * LANES),
                    vcombine_u32(vget_high_u32(t0), vget_high_u32(t2)),
                );
                vst1q_u32(
                    at.add(3 * LANES),
                    vcombine_u32(vget_high_u32(t1), vget_high_u32(t3)),
                );
            }
        }
    }

    /// Load a half's chaining values into lane vectors.
    #[inline(always)]
    unsafe fn load(states: &[[u32; 8]; LANES], h: &mut [uint32x4_t; 8]) {
        // SAFETY: NEON; `h` has room for eight vectors.
        unsafe {
            for (i, slot) in h.iter_mut().enumerate() {
                let quad = [states[0][i], states[1][i], states[2][i], states[3][i]];
                *slot = vld1q_u32(quad.as_ptr());
            }
        }
    }

    /// Write lane vectors back into a half's chaining values.
    #[inline(always)]
    unsafe fn store(h: &[uint32x4_t; 8], states: &mut [[u32; 8]; LANES]) {
        // SAFETY: NEON; `h` holds eight vectors.
        unsafe {
            for (i, word) in h.iter().enumerate() {
                let mut quad = [0u32; LANES];
                vst1q_u32(quad.as_mut_ptr(), *word);
                for (lane, value) in quad.iter().enumerate() {
                    states[lane][i] = *value;
                }
            }
        }
    }

    /// Set up one half's working words for a block.
    #[inline(always)]
    unsafe fn prepare(v: &mut [uint32x4_t; 16], h: &[uint32x4_t; 8], counter: u64) {
        // SAFETY: NEON; `v` holds sixteen vectors and `h` eight.
        unsafe {
            v[..8].copy_from_slice(h);
            for (i, slot) in v[8..16].iter_mut().enumerate() {
                *slot = vdupq_n_u32(IV[i]);
            }
            // Every lane is at the same counter and none is at its last
            // block, so the two flag words stay as they were.
            v[12] = veorq_u32(v[12], vdupq_n_u32(counter as u32));
            v[13] = veorq_u32(v[13], vdupq_n_u32((counter >> 32) as u32));
        }
    }

    /// Fold one block's working words back into the chaining values.
    #[inline(always)]
    unsafe fn mix(h: &mut [uint32x4_t; 8], v: &[uint32x4_t; 16]) {
        // SAFETY: NEON; both slices are long enough for the indices used.
        unsafe {
            for (i, slot) in h.iter_mut().enumerate() {
                *slot = veorq_u32(*slot, veorq_u32(v[i], v[i + 8]));
            }
        }
    }

    /// Four leaves, all the groups.
    #[target_feature(enable = "neon")]
    // Live with the `parallel` feature only, which the default build has.
    #[allow(dead_code)]
    pub(super) unsafe fn half(
        states: &mut [[u32; 8]; LANES],
        groups: &[u8],
        which: usize,
        counter: u64,
    ) {
        // SAFETY: NEON is enabled per the target feature; every read is
        // inside one group of `groups`, whose length the caller checked.
        unsafe {
            let ror8_table = vld1q_u8(ROR8.as_ptr());
            let mut h = [vdupq_n_u32(0); 8];
            load(states, &mut h);
            let mut counter = counter;
            let mut m = [0u32; 16 * LANES];
            let mut v = [vdupq_n_u32(0); 16];
            let (whole, _) = groups.as_chunks::<GROUP>();
            for group in whole {
                counter += BLOCK as u64;
                gather(&mut m, group.as_ptr().add(which * LANES * BLOCK));
                prepare(&mut v, &h, counter);
                macro_rules! word {
                    ($i:expr) => {
                        vld1q_u32(m.as_ptr().add($i * LANES))
                    };
                }
                macro_rules! round {
                    ($r:expr) => {{
                        const S: [usize; 16] = SIGMA[$r];
                        g(&mut v, 0, 4, 8, 12, word!(S[0]), word!(S[1]), ror8_table);
                        g(&mut v, 1, 5, 9, 13, word!(S[2]), word!(S[3]), ror8_table);
                        g(&mut v, 2, 6, 10, 14, word!(S[4]), word!(S[5]), ror8_table);
                        g(&mut v, 3, 7, 11, 15, word!(S[6]), word!(S[7]), ror8_table);
                        g(&mut v, 0, 5, 10, 15, word!(S[8]), word!(S[9]), ror8_table);
                        g(&mut v, 1, 6, 11, 12, word!(S[10]), word!(S[11]), ror8_table);
                        g(&mut v, 2, 7, 8, 13, word!(S[12]), word!(S[13]), ror8_table);
                        g(&mut v, 3, 4, 9, 14, word!(S[14]), word!(S[15]), ror8_table);
                    }};
                }
                round!(0);
                round!(1);
                round!(2);
                round!(3);
                round!(4);
                round!(5);
                round!(6);
                round!(7);
                round!(8);
                round!(9);
                mix(&mut h, &v);
            }
            store(&h, states);
        }
    }

    /// Eight leaves, all the groups, the two halves interleaved.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn both(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
        // SAFETY: as in `half`.
        unsafe {
            let ror8_table = vld1q_u8(ROR8.as_ptr());
            let mut ha = [vdupq_n_u32(0); 8];
            let mut hb = [vdupq_n_u32(0); 8];
            load(&halves[0], &mut ha);
            load(&halves[1], &mut hb);
            let mut counter = counter;
            let mut ma = [0u32; 16 * LANES];
            let mut mb = [0u32; 16 * LANES];
            let mut va = [vdupq_n_u32(0); 16];
            let mut vb = [vdupq_n_u32(0); 16];
            let (whole, _) = groups.as_chunks::<GROUP>();
            for group in whole {
                counter += BLOCK as u64;
                gather(&mut ma, group.as_ptr());
                gather(&mut mb, group.as_ptr().add(LANES * BLOCK));
                prepare(&mut va, &ha, counter);
                prepare(&mut vb, &hb, counter);
                macro_rules! word {
                    ($m:expr, $i:expr) => {
                        vld1q_u32($m.as_ptr().add($i * LANES))
                    };
                }
                macro_rules! pair {
                    ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $y:expr) => {{
                        g(
                            &mut va,
                            $a,
                            $b,
                            $c,
                            $d,
                            word!(ma, $x),
                            word!(ma, $y),
                            ror8_table,
                        );
                        g(
                            &mut vb,
                            $a,
                            $b,
                            $c,
                            $d,
                            word!(mb, $x),
                            word!(mb, $y),
                            ror8_table,
                        );
                    }};
                }
                macro_rules! round {
                    ($r:expr) => {{
                        const S: [usize; 16] = SIGMA[$r];
                        pair!(0, 4, 8, 12, S[0], S[1]);
                        pair!(1, 5, 9, 13, S[2], S[3]);
                        pair!(2, 6, 10, 14, S[4], S[5]);
                        pair!(3, 7, 11, 15, S[6], S[7]);
                        pair!(0, 5, 10, 15, S[8], S[9]);
                        pair!(1, 6, 11, 12, S[10], S[11]);
                        pair!(2, 7, 8, 13, S[12], S[13]);
                        pair!(3, 4, 9, 14, S[14], S[15]);
                    }};
                }
                round!(0);
                round!(1);
                round!(2);
                round!(3);
                round!(4);
                round!(5);
                round!(6);
                round!(7);
                round!(8);
                round!(9);
                mix(&mut ha, &va);
                mix(&mut hb, &vb);
            }
            let (first, second) = halves.split_at_mut(1);
            store(&ha, &mut first[0]);
            store(&hb, &mut second[0]);
        }
    }
}

/// The eight leaves of one BLAKE2sp, advanced in whole groups.
#[derive(Clone)]
pub(crate) struct Leaves {
    /// The two halves the lane kernel takes: leaves 0 to 3 and 4 to 7.
    halves: [[[u32; 8]; LANES]; 2],
    /// Bytes every leaf has already compressed.
    counter: u64,
}

impl Default for Leaves {
    fn default() -> Leaves {
        Leaves::new()
    }
}

impl Leaves {
    /// Eight leaves over no bytes yet.
    pub(crate) fn new() -> Leaves {
        Leaves {
            halves: std::array::from_fn(|half| {
                std::array::from_fn(|lane| initial((half * LANES + lane) as u64, 0))
            }),
            counter: 0,
        }
    }

    /// Feed whole groups, none of which is any leaf's last.
    ///
    /// With `workers` above one the two halves run on the pool; they share
    /// nothing, so the digest is the same either way.
    pub(crate) fn absorb(&mut self, groups: &[u8], workers: usize) {
        debug_assert!(groups.len().is_multiple_of(GROUP));
        if groups.is_empty() {
            return;
        }
        let start = self.counter;
        self.counter = start + (groups.len() / GROUP) as u64 * BLOCK as u64;
        // MEASURING ONLY (feature `b2sp-x86-team`): eight scalar leaves,
        // one a task, in place of the eight-lane kernel.
        #[cfg(all(feature = "b2sp-x86-team", feature = "parallel"))]
        if groups.len() >= TEAM_ARM_MIN && team_arm() {
            absorb_team(&mut self.halves, groups, start);
            return;
        }
        // All eight leaves in one register on x86-64: there is no half to
        // hand a second worker, so the allowance is not consulted.
        #[cfg(target_arch = "x86_64")]
        if let Some(form) = x86::form() {
            x86::absorb(form, &mut self.halves, groups, start);
            return;
        }
        #[cfg(feature = "parallel")]
        if workers > 1 {
            let (first, second) = self.halves.split_at_mut(1);
            rayon::join(
                || absorb_half(&mut first[0], groups, 0, start),
                || absorb_half(&mut second[0], groups, 1, start),
            );
            return;
        }
        let _ = workers;
        absorb_both(&mut self.halves, groups, start);
    }

    /// Compress each leaf's last block or two and hash the eight digests.
    ///
    /// `tail` is the last TWO groups of the input, at most. Two, not one:
    /// if only the first few leaves are reached by a partial last group,
    /// the leaves past it had their final block in the group BEFORE it, and
    /// a leaf must not compress its final block as an ordinary one. Held
    /// back this way, every leaf's last block is here, and a leaf with two
    /// blocks in the tail compresses the first as an ordinary one.
    pub(crate) fn finish(mut self, tail: &[u8]) -> [u8; DIGEST] {
        debug_assert!(tail.len() <= 2 * GROUP);
        let mut message = [0u8; LEAVES * DIGEST];
        let piece = |number: usize| -> &[u8] {
            let at = (number * BLOCK).min(tail.len());
            &tail[at..(at + BLOCK).min(tail.len())]
        };
        for leaf in 0..LEAVES {
            let state = &mut self.halves[leaf / LANES][leaf % LANES];
            let mut counter = self.counter;
            let (first, second) = (piece(leaf), piece(leaf + LEAVES));
            let mut block = [0u8; BLOCK];
            if !second.is_empty() {
                debug_assert_eq!(first.len(), BLOCK);
                block.copy_from_slice(first);
                counter += BLOCK as u64;
                compress(state, &block, counter, false, false);
                block = [0u8; BLOCK];
            }
            let last = if second.is_empty() { first } else { second };
            block[..last.len()].copy_from_slice(last);
            counter += last.len() as u64;
            compress(state, &block, counter, true, leaf == LEAVES - 1);
            let (slots, _) = message[leaf * DIGEST..].as_chunks_mut::<4>();
            for (word, slot) in state.iter().zip(slots) {
                *slot = word.to_le_bytes();
            }
        }
        root(&message)
    }
}

/// The root: one BLAKE2s at node depth 1 over the eight leaf digests.
fn root(message: &[u8; LEAVES * DIGEST]) -> [u8; DIGEST] {
    let mut h = initial(0, 1);
    let (blocks, _) = message.as_chunks::<BLOCK>();
    let mut counter = 0u64;
    for (i, block) in blocks.iter().enumerate() {
        counter += BLOCK as u64;
        // The last-node flag belongs to the LAST compression of the node,
        // not to every block of it.
        let last = i + 1 == blocks.len();
        compress(&mut h, block, counter, last, last);
    }
    let mut out = [0u8; DIGEST];
    let (slots, _) = out.as_chunks_mut::<4>();
    for (word, slot) in h.iter().zip(slots) {
        *slot = word.to_le_bytes();
    }
    out
}

#[cfg(all(test, feature = "b2sp-x86-team", feature = "parallel"))]
mod team_arm_tests {
    use super::*;

    /// The measuring arm's eight tasks leave every leaf where the scalar
    /// halves on one thread leave it, from a counter that is not zero.
    #[test]
    fn eight_leaf_tasks_agree_with_the_scalar_halves() {
        let data: Vec<u8> = (0..(700 * GROUP)).map(|i| (i * 31 + i / 7) as u8).collect();
        let fresh = || -> [[[u32; 8]; LANES]; 2] {
            std::array::from_fn(|half| {
                std::array::from_fn(|lane| initial((half * LANES + lane) as u64, 0))
            })
        };
        let (mut team, mut plain) = (fresh(), fresh());
        for (at, len) in [(0, 300 * GROUP), (300 * GROUP, 400 * GROUP)] {
            let counter = (at / GROUP * BLOCK) as u64;
            absorb_team(&mut team, &data[at..at + len], counter);
            for (half, states) in plain.iter_mut().enumerate() {
                let mut c = counter;
                for group in data[at..at + len].as_chunks::<GROUP>().0 {
                    c += BLOCK as u64;
                    for (lane, state) in states.iter_mut().enumerate() {
                        let from = (half * LANES + lane) * BLOCK;
                        let block: &[u8; BLOCK] =
                            group[from..from + BLOCK].try_into().expect("one block");
                        compress(state, block, c, false, false);
                    }
                }
            }
        }
        assert_eq!(team, plain);
    }
}
