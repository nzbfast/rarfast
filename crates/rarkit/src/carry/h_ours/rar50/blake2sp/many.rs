//! Carried from the predecessor's `rar50/blake2sp/many.rs` at an earlier revision
//! (the fork tip): the 48 items ours from birth per the
//! provenance census, 758 lines. Re-verified 18 Sep 2026 with a WHOLE-TREE
//! provenance run over the predecessor's source tree (the donor's main
//! branch against the fork point), which is the run that counts: a
//! narrow-prefix run cannot see the other files and under-reports. The file
//! is byte-identical at three revisions of the predecessor, the one
//! `Cargo.lock` pins among them, so the verdict covers all three.
//!
//! Nothing below is anything but carried text. Four items this kernel calls
//! would not cross - `IV` and `LANES` (held back on a short-name
//! collision, zero donor lines), `g` (the same) and `load` (one donor-blamed
//! line) - and neither would the four constants and the `LeafSet` trait the
//! predecessor kept in its `mod.rs`. All of those are this repository's
//! own text in [`crate::carry::wiring::blake2sp`], on the precedent the CRC32 carry
//! set: the carried kernel is bound to package L's items through the wiring
//! layer rather than to the predecessor's.
//!
//! The visibility edits to the carried text are `pub(crate)` on `V`, on the
//! four rotate helpers and on `THREAD_MIN_GROUPS`, so that the wiring's `g`
//! composes THIS kernel's rotates - the `tbl`-based `rot8` among them -
//! rather than substituting package L's, which choose different
//! instructions, and so that package L can READ this kernel's pool
//! threshold instead of repeating the number
//! (`crate::carry::wiring::blake2sp::POOL_MIN_BATCH`, which says why).
//!
//! The resident pool work of 19 Sep 2026 changed three carried items
//! in substance, so they are no longer byte-identical to the fork's and a
//! later census must read them as edited rather than as carried:
//!
//! - `ScalarLeafTeam::run` earns the pool on the bytes absorbed SO FAR
//!   rather than on one batch, and keeps the work on the calling thread
//!   until it exists, so a caller feeding runs under the threshold reaches
//!   a standing team instead of starting seven threads on every call. That
//!   is the same defect package L's staging addresses from the other side,
//!   fixed here so the kernel no longer needs a caller to avoid it;
//! - `ManyLeaves::absorb_pieces` draws the same line on its NEON arm, and
//!   takes a width of one, which runs both halves here;
//! - `Job` carries the number of shares the batch was cut into and
//!   `worker_loop` stands down outside it. `dispatch` wakes every worker
//!   but needs only the first `shares` of them, and a worker past that
//!   wrote past `states` and `withheld`: unreachable while every dispatch
//!   cut the eight leaves one apiece, reachable as soon as a caller's
//!   allowance cut them any other way, which `absorb_groups_at` allows.
//!
//! The same work made three more, so the
//! carried items are no longer byte-identical to the fork's and a later
//! census must read them as edited rather than as carried:
//!
//! - `ScalarLeafTeam::run` earns the pool on the bytes absorbed SO FAR
//!   rather than on one batch, and keeps the work on the calling thread
//!   until it exists, so a caller feeding 256 KiB runs reaches a standing
//!   team instead of starting seven threads on every call;
//! - `ManyLeaves::absorb_pieces` draws the same line on its NEON arm, and
//!   takes a width of one, which runs both halves here;
//! - `Job` carries the number of shares the batch was cut into and
//!   `worker_loop` stands down outside it. `dispatch` wakes every worker
//!   but needs only the first `shares` of them, and a worker past that
//!   wrote past `states` and `withheld`: unreachable while every dispatch
//!   cut the eight leaves one apiece, reachable as soon as a caller's
//!   allowance cut them any other way, which `absorb_groups_at` allows.
//!
//! The resident team work of 23 Sep 2026 changed two
//! more, so a later census reads them as edited too: `ManyLeaves::
//! absorb_pieces` hands a team of two's second NEON half to a resident
//! helper leased per stream (the foot of this file) instead of a spawn
//! per batch, and `LeafPool` is generic over the batch it runs, so the
//! scalar team's shares and that half share one pool.
//!
//! The work of 26 Sep 2026 changed one
//! more: `ScalarLeafTeam`'s pool is LEASED from a parked set and given back
//! when the team is dropped (`TeamLease`, beside the helper at the foot of
//! this file), where it was built per stream and joined at the stream's
//! end.
//!
//! The predecessor's `#[cfg(test)]` panic injector, its live-worker counter
//! and their fragments inside the carried items are TEST by the census and
//! are not here; the pool's panic handling itself is, and is untested in
//! this repository; that test is not written yet.

//! Spec L's erratum of 18 Sep 2026 names this module and permits `unsafe`
//! inside it, which is why the crate-wide `deny` is lifted here.
#![allow(unsafe_code)]

use std::arch::aarch64::{
    uint32x4_t, vaddq_u32, vcombine_u32, vcreate_u32, vdupq_n_u32, veorq_u32, vgetq_lane_u64,
    vqtbl1q_u8, vreinterpretq_u16_u32, vreinterpretq_u32_u16, vreinterpretq_u32_u64,
    vreinterpretq_u32_u8, vreinterpretq_u64_u32, vreinterpretq_u8_u32, vrev32q_u16, vshlq_n_u32,
    vsriq_n_u32, vzip1q_u32, vzip1q_u64, vzip2q_u32, vzip2q_u64,
};

use crate::carry::wiring::blake2sp::{
    g, load, LeafSet, Lent, BLOCK_BYTES, GROUP_BYTES, IV, LANES, OUT_BYTES, PARALLELISM,
};

pub(crate) type V = uint32x4_t;

const HALVES: usize = PARALLELISM / LANES;
/// Whole groups above which a thread is worth starting. One half is one
/// thread's worth of vector work; below this the spawn costs more than it
/// buys.
///
/// Read two ways, and the difference matters. For the NEON halves, which
/// spawn per call, it is the groups in THIS call. For the scalar team,
/// whose workers are resident, it is the groups absorbed SO FAR: there the
/// question is not whether this batch repays a spawn but whether the
/// stream has earned a standing team, and once it has, a batch of any size
/// reaches it for the price of a condvar.
///
/// `pub(crate)` so that package L can read it as
/// [`crate::carry::wiring::blake2sp::POOL_MIN_BATCH`] and stage to it
/// rather than repeat the number. Since the team earns its pool on the
/// running total, staging to it is no longer what makes the per-call
/// thread start unreachable; it is now belt and braces, and whether
/// to keep it is an open question.
pub(crate) const THREAD_MIN_GROUPS: usize = 1024;

/// One lane vector as its little-endian bytes: the state words live in this
/// form between kernel calls so no pointer ever reaches an intrinsic.
type LaneBytes = [u8; 16];

#[inline]
#[target_feature(enable = "neon")]
fn load_words(w: [u32; LANES]) -> V {
    vcombine_u32(
        vcreate_u32(w[0] as u64 | (w[1] as u64) << 32),
        vcreate_u32(w[2] as u64 | (w[3] as u64) << 32),
    )
}

#[inline]
#[target_feature(enable = "neon")]
fn store(v: V) -> LaneBytes {
    let v = vreinterpretq_u64_u32(v);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&vgetq_lane_u64::<0>(v).to_le_bytes());
    out[8..].copy_from_slice(&vgetq_lane_u64::<1>(v).to_le_bytes());
    out
}

#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn rot16(x: V) -> V {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
}

#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn rot12(x: V) -> V {
    vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x)
}

#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn rot8(x: V) -> V {
    // Byte shuffle: each 32-bit lane rotated right by one byte.
    let index = vreinterpretq_u8_u32(load_words([
        0x0003_0201,
        0x0407_0605,
        0x080B_0A09,
        0x0C0F_0E0D,
    ]));
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), index))
}

#[inline]
#[target_feature(enable = "neon")]
pub(crate) fn rot7(x: V) -> V {
    vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x)
}

/// One BLAKE2s round with its sigma permutation spelled out as literals.
/// A `for s in SIGMA` loop does not unroll here and leaves every message
/// word a bounds-checked indexed stack load (measured 22 Aug 2026: 16
/// compare-and-branch pairs per round, and the kernel no faster than the
/// scalar crate).
macro_rules! round {
    ($v:ident, $m:ident, $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal,
     $s5:literal, $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal,
     $s11:literal, $s12:literal, $s13:literal, $s14:literal, $s15:literal) => {
        g(&mut $v, 0, 4, 8, 12, $m[$s0], $m[$s1]);
        g(&mut $v, 1, 5, 9, 13, $m[$s2], $m[$s3]);
        g(&mut $v, 2, 6, 10, 14, $m[$s4], $m[$s5]);
        g(&mut $v, 3, 7, 11, 15, $m[$s6], $m[$s7]);
        g(&mut $v, 0, 5, 10, 15, $m[$s8], $m[$s9]);
        g(&mut $v, 1, 6, 11, 12, $m[$s10], $m[$s11]);
        g(&mut $v, 2, 7, 8, 13, $m[$s12], $m[$s13]);
        g(&mut $v, 3, 4, 9, 14, $m[$s14], $m[$s15]);
    };
}

/// Transpose four 64-byte blocks into sixteen four-lane message words.
#[inline]
#[target_feature(enable = "neon")]
fn load_message(blocks: [&[u8]; LANES]) -> [V; 16] {
    let mut m = [vdupq_n_u32(0); 16];
    for quarter in 0..4 {
        let at = quarter * 16;
        let a = load(&blocks[0][at..at + 16]);
        let b = load(&blocks[1][at..at + 16]);
        let c = load(&blocks[2][at..at + 16]);
        let d = load(&blocks[3][at..at + 16]);
        let ab_lo = vreinterpretq_u64_u32(vzip1q_u32(a, b));
        let ab_hi = vreinterpretq_u64_u32(vzip2q_u32(a, b));
        let cd_lo = vreinterpretq_u64_u32(vzip1q_u32(c, d));
        let cd_hi = vreinterpretq_u64_u32(vzip2q_u32(c, d));
        m[quarter * 4] = vreinterpretq_u32_u64(vzip1q_u64(ab_lo, cd_lo));
        m[quarter * 4 + 1] = vreinterpretq_u32_u64(vzip2q_u64(ab_lo, cd_lo));
        m[quarter * 4 + 2] = vreinterpretq_u32_u64(vzip1q_u64(ab_hi, cd_hi));
        m[quarter * 4 + 3] = vreinterpretq_u32_u64(vzip2q_u64(ab_hi, cd_hi));
    }
    m
}

/// Compress `count` blocks into four lane states. Block `i` of lane `l`
/// starts at `data[i * stride + l * 64]`. `t_first` is the per-lane byte
/// counter AFTER the first block (it advances by 64 per block); `f0`/`f1`
/// are all-ones lane masks for the final-block and last-node flags and
/// apply to every block, so a multi-block call passes zeros.
#[target_feature(enable = "neon")]
fn compress_blocks_neon(
    h: &mut [LaneBytes; 8],
    data: &[u8],
    stride: usize,
    count: usize,
    t_first: [u64; LANES],
    f0: [u32; LANES],
    f1: [u32; LANES],
) {
    let mut hv = [vdupq_n_u32(0); 8];
    for (word, bytes) in hv.iter_mut().zip(h.iter()) {
        *word = load(bytes);
    }
    let iv: [V; 8] = [
        vdupq_n_u32(IV[0]),
        vdupq_n_u32(IV[1]),
        vdupq_n_u32(IV[2]),
        vdupq_n_u32(IV[3]),
        vdupq_n_u32(IV[4]),
        vdupq_n_u32(IV[5]),
        vdupq_n_u32(IV[6]),
        vdupq_n_u32(IV[7]),
    ];
    let f0 = veorq_u32(iv[6], load_words(f0));
    let f1 = veorq_u32(iv[7], load_words(f1));
    let mut t = t_first;
    for block in 0..count {
        let base = block * stride;
        let m = load_message([
            &data[base..base + BLOCK_BYTES],
            &data[base + BLOCK_BYTES..base + 2 * BLOCK_BYTES],
            &data[base + 2 * BLOCK_BYTES..base + 3 * BLOCK_BYTES],
            &data[base + 3 * BLOCK_BYTES..base + 4 * BLOCK_BYTES],
        ]);
        let t_lo = load_words([t[0] as u32, t[1] as u32, t[2] as u32, t[3] as u32]);
        let t_hi = load_words([
            (t[0] >> 32) as u32,
            (t[1] >> 32) as u32,
            (t[2] >> 32) as u32,
            (t[3] >> 32) as u32,
        ]);
        let mut v: [V; 16] = [
            hv[0],
            hv[1],
            hv[2],
            hv[3],
            hv[4],
            hv[5],
            hv[6],
            hv[7],
            iv[0],
            iv[1],
            iv[2],
            iv[3],
            veorq_u32(iv[4], t_lo),
            veorq_u32(iv[5], t_hi),
            f0,
            f1,
        ];
        round!(v, m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        round!(v, m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
        round!(v, m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
        round!(v, m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
        round!(v, m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
        round!(v, m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
        round!(v, m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
        round!(v, m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
        round!(v, m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
        round!(v, m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
        for word in 0..8 {
            hv[word] = veorq_u32(veorq_u32(hv[word], v[word]), v[word + 8]);
        }
        for lane in &mut t {
            *lane += BLOCK_BYTES as u64;
        }
    }
    for (bytes, word) in h.iter_mut().zip(hv.iter()) {
        *bytes = store(*word);
    }
}

/// The first of this module's two unsafe sites. See the module comment:
/// the only thing asserted is that NEON is present, and on aarch64 it
/// always is. The second is the persistent leaf team at the foot of the
/// file, whose argument is its own.
#[allow(unsafe_code)]
fn compress_blocks(
    h: &mut [LaneBytes; 8],
    data: &[u8],
    stride: usize,
    count: usize,
    t_first: [u64; LANES],
    f0: [u32; LANES],
    f1: [u32; LANES],
) {
    debug_assert!(
        data.len() >= count.saturating_sub(1) * stride + LANES * BLOCK_BYTES || count == 0
    );
    // SAFETY: Advanced SIMD (NEON) is mandatory in the ARMv8-A base
    // architecture and assumed by every aarch64 target rustc ships, so the
    // `#[target_feature(enable = "neon")]` precondition holds unconditionally
    // on the only architecture this module is compiled for. The callee takes
    // safe slices and integers only; no pointer, lifetime or aliasing claim
    // is being made here.
    unsafe { compress_blocks_neon(h, data, stride, count, t_first, f0, f1) }
}

/// Four leaves with consecutive indices, kept lane-wise.
#[derive(Clone)]
struct Half {
    /// State word `w` of the four lanes, as `h[w]`'s little-endian bytes.
    h: [LaneBytes; 8],
    /// The most recent full block of each lane, withheld because BLAKE2s
    /// cannot compress a block until it knows whether more input follows.
    pending: Option<[[u8; BLOCK_BYTES]; LANES]>,
    /// Bytes fed to each lane so far, pending block included. Uniform
    /// across lanes until finalization, because whole groups feed every
    /// leaf exactly one block.
    fed: u64,
}

impl Half {
    fn new(first_leaf: usize) -> Self {
        let mut h = [[0u8; 16]; 8];
        for lane in 0..LANES {
            let leaf = first_leaf + lane;
            // Parameter block, words 0..8: digest_length | key_length << 8 |
            // fanout << 16 | depth << 24; leaf_length; node_offset (48 bits,
            // low word then high half-word) | node_depth << 16 |
            // inner_length << 24; then salt and personalization, all zero.
            let params: [u32; 8] = [
                (OUT_BYTES as u32) | (PARALLELISM as u32) << 16 | 2 << 24,
                0,
                leaf as u32,
                (OUT_BYTES as u32) << 24,
                0,
                0,
                0,
                0,
            ];
            for word in 0..8 {
                h[word][lane * 4..lane * 4 + 4]
                    .copy_from_slice(&(IV[word] ^ params[word]).to_le_bytes());
            }
        }
        Self {
            h,
            pending: None,
            fed: 0,
        }
    }

    /// Feed whole groups. Lane `i` takes block `first_leaf + i` of every
    /// group, `first_leaf` being the block offset of this half's lanes.
    fn absorb_groups(&mut self, groups: &[u8], first_leaf: usize) {
        let slot = first_leaf * BLOCK_BYTES;
        let group_count = groups.len() / GROUP_BYTES;
        if group_count == 0 {
            return;
        }
        if let Some(pending) = self.pending.take() {
            compress_blocks(
                &mut self.h,
                pending.as_flattened(),
                0,
                1,
                [self.fed; LANES],
                [0; LANES],
                [0; LANES],
            );
        }
        // Every group but the last; the last is withheld.
        let lead = group_count - 1;
        compress_blocks(
            &mut self.h,
            &groups[slot..],
            GROUP_BYTES,
            lead,
            [self.fed + BLOCK_BYTES as u64; LANES],
            [0; LANES],
            [0; LANES],
        );
        let lanes =
            &groups[lead * GROUP_BYTES + slot..lead * GROUP_BYTES + slot + LANES * BLOCK_BYTES];
        let mut pending = [[0u8; BLOCK_BYTES]; LANES];
        for (lane, block) in pending.iter_mut().enumerate() {
            block.copy_from_slice(&lanes[lane * BLOCK_BYTES..(lane + 1) * BLOCK_BYTES]);
        }
        self.pending = Some(pending);
        self.fed += (group_count * BLOCK_BYTES) as u64;
    }

    /// Finish every lane. `tail` is this half's share of the final partial
    /// group (up to `LANES * BLOCK_BYTES` bytes, lane `i` owning bytes
    /// `i * 64..`); `last_node` marks the lane carrying the last-node flag.
    fn finalize(mut self, tail: &[u8], last_node: Option<usize>) -> [[u8; OUT_BYTES]; LANES] {
        let lane_len = |lane: usize| -> usize {
            tail.len()
                .saturating_sub(lane * BLOCK_BYTES)
                .min(BLOCK_BYTES)
        };
        let f1_for = |lane: usize| -> u32 {
            if last_node == Some(lane) {
                u32::MAX
            } else {
                0
            }
        };
        // Step 1: the withheld block. It is the final block of any lane the
        // tail gives nothing to.
        if let Some(pending) = self.pending.take() {
            let mut f0 = [0u32; LANES];
            let mut f1 = [0u32; LANES];
            for lane in 0..LANES {
                if lane_len(lane) == 0 {
                    f0[lane] = u32::MAX;
                    f1[lane] = f1_for(lane);
                }
            }
            compress_blocks(
                &mut self.h,
                pending.as_flattened(),
                0,
                1,
                [self.fed; LANES],
                f0,
                f1,
            );
            // Step 2 (pending case): lanes that received tail bytes compress
            // them as their final block; the others are finished already.
            let active: Vec<usize> = (0..LANES).filter(|&lane| lane_len(lane) > 0).collect();
            if !active.is_empty() {
                self.final_tail(tail, &active, f1_for);
            }
        } else {
            // No pending block: every lane's final block is its tail share,
            // empty shares included (an empty leaf still compresses one
            // zero block, per RFC 7693).
            let active: Vec<usize> = (0..LANES).collect();
            self.final_tail(tail, &active, f1_for);
        }
        let mut out = [[0u8; OUT_BYTES]; LANES];
        for (lane, digest) in out.iter_mut().enumerate() {
            for word in 0..8 {
                digest[word * 4..word * 4 + 4]
                    .copy_from_slice(&self.h[word][lane * 4..lane * 4 + 4]);
            }
        }
        out
    }

    fn final_tail(&mut self, tail: &[u8], active: &[usize], f1_for: impl Fn(usize) -> u32) {
        let mut blocks = [[0u8; BLOCK_BYTES]; LANES];
        let mut t = [self.fed; LANES];
        let mut f0 = [0u32; LANES];
        let mut f1 = [0u32; LANES];
        for &lane in active {
            let start = (lane * BLOCK_BYTES).min(tail.len());
            let end = ((lane + 1) * BLOCK_BYTES).min(tail.len());
            blocks[lane][..end - start].copy_from_slice(&tail[start..end]);
            t[lane] += (end - start) as u64;
            f0[lane] = u32::MAX;
            f1[lane] = f1_for(lane);
        }
        let mut h = self.h;
        compress_blocks(&mut h, blocks.as_flattened(), 0, 1, t, f0, f1);
        for &lane in active {
            for (mine, theirs) in self.h.iter_mut().zip(&h) {
                mine[lane * 4..lane * 4 + 4].copy_from_slice(&theirs[lane * 4..lane * 4 + 4]);
            }
        }
    }
}

/// The eight BLAKE2sp leaves as two four-lane halves.
#[derive(Clone)]
pub(crate) struct ManyLeaves {
    halves: [Half; HALVES],
}

impl LeafSet for ManyLeaves {
    fn new() -> Self {
        Self {
            halves: [Half::new(0), Half::new(LANES)],
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        debug_assert_eq!(groups.len() % GROUP_BYTES, 0);
        if groups.is_empty() {
            return;
        }
        let [first, second] = &mut self.halves;
        if groups.len() / GROUP_BYTES >= THREAD_MIN_GROUPS {
            std::thread::scope(|scope| {
                // A half the host will not start a thread for runs here.
                let refused =
                    crate::threads::scoped(scope, || second.absorb_groups(groups, LANES)).err();
                first.absorb_groups(groups, 0);
                if let Some(half) = refused {
                    half();
                }
            });
        } else {
            first.absorb_groups(groups, 0);
            second.absorb_groups(groups, LANES);
        }
    }

    fn finalize(self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM] {
        debug_assert!(tail.len() < GROUP_BYTES);
        let [first, second] = self.halves;
        let split = tail.len().min(LANES * BLOCK_BYTES);
        let a = first.finalize(&tail[..split], None);
        let b = second.finalize(&tail[split..], Some(LANES - 1));
        let mut out = [[0u8; OUT_BYTES]; PARALLELISM];
        out[..LANES].copy_from_slice(&a);
        out[LANES..].copy_from_slice(&b);
        out
    }
}

// ---- The in-place scalar leaf team: aarch64 production above 8 cores ----
//
// A BLAKE2sp leaf is a serial chain and there are eight of them, so eight
// workers is the whole of the tree's parallelism and the four-lane kernel
// above - two halves, two threads - can never use more than two cores.
// Where a box has a core per leaf, one leaf per core wins wall outright.
//
// Each worker reads its own 64-byte blocks IN PLACE at a stride of 512 and
// runs them through the scalar compression below. The alternative, kept in
// `portable.rs` as the independent cross-check, gathers a leaf's blocks
// into a scratch buffer first and hands the gathered run to a
// `blake2s_simd` state. Both were measured in ONE process on a 32-core
// arm64 desktop, 256 MiB, best of five, three runs agreeing within 2%
// (`blake2sp::tests::timing_matrix` prints this table):
//
//     feed        256K   1M    4M    16M   one-shot
//     NEON 2 thr  2.41  2.71  2.88  2.96  3.00
//     gathered 8  3.05  3.97  5.05  5.26  5.24
//     in place 8  3.16  4.28  5.71  6.24  6.43
//
// In place wins at every size - 13% at the 4 MiB batch a stored extract's
// digester produces, 23% at the ceiling - because the gather copies every
// byte of the stream once before any of it is compressed. It also needs no
// scratch at all, so a worker holds eight words of state and nothing else.
//
// The kernel is the design and the code of the extraction review of
// 18 Sep 2026 (with its own measurements on a different Apple part); it
// is carried here rather than rewritten.

#[inline(always)]
fn gs(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

macro_rules! round_s {
    ($v:ident, $m:ident, $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal,
     $s5:literal, $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal,
     $s11:literal, $s12:literal, $s13:literal, $s14:literal, $s15:literal) => {
        gs(&mut $v, 0, 4, 8, 12, $m[$s0], $m[$s1]);
        gs(&mut $v, 1, 5, 9, 13, $m[$s2], $m[$s3]);
        gs(&mut $v, 2, 6, 10, 14, $m[$s4], $m[$s5]);
        gs(&mut $v, 3, 7, 11, 15, $m[$s6], $m[$s7]);
        gs(&mut $v, 0, 5, 10, 15, $m[$s8], $m[$s9]);
        gs(&mut $v, 1, 6, 11, 12, $m[$s10], $m[$s11]);
        gs(&mut $v, 2, 7, 8, 13, $m[$s12], $m[$s13]);
        gs(&mut $v, 3, 4, 9, 14, $m[$s14], $m[$s15]);
    };
}

/// One non-final scalar BLAKE2s compression.
#[inline(always)]
fn compress_scalar(h: &mut [u32; 8], block: &[u8], t: u64) {
    let block: &[u8; BLOCK_BYTES] = block[..BLOCK_BYTES].try_into().unwrap();
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    // Built element by element, never by a slice copy: under a profile
    // that never saw this loop the two copies were left OUT OF LINE, a
    // call each a block (counted on 2 Oct 2026, an M-series chip: 5.3
    // percent more instructions on a stored member's read, in two draws
    // of two of one tree, where the plain build was level).
    let mut v = [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ t as u32,
        IV[5] ^ (t >> 32) as u32,
        IV[6],
        IV[7],
    ];
    round_s!(v, m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    round_s!(v, m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    round_s!(v, m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    round_s!(v, m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    round_s!(v, m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    round_s!(v, m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    round_s!(v, m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    round_s!(v, m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    round_s!(v, m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    round_s!(v, m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// One BLAKE2s round over TWO leaves, the steps of the one interleaved with
/// the steps of the other: the same sigma literals as [`round_s`], each
/// step applied to both states.
macro_rules! round_pair {
    ($v:ident, $w:ident, $m:ident, $n:ident, $s0:literal, $s1:literal, $s2:literal,
     $s3:literal, $s4:literal, $s5:literal, $s6:literal, $s7:literal, $s8:literal,
     $s9:literal, $s10:literal, $s11:literal, $s12:literal, $s13:literal, $s14:literal,
     $s15:literal) => {
        gs(&mut $v, 0, 4, 8, 12, $m[$s0], $m[$s1]);
        gs(&mut $w, 0, 4, 8, 12, $n[$s0], $n[$s1]);
        gs(&mut $v, 1, 5, 9, 13, $m[$s2], $m[$s3]);
        gs(&mut $w, 1, 5, 9, 13, $n[$s2], $n[$s3]);
        gs(&mut $v, 2, 6, 10, 14, $m[$s4], $m[$s5]);
        gs(&mut $w, 2, 6, 10, 14, $n[$s4], $n[$s5]);
        gs(&mut $v, 3, 7, 11, 15, $m[$s6], $m[$s7]);
        gs(&mut $w, 3, 7, 11, 15, $n[$s6], $n[$s7]);
        gs(&mut $v, 0, 5, 10, 15, $m[$s8], $m[$s9]);
        gs(&mut $w, 0, 5, 10, 15, $n[$s8], $n[$s9]);
        gs(&mut $v, 1, 6, 11, 12, $m[$s10], $m[$s11]);
        gs(&mut $w, 1, 6, 11, 12, $n[$s10], $n[$s11]);
        gs(&mut $v, 2, 7, 8, 13, $m[$s12], $m[$s13]);
        gs(&mut $w, 2, 7, 8, 13, $n[$s12], $n[$s13]);
        gs(&mut $v, 3, 4, 9, 14, $m[$s14], $m[$s15]);
        gs(&mut $w, 3, 4, 9, 14, $n[$s14], $n[$s15]);
    };
}

/// Sixteen little-endian message words of one block.
#[inline(always)]
fn message(block: &[u8]) -> [u32; 16] {
    let block: &[u8; BLOCK_BYTES] = block[..BLOCK_BYTES].try_into().unwrap();
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    m
}

/// The working vector of one non-final compression at counter `t`, built
/// element by element for the reason [`compress_scalar`] gives.
#[inline(always)]
fn working(h: &[u32; 8], t: u64) -> [u32; 16] {
    [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ t as u32,
        IV[5] ^ (t >> 32) as u32,
        IV[6],
        IV[7],
    ]
}

/// Two non-final scalar compressions at one counter, one block of each of
/// two leaves, in ONE instruction stream.
///
/// **Why two.** A leaf's compression is one dependent chain: each G is
/// twelve to fourteen single-cycle steps in a row, and a block is twenty
/// half-rounds of them, so one leaf alone leaves the core waiting on its
/// own chain (counted on an M5 Max, 16 Oct 2026: 4.44 cycles a byte at an
/// IPC of 4.6). Two leaves share nothing, so their chains overlap: 3.47
/// cycles a byte for the pair at an IPC of 6.8, 22 percent fewer cycles,
/// for 16 percent more instructions. The arithmetic per leaf is exactly
/// [`compress_scalar`]'s.
#[inline(always)]
fn compress_pair(h: &mut [u32; 8], g: &mut [u32; 8], a: &[u8], b: &[u8], t: u64) {
    let m = message(a);
    let n = message(b);
    let mut v = working(h, t);
    let mut w = working(g, t);
    round_pair!(v, w, m, n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    round_pair!(v, w, m, n, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    round_pair!(v, w, m, n, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    round_pair!(v, w, m, n, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    round_pair!(v, w, m, n, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    round_pair!(v, w, m, n, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    round_pair!(v, w, m, n, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    round_pair!(v, w, m, n, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    round_pair!(v, w, m, n, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    round_pair!(v, w, m, n, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
        g[i] ^= w[i] ^ w[i + 8];
    }
}

/// Leaves `leaf` and `leaf + 1` over a batch, their blocks compressed
/// side by side by [`compress_pair`]: what two calls of [`leaf_run`] give,
/// in one pass. A share of two leaves (a team of four) runs this.
///
/// The two leaves are at one counter throughout, because a whole group
/// gives every leaf one block, and their withheld blocks are side by side
/// in the batch's last group.
fn leaf_pair_run(
    h: &mut [u32; 8],
    g: &mut [u32; 8],
    pending: [Option<[u8; BLOCK_BYTES]>; 2],
    fed: u64,
    pieces: &[&[u8]],
    leaf: usize,
) -> [[u8; BLOCK_BYTES]; 2] {
    debug_assert!(leaf + 1 < PARALLELISM);
    let mut t = fed;
    match pending {
        [Some(a), Some(b)] => compress_pair(h, g, &a, &b, t),
        [a, b] => {
            if let Some(block) = a {
                compress_scalar(h, &block, t);
            }
            if let Some(block) = b {
                compress_scalar(g, &block, t);
            }
        }
    }
    let slot = leaf * BLOCK_BYTES;
    let last_piece = pieces.len() - 1;
    let mut withheld = [[0u8; BLOCK_BYTES]; 2];
    for (index, piece) in pieces.iter().enumerate() {
        let groups = piece.len() / GROUP_BYTES;
        let lead = if index == last_piece {
            groups - 1
        } else {
            groups
        };
        for group in piece.chunks_exact(GROUP_BYTES).take(lead) {
            t += BLOCK_BYTES as u64;
            let (a, b) = group[slot..slot + 2 * BLOCK_BYTES].split_at(BLOCK_BYTES);
            compress_pair(h, g, a, b, t);
        }
        if index == last_piece {
            let at = lead * GROUP_BYTES + slot;
            withheld[0].copy_from_slice(&piece[at..at + BLOCK_BYTES]);
            withheld[1].copy_from_slice(&piece[at + BLOCK_BYTES..at + 2 * BLOCK_BYTES]);
        }
    }
    withheld
}

/// One leaf over a batch: the withheld block, then every block of this leaf
/// but the batch's last, which comes back as the new withheld block.
fn leaf_run(
    h: &mut [u32; 8],
    pending: Option<[u8; BLOCK_BYTES]>,
    fed: u64,
    pieces: &[&[u8]],
    leaf: usize,
) -> [u8; BLOCK_BYTES] {
    let mut t = fed;
    if let Some(block) = pending {
        compress_scalar(h, &block, t);
    }
    let slot = leaf * BLOCK_BYTES;
    let last_piece = pieces.len() - 1;
    let mut withheld = [0u8; BLOCK_BYTES];
    for (index, piece) in pieces.iter().enumerate() {
        let groups = piece.len() / GROUP_BYTES;
        let lead = if index == last_piece {
            groups - 1
        } else {
            groups
        };
        for group in piece.chunks_exact(GROUP_BYTES).take(lead) {
            t += BLOCK_BYTES as u64;
            compress_scalar(h, &group[slot..slot + BLOCK_BYTES], t);
        }
        if index == last_piece {
            let at = lead * GROUP_BYTES + slot;
            withheld.copy_from_slice(&piece[at..at + BLOCK_BYTES]);
        }
    }
    withheld
}

impl ManyLeaves {
    /// Every piece is a non-empty whole number of groups. `threads` is 1
    /// (the NEON halves, both on this thread), 2 (the NEON halves, the
    /// second on another thread, and only for a batch that repays it), 4
    /// (scalar leaves, two a share in one stream: `leaf_pair_run`) or 8
    /// (scalar leaves, one a share). With a `pool`, the scalar shares go to
    /// workers that outlive the batch; without one, to a
    /// `std::thread::scope` of its own. With a `helper`, the second NEON
    /// half goes to a resident thread leased for the stream; without one,
    /// to one spawn per batch.
    pub(crate) fn absorb_pieces(
        &mut self,
        pieces: &[&[u8]],
        threads: usize,
        pool: Option<&LeafPool>,
        helper: Option<&Helper>,
    ) {
        if pieces.is_empty() {
            return;
        }
        if threads <= 2 {
            let [first, second] = &mut self.halves;
            // The same line `ManyLeaves::absorb_groups` draws, drawn again
            // here: one spawn is worth having over a batch and not over a
            // 256 KiB run, and a caller allowed ONE worker gets no spawn at
            // any size. The two halves are independent, so running them one
            // after the other on this thread is the same arithmetic.
            let groups: usize = pieces.iter().map(|p| p.len() / GROUP_BYTES).sum();
            if threads < 2 || groups < THREAD_MIN_GROUPS {
                for piece in pieces {
                    first.absorb_groups(piece, 0);
                }
                for piece in pieces {
                    second.absorb_groups(piece, LANES);
                }
                return;
            }
            if let Some(helper) = helper {
                // The second half on the stream's resident helper, the
                // first here, and back only when both are done: the same
                // arithmetic as the scope below without its thread start.
                let job = HalfJob {
                    pieces: pieces.as_ptr().cast(),
                    pieces_len: pieces.len(),
                    half: std::ptr::from_mut(second),
                };
                helper.dispatch(job, || {
                    for piece in pieces {
                        first.absorb_groups(piece, 0);
                    }
                });
                return;
            }
            std::thread::scope(|scope| {
                // A half the host will not start a thread for runs here.
                let refused = crate::threads::scoped(scope, || {
                    for piece in pieces {
                        second.absorb_groups(piece, LANES);
                    }
                })
                .err();
                for piece in pieces {
                    first.absorb_groups(piece, 0);
                }
                if let Some(half) = refused {
                    half();
                }
            });
            return;
        }
        let total: usize = pieces.iter().map(|p| p.len() / GROUP_BYTES).sum();
        let mut states = [[0u32; 8]; PARALLELISM];
        let mut pendings: [Option<[u8; BLOCK_BYTES]>; PARALLELISM] = [None; PARALLELISM];
        let mut withheld = [[0u8; BLOCK_BYTES]; PARALLELISM];
        for leaf in 0..PARALLELISM {
            let half = &self.halves[leaf / LANES];
            let lane = leaf % LANES;
            for (word, state) in states[leaf].iter_mut().enumerate() {
                *state =
                    u32::from_le_bytes(half.h[word][lane * 4..lane * 4 + 4].try_into().unwrap());
            }
            pendings[leaf] = half.pending.map(|p| p[lane]);
        }
        let fed = self.halves[0].fed;
        let per = PARALLELISM / threads;
        if let Some(pool) = pool {
            #[allow(unused_mut)]
            let mut job = Job {
                pieces: pieces.as_ptr().cast(),
                pieces_len: pieces.len(),
                states: states.as_mut_ptr(),
                withheld: withheld.as_mut_ptr(),
                pendings: pendings.as_ptr(),
                fed,
                per,
                shares: threads,
            };
            pool.dispatch(job, threads, || {});
        } else {
            Self::spawn_shares(
                pieces,
                threads,
                per,
                fed,
                &pendings,
                &mut states,
                &mut withheld,
            );
        }
        Self::rejoin(self, &states, &withheld, total);
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_shares(
        pieces: &[&[u8]],
        threads: usize,
        per: usize,
        fed: u64,
        pendings: &[Option<[u8; BLOCK_BYTES]>; PARALLELISM],
        states: &mut [[u32; 8]; PARALLELISM],
        withheld: &mut [[u8; BLOCK_BYTES]; PARALLELISM],
    ) {
        std::thread::scope(|scope| {
            let mut rest_s = &mut states[..];
            let mut rest_w = &mut withheld[..];
            for team in 0..threads {
                let (s, tail_s) = rest_s.split_at_mut(per);
                let (w, tail_w) = rest_w.split_at_mut(per);
                rest_s = tail_s;
                rest_w = tail_w;
                let pendings = &pendings;
                let mut work = move || {
                    if let ([h, g], [a, b]) = (&mut *s, &mut *w) {
                        let leaf = team * 2;
                        [*a, *b] = leaf_pair_run(
                            h,
                            g,
                            [pendings[leaf], pendings[leaf + 1]],
                            fed,
                            pieces,
                            leaf,
                        );
                        return;
                    }
                    for k in 0..per {
                        let leaf = team * per + k;
                        w[k] = leaf_run(&mut s[k], pendings[leaf], fed, pieces, leaf);
                    }
                };
                if team + 1 == threads {
                    work();
                } else if let Err(mut work) = crate::threads::scoped(scope, work) {
                    // A team the host will not start a thread for runs here.
                    work();
                }
            }
        });
    }

    /// Every leaf's state and withheld block, by value, for a lent batch.
    /// The same unpacking `absorb_pieces` does for its shares, written
    /// again rather than shared so that path's code is not touched.
    fn leaf_tasks(&self) -> [LeafTask; PARALLELISM] {
        std::array::from_fn(|leaf| {
            let half = &self.halves[leaf / LANES];
            let lane = leaf % LANES;
            LeafTask {
                state: std::array::from_fn(|word| {
                    u32::from_le_bytes(half.h[word][lane * 4..lane * 4 + 4].try_into().unwrap())
                }),
                pending: half.pending.map(|p| p[lane]),
                withheld: [0; BLOCK_BYTES],
            }
        })
    }

    /// [`Self::rejoin`] from a lent batch's returned tasks.
    fn rejoin_tasks(&mut self, tasks: &[LeafTask; PARALLELISM], groups: usize) {
        let states = tasks.map(|task| task.state);
        let withheld = tasks.map(|task| task.withheld);
        self.rejoin(&states, &withheld, groups);
    }

    /// Fold the per-leaf states and withheld blocks back into the lane
    /// vectors the NEON halves and `finalize` read.
    fn rejoin(
        &mut self,
        states: &[[u32; 8]; PARALLELISM],
        withheld: &[[u8; BLOCK_BYTES]; PARALLELISM],
        total: usize,
    ) {
        for leaf in 0..PARALLELISM {
            let half = &mut self.halves[leaf / LANES];
            let lane = leaf % LANES;
            for (word, state) in states[leaf].iter().enumerate() {
                half.h[word][lane * 4..lane * 4 + 4].copy_from_slice(&state.to_le_bytes());
            }
            let mut pending = half.pending.unwrap_or([[0u8; BLOCK_BYTES]; LANES]);
            pending[lane] = withheld[leaf];
            half.pending = Some(pending);
        }
        for half in &mut self.halves {
            half.fed += (total * BLOCK_BYTES) as u64;
        }
    }
}

/// `ManyLeaves` driven through [`ManyLeaves::absorb_pieces`] at up to
/// `THREADS` workers, as a `LeafSet`. A width of 8 puts one leaf on each
/// worker's in-place scalar run and a width of 4 two, compressed side by
/// side in one stream (`leaf_pair_run`); 2 or fewer falls back to
/// the NEON halves, with at most one spawn per BATCH rather than per
/// piece.
///
/// `THREADS` is the ceiling. [`Self::absorb_groups_at`] takes the
/// allowance the caller actually has for this call and rounds it down to
/// a width that divides the eight leaves; the `LeafSet` methods, which
/// carry no allowance, take the ceiling.
pub(crate) struct ScalarLeafTeam<const THREADS: usize, const POOLED: bool> {
    leaves: ManyLeaves,
    /// Leased once the BYTES SO FAR are worth a team, not on `new`: a
    /// hasher over a member too small to reach one never pays for a
    /// thread. Leased from [`PARKED_TEAMS`] and given back when the team
    /// is dropped, so a stream of many members, or many one-shot hashes,
    /// starts no thread in the steady state.
    pool: Option<TeamLease>,
    /// The resident thread a team of TWO hands its second NEON half to,
    /// leased from [`PARKED`] on the same bytes-so-far rule as `pool` and
    /// given back when the team is dropped.
    helper: Option<Helper>,
    /// Whole groups absorbed so far, which is what earns the pool.
    absorbed: usize,
    /// The resident team a LENT batch goes to (see [`Self::lend`]): one
    /// worker per share, the calling thread taking none, so the caller is
    /// free to gather the next batch while this one is hashed. Earned on
    /// the same bytes-so-far rule as `pool`.
    pipe: Option<PipeLease>,
    /// Whole groups of the lent batch in flight, if one is.
    flight: Option<usize>,
    /// The last lent stage, back from the pipe and not yet collected by
    /// [`Self::settle`].
    back: Option<Lent>,
    /// The resident team RELAYED feeds go to (see [`Self::relay`]): one
    /// worker per share, each running its leaves from one feed straight
    /// on into the next. Leased on a stream's first relayed feed.
    relay: Option<RelayLease>,
}

/// The team width an allowance of `workers` buys: the largest of 1, 2, 4
/// and 8 that it covers.
///
/// Eight shares of one leaf, four of two, two of four. A width that did
/// not divide [`PARALLELISM`] would leave a share short or a leaf
/// unclaimed, so the allowance is rounded DOWN to one that does rather
/// than refused.
fn team_width(workers: usize) -> usize {
    match workers {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=7 => 4,
        _ => PARALLELISM,
    }
}

/// A clone starts with no team of its own. The hasher holding this is
/// cloned per member, and a clone that shared a team would either
/// serialise two members onto it or outlive the original.
///
/// A batch lent to the pipe and still in flight is waited for and its
/// leaves copied into the clone; the original lands it for itself later.
impl<const THREADS: usize, const POOLED: bool> Clone for ScalarLeafTeam<THREADS, POOLED> {
    fn clone(&self) -> Self {
        Self {
            leaves: self.landed_copy(),
            pool: None,
            helper: None,
            // The clone re-earns its team on its own bytes, for the same
            // reason it does not inherit one: what the original has
            // absorbed says nothing about what this one will be fed.
            absorbed: 0,
            pipe: None,
            flight: None,
            back: None,
            relay: None,
        }
    }
}

impl<const THREADS: usize, const POOLED: bool> ScalarLeafTeam<THREADS, POOLED> {
    /// [`LeafSet::absorb_groups`] at an explicit worker allowance.
    pub(crate) fn absorb_groups_at(&mut self, groups: &[u8], workers: usize) {
        if groups.len() < GROUP_BYTES {
            return;
        }
        self.run(&[groups], workers);
    }

    /// [`LeafSet::absorb_group_pieces`] at an explicit worker allowance, in
    /// ONE dispatch.
    ///
    /// The pieces are hashed as if they were concatenated, and the width is
    /// decided by their TOTAL. That is the whole point of the entry point:
    /// a short run that has to precede the rest in stream order rides into
    /// the batch it precedes instead of being handed over beneath it, so no
    /// batch under the team's worthwhile size ever reaches the team.
    ///
    /// Every piece must be a non-empty whole number of groups. Unlike
    /// [`LeafSet::absorb_group_pieces`] this does NOT filter short pieces,
    /// because it is on the streaming hasher's hot path and that filter is
    /// a `Vec`: an allocation per call is exactly what
    /// `small_updates_add_no_heap_once_the_kernel_is_chosen` forbids.
    ///
    /// Reached from the seam's aarch64 `Team` arm only, and this module is
    /// compiled on every target, so off aarch64 it has no caller at all -
    /// the same arrangement `LeafSet::absorb_group_pieces` is in, and
    /// annotated for the same reason.
    #[allow(dead_code)]
    pub(crate) fn absorb_pieces_at(&mut self, pieces: &[&[u8]], workers: usize) {
        debug_assert!(
            pieces
                .iter()
                .all(|piece| piece.len() >= GROUP_BYTES && piece.len().is_multiple_of(GROUP_BYTES)),
            "every piece is a non-empty whole number of groups"
        );
        if pieces.is_empty() {
            return;
        }
        self.run(pieces, workers);
    }

    fn run(&mut self, pieces: &[&[u8]], workers: usize) {
        // A lent batch precedes this one in stream order.
        self.land();
        let threads = team_width(workers).min(THREADS);
        let groups: usize = pieces.iter().map(|piece| piece.len() / GROUP_BYTES).sum();
        self.absorbed = self.absorbed.saturating_add(groups);
        // A team is earned by the BYTES SO FAR, not by one batch. What the
        // per-batch test bought - a member finishing with one leftover
        // group never starting seven threads to hash 512 bytes - the
        // running total buys just as well, and it does not turn a caller
        // who drips 256 KiB runs into a caller who pays seven
        // `pthread_create`s on every one of them. Once built the pool
        // takes every batch, large or small: the threads are already
        // there, and waking them is a condvar rather than a syscall.
        if POOLED && threads > 2 && self.pool.is_none() && self.absorbed >= THREAD_MIN_GROUPS {
            // One share stays on this thread, so the team is one short.
            self.pool = Some(TeamLease::lease(threads - 1));
        }
        // A team of two earns its helper the same way. The helper is
        // leased rather than built, because a stream is often one member
        // and eight members at once would otherwise start and join eight
        // threads a round; a parked one is a condvar away.
        if POOLED
            && threads == 2
            && self.helper.is_none()
            && self.absorbed >= THREAD_MIN_GROUPS
            && !resident_is_off()
        {
            self.helper = Helper::lease();
        }
        // Before the pool exists there is no cheap way to hand a share to
        // another thread, so the work stays on this one rather than
        // opening a scope for it. This is the whole of the first 512 KiB.
        let threads = if POOLED && self.pool.is_none() {
            threads.min(2)
        } else {
            threads
        };
        self.leaves.absorb_pieces(
            pieces,
            threads,
            self.pool.as_ref().map(TeamLease::pool),
            self.helper.as_ref(),
        );
    }

    /// Hand the pipe the first `len` bytes of `stage`, whole groups none of
    /// which is any leaf's last, and return AT ONCE: the batch is hashed
    /// by one worker per share while the caller does something else, and
    /// is landed by the next call that needs the leaves ([`Self::land`]).
    ///
    /// The stage is OWNED for the flight, shared with the workers through
    /// its `Arc`, and every leaf's state goes to its worker by value and
    /// comes back by value, so no pointer outlives any frame and nothing
    /// here is `unsafe`. `Err` hands the stage straight back, untouched,
    /// when this team cannot take a lent batch: a width of two or less, a
    /// stream that has not earned a team yet, or a pipe whose threads
    /// could not all be started. The caller then absorbs it in place.
    pub(crate) fn lend(&mut self, stage: Lent, len: usize, workers: usize) -> Result<(), Lent> {
        self.land();
        let threads = team_width(workers).min(THREADS);
        let groups = len / GROUP_BYTES;
        debug_assert!(len.is_multiple_of(GROUP_BYTES) && len <= stage.len());
        if !self.will_lend(len, workers) {
            return Err(stage);
        }
        if self.pipe.is_none() {
            self.pipe = PipeLease::lease(threads);
        }
        let Some(pipe) = self.pipe.as_ref().filter(|pipe| pipe.shares == threads) else {
            return Err(stage);
        };
        self.absorbed = self.absorbed.saturating_add(groups);
        let fed = self.leaves.halves[0].fed;
        pipe.start(stage, len, fed, self.leaves.leaf_tasks());
        self.flight = Some(groups);
        Ok(())
    }

    /// Hand the relay one feed, OWNED (`stage`, whose first `len` bytes are
    /// whole groups none of which is any leaf's last), and return once it
    /// is queued: each share's worker runs its leaves on from the feed
    /// before into this one without waiting for the other shares, and the
    /// leaves come back only where something needs them ([`Self::land`]).
    /// This thread waits only while [`RELAY_DEPTH`] feeds are queued.
    ///
    /// **Why.** Hashed in place, every feed of a stored member was a
    /// dispatch to the pool and a JOIN: the feeding thread waited for the
    /// slowest share of each feed, and the shares waited for each other.
    /// Counted on an M5 Max, 16 Oct 2026, `x` of one stored 4 GiB member at
    /// the default width: 2,048 feeds of 2 MiB, each joined, the join
    /// about a quarter of the hash's span. Relayed, a share's own total is
    /// the bound, not the sum of each feed's slowest share.
    ///
    /// Safe by the pipe's construction: a worker reads the feed only
    /// through its `Arc` and owns its leaves' state by value, and the
    /// stage is unshared again once every share is past it. `Err` hands
    /// the stage back untouched where this team takes no relayed feed (a
    /// width of two or less, or a relay whose threads could not all be
    /// started); the caller then absorbs it in place.
    pub(crate) fn relay(&mut self, stage: Lent, len: usize, workers: usize) -> Result<(), Lent> {
        let threads = team_width(workers).min(THREADS);
        if !self.will_relay(workers) || len < GROUP_BYTES {
            return Err(stage);
        }
        debug_assert!(len.is_multiple_of(GROUP_BYTES) && len <= stage.len());
        // A lent flight precedes this feed in stream order.
        if self.flight.is_some() {
            let relay = self.relay.take();
            self.land();
            self.relay = relay;
        }
        if self
            .relay
            .as_ref()
            .is_some_and(|relay| relay.shares != threads)
        {
            self.land();
            self.relay = None;
        }
        if self.relay.is_none() {
            self.relay = RelayLease::lease(threads);
        }
        let Some(relay) = self.relay.as_mut() else {
            return Err(stage);
        };
        self.absorbed = self.absorbed.saturating_add(len / GROUP_BYTES);
        relay.submit(&self.leaves, stage, len);
        Ok(())
    }

    /// Whether [`Self::relay`] takes a feed at an allowance of `workers`:
    /// a team of more than two, as [`Self::lend`] asks.
    pub(crate) fn will_relay(&self, workers: usize) -> bool {
        POOLED && team_width(workers).min(THREADS) > 2
    }

    /// Whether [`Self::lend`] takes a batch of `len` bytes at an allowance
    /// of `workers`: a width above two, a whole group at least, and a
    /// stream that has earned a team by the bytes so far, the same rule
    /// that earns `pool`.
    pub(crate) fn will_lend(&self, len: usize, workers: usize) -> bool {
        let threads = team_width(workers).min(THREADS);
        POOLED
            && threads > 2
            && len >= GROUP_BYTES
            && self.absorbed.saturating_add(len / GROUP_BYTES) >= THREAD_MIN_GROUPS
    }

    /// Wait for the lent batch in flight, if there is one, and fold its
    /// leaves back. Its stage is kept for [`Self::settle`].
    fn land(&mut self) {
        // A relayed run and a lent flight are never out together: each
        // lands the other before it starts.
        if let Some(relay) = self.relay.as_mut() {
            relay.land(&mut self.leaves);
        }
        let Some(groups) = self.flight.take() else {
            return;
        };
        let pipe = self.pipe.as_ref().expect("a flight has a pipe");
        let (tasks, stage) = pipe.finish();
        self.leaves.rejoin_tasks(&tasks, groups);
        self.back = Some(stage);
    }

    /// Land any lent batch and give its stage back, unshared, for the
    /// caller to gather into again.
    pub(crate) fn settle(&mut self) -> Option<Lent> {
        self.land();
        self.back.take()
    }

    /// The leaves with any lent batch in flight folded in, for a clone:
    /// waited for through `&self`, and copied rather than taken, so the
    /// original still lands the batch for itself.
    fn landed_copy(&self) -> ManyLeaves {
        let mut leaves = self.leaves.clone();
        if let (Some(groups), Some(pipe)) = (self.flight, self.pipe.as_ref()) {
            leaves.rejoin_tasks(&pipe.wait_tasks(), groups);
        }
        if let Some((tasks, groups)) = self.relay.as_ref().and_then(|relay| relay.wait_tasks()) {
            leaves.rejoin_tasks(&tasks, groups);
        }
        leaves
    }
}

impl<const THREADS: usize, const POOLED: bool> LeafSet for ScalarLeafTeam<THREADS, POOLED> {
    fn new() -> Self {
        Self {
            leaves: ManyLeaves::new(),
            pool: None,
            helper: None,
            absorbed: 0,
            pipe: None,
            flight: None,
            back: None,
            relay: None,
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        // `leaf_run` takes the batch's last group apart, so a piece that
        // carries no whole group would underflow its `groups - 1`.
        self.absorb_groups_at(groups, THREADS);
    }

    fn absorb_group_pieces(&mut self, pieces: &[&[u8]]) {
        let pieces: Vec<&[u8]> = pieces
            .iter()
            .copied()
            .filter(|piece| piece.len() >= GROUP_BYTES)
            .collect();
        if pieces.is_empty() {
            return;
        }
        self.run(&pieces, THREADS);
    }

    fn finalize(mut self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM] {
        self.land();
        self.leaves.finalize(tail)
    }
}

// ---- The persistent leaf team ----
//
// `absorb_pieces` above would otherwise open a `std::thread::scope` per
// BATCH, so a member hashed in 4 MiB batches would pay seven
// `pthread_create`s every 4 MiB, and the in-place team's throughput
// would climb with the batch size purely because that cost amortises.
// Workers that live as long as the
// hasher and take a batch over a condvar remove it. Measured on a
// 32-core arm64 desktop, 256 MiB, best of five, three runs agreeing
// within 2% (`blake2sp::tests::timing_matrix` prints this table):
//
//     feed        256K   1M    4M    16M   one-shot
//     NEON 2 thr  2.41  2.70  2.85  2.89  2.92
//     gathered 8  3.20  3.99  5.04  5.26  5.24
//     in place 8  3.26  4.57  5.74  6.22  6.43
//     one team    4.45  5.46  6.13  6.31  6.41
//
// The win is largest where the batches are smallest - 36% at 256 KiB,
// 20% at 1 MiB - and 7% at the 4 MiB a stored extract's digester
// produces. It is nil fed the whole 256 MiB in one call, which is the
// control: one dispatch has one scope either way. End to end on a 2 GiB
// stored member with a BLAKE2sp record, `rarfast t`, both arms in one
// binary and the reps interleaved: 0.36 s against 0.39 s, and LESS CPU
// (0.25 s system against 0.31 s), the spawns being syscalls.
//
// TWO CHEAPER THINGS WERE MEASURED FIRST AND NEITHER PAID, so do not
// re-derive them (same box, same rig, arms interleaved in one binary):
//
// - A 64 KiB worker stack instead of the default 2 MiB: 5.78 against
//   5.78 at 4 MiB. The cost is the thread creation, not the mapping.
// - Reading each message word out of the block at the point of use
//   rather than unpacking all sixteen up front - sixteen state words
//   plus sixteen message words being one live value more than aarch64
//   has registers: 5.77 against 5.78. The chain is latency bound rather
//   than register bound, and LLVM was already scheduling those loads.
//   Hoisting the leaf state into a local across the block loop, in case
//   the `&mut` aliased the input, was measurably WORSE (5.98): it was
//   already being promoted.
//
// ON THE `unsafe`: this module's header argues its first site, the NEON
// entry. This is the second, and it is a different argument. A worker
// that outlives one batch cannot borrow that batch: `std::thread::scope`
// exists precisely to lend a borrow to a thread, and it can only do so
// by ending the thread at the end of the borrow, which is the cost being
// removed here. So the batch reaches the workers as raw pointers, and
// what makes them sound is the same property `scope` enforces by
// construction and this code enforces by blocking: `dispatch` does not
// return until every share it handed out has signalled completion, so no
// pointer here outlives the frame it addresses. The two ways that could
// break are a worker panicking (it would never signal) and a panic in
// the dispatching thread's own share (it would unwind past the wait) - both are
// caught, counted, and re-raised only once the team is idle. All three
// properties have tests, and every one of them runs the body on a thread
// under a deadline rather than joining it, because the failure being
// guarded against is a hang and a join would simply hang with it.

use std::sync::{Arc, Condvar, Mutex};

/// What a resident worker can be handed: one share of one batch, as
/// pointers into the dispatching frame. [`Job`] is the scalar team's
/// batch, cut into leaf shares; [`HalfJob`] is the NEON halves' second
/// half, one share.
trait Batch: Copy + Send + 'static {
    /// Shares this batch was cut into. A worker whose index is past this
    /// has nothing to do.
    fn shares(&self) -> usize;

    /// Run share `share`.
    ///
    /// # Safety
    ///
    /// The batch's pointers must be valid for the call, `share` must be
    /// less than [`Self::shares`], and no other live call may name the
    /// same `share`.
    unsafe fn run(&self, share: usize);
}

/// One batch, as the pointers a worker needs to find its own leaves in
/// it. Every field addresses a local of the dispatching frame.
#[derive(Clone, Copy)]
struct Job {
    pieces: *const &'static [u8],
    pieces_len: usize,
    states: *mut [u32; 8],
    withheld: *mut [u8; BLOCK_BYTES],
    pendings: *const Option<[u8; BLOCK_BYTES]>,
    fed: u64,
    /// Leaves per worker share.
    per: usize,
    /// Shares this batch was cut into. `dispatch` wakes every worker,
    /// not only the ones it needs, so a worker whose index is past this
    /// has nothing to do - and must NOT guess, because share `s` writes
    /// `states[s * per ..]` and a share past the end writes past the
    /// array. While `per` was always 1 that could not happen; it can as
    /// soon as a caller's allowance cuts the eight leaves any other way.
    shares: usize,
}

// SAFETY: a `Job` is only ever read inside `run_share`, which runs
// between `dispatch` publishing it and `dispatch` observing every
// worker's completion - so the dispatching frame, which owns every
// target, is alive throughout. Share `s` touches `states[s * per ..]`
// and `withheld[s * per ..]` and no other share's, so the two `*mut`
// arrays are partitioned rather than aliased; `pieces` and `pendings`
// are read-only for the whole dispatch.
#[allow(unsafe_code)]
unsafe impl Send for Job {}

#[allow(unsafe_code)]
impl Batch for Job {
    fn shares(&self) -> usize {
        self.shares
    }

    unsafe fn run(&self, share: usize) {
        // SAFETY: the trait's contract is `run_share`'s.
        unsafe { run_share(self, share) }
    }
}

/// The second NEON half of one batch: the half's state and the pieces it
/// absorbs, both in the dispatching frame. One share.
#[derive(Clone, Copy)]
struct HalfJob {
    pieces: *const &'static [u8],
    pieces_len: usize,
    half: *mut Half,
}

// SAFETY: a `HalfJob` is only read inside `Batch::run`, between
// `Helper::dispatch` publishing it and observing its completion, so the
// frame that owns the half and the pieces is alive throughout. The half
// it points to is the SECOND of the two; the dispatching thread touches
// only the first while the job runs, so the `*mut` is not aliased, and
// the pieces are read-only for the whole dispatch.
#[allow(unsafe_code)]
unsafe impl Send for HalfJob {}

#[allow(unsafe_code)]
impl Batch for HalfJob {
    fn shares(&self) -> usize {
        1
    }

    unsafe fn run(&self, share: usize) {
        debug_assert_eq!(share, 0);
        // SAFETY: the caller guarantees the pointers for the call; the
        // `unsafe impl Send` above is why nothing else touches the half.
        unsafe {
            let pieces = std::slice::from_raw_parts(self.pieces, self.pieces_len);
            let half = &mut *self.half;
            for piece in pieces {
                half.absorb_groups(piece, LANES);
            }
        }
    }
}

/// Run share `share` of `job`: its `per` leaves, in place.
///
/// # Safety
///
/// `job`'s pointers must be valid for the call, `share` must be less
/// than `job.shares`, and no other live call may name the same `share`.
#[allow(unsafe_code)]
unsafe fn run_share(job: &Job, share: usize) {
    debug_assert!(share < job.shares);
    // SAFETY: the caller guarantees the pointers; the partitioning is the
    // `unsafe impl Send` argument above.
    unsafe {
        let pieces = std::slice::from_raw_parts(job.pieces, job.pieces_len);
        if job.per == 2 {
            // A share of two leaves: both in one stream (`leaf_pair_run`).
            // Two references into `states`, one per leaf of this share.
            let leaf = share * 2;
            let [a, b] = leaf_pair_run(
                &mut *job.states.add(leaf),
                &mut *job.states.add(leaf + 1),
                [*job.pendings.add(leaf), *job.pendings.add(leaf + 1)],
                job.fed,
                pieces,
                leaf,
            );
            *job.withheld.add(leaf) = a;
            *job.withheld.add(leaf + 1) = b;
            return;
        }
        for k in 0..job.per {
            let leaf = share * job.per + k;
            *job.withheld.add(leaf) = leaf_run(
                &mut *job.states.add(leaf),
                *job.pendings.add(leaf),
                job.fed,
                pieces,
                leaf,
            );
        }
    }
}

struct Slot<J> {
    /// Bumped once per batch; a worker takes work when this passes the
    /// generation it last ran, which is what makes a missed notify
    /// harmless rather than a hang.
    generation: u64,
    shutdown: bool,
    outstanding: usize,
    job: Option<J>,
    panicked: bool,
}

struct Shared<J> {
    slot: Mutex<Slot<J>>,
    /// Workers wait here for a new generation.
    ready: Condvar,
    /// The dispatching thread waits here for `outstanding` to reach zero.
    idle: Condvar,
}

/// Workers that outlive a batch. The scalar team's is leased on a
/// hasher's first wide batch and parked again when it is dropped (joined
/// past [`parked_team_cap`]), so a hasher abandoned mid-stream (an
/// extraction that stops early) leaves at most a parked pool behind, never
/// a pool bound to it. A [`Helper`]'s is one worker, parked between
/// streams.
pub(crate) struct LeafPool<J: Batch = Job> {
    shared: Arc<Shared<J>>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

/// A leaf worker holds eight state words, a block and a message array,
/// and what the build makes of the leaf runs' frames: at opt-level 0 with
/// cargo's own full debuginfo (the public tree's plain `cargo test`) the
/// pipe's worker needs between 64 and 80 KiB on Apple aarch64, where 64
/// KiB aborted the test binary (20 Oct 2026); at the shipped profile far
/// less. So 256 KiB: over three times the most it was measured to use, in
/// every profile (`the_leaf_workers_stack_holds_twice_their_use`). It is a
/// reservation of address space, not memory: only the pages a worker
/// touches are ever made, and a handful of workers reserve under 3 MiB
/// against the 64 MiB arena each thread may map on glibc Linux
/// (`crate::threads`).
const LEAF_STACK: usize = 256 << 10;

fn lock<J>(shared: &Shared<J>) -> std::sync::MutexGuard<'_, Slot<J>> {
    // A worker only panics inside `catch_unwind`, so the lock is never
    // held by a panicking frame; take the inner guard rather than adding
    // a failure mode that cannot happen.
    shared.slot.lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(unsafe_code)]
fn worker_loop<J: Batch>(shared: &Shared<J>, share: usize) {
    let mut seen = 0u64;
    loop {
        let job = {
            let mut slot = lock(shared);
            loop {
                if slot.shutdown {
                    return;
                }
                if slot.generation != seen {
                    seen = slot.generation;
                    break slot.job;
                }
                slot = shared.ready.wait(slot).unwrap_or_else(|e| e.into_inner());
            }
        };
        // A worker this batch did not need. It still has to count itself
        // out of nothing and go back to waiting, which is what falling
        // through to the next generation does.
        let job = job.filter(|job| share < job.shares());
        if let Some(job) = job {
            // SAFETY: `dispatch` published these pointers and is blocked
            // on `idle` until this share signals below, so the frame they
            // address is alive for the whole call. `share` is this
            // worker's alone.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                job.run(share)
            }));
            let mut slot = lock(shared);
            slot.panicked |= outcome.is_err();
            slot.outstanding -= 1;
            if slot.outstanding == 0 {
                shared.idle.notify_all();
            }
        }
    }
}

impl<J: Batch> LeafPool<J> {
    /// `workers` threads, each taking one share. Spawning fewer than
    /// asked is not an error: [`Self::dispatch`] runs whatever shares
    /// have no worker on the dispatching thread.
    fn new(workers: usize) -> Self {
        let shared = Arc::new(Shared {
            slot: Mutex::new(Slot {
                generation: 0,
                shutdown: false,
                outstanding: 0,
                job: None,
                panicked: false,
            }),
            ready: Condvar::new(),
            idle: Condvar::new(),
        });
        let mut handles = Vec::with_capacity(workers);
        for share in 0..workers {
            let mine = Arc::clone(&shared);
            let spawned = std::thread::Builder::new()
                .name("blake2sp-leaf".to_owned())
                .stack_size(LEAF_STACK)
                .spawn(move || worker_loop(&mine, share));
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(_) => break,
            }
        }
        Self {
            shared,
            workers: handles,
        }
    }

    /// Run all `shares` of `job`, and `local` on this thread beside them,
    /// returning once every one of them is complete.
    #[allow(unsafe_code)]
    fn dispatch(&self, job: J, shares: usize, local: impl FnOnce()) {
        let woken = self.workers.len().min(shares);
        if woken > 0 {
            let mut slot = lock(&self.shared);
            slot.job = Some(job);
            slot.outstanding = woken;
            slot.generation = slot.generation.wrapping_add(1);
            drop(slot);
            self.shared.ready.notify_all();
        }
        // This thread's own work, then the shares no worker took. Both
        // caught rather than propagated: an unwind from here would leave
        // the frame `job` points into while the workers are still
        // reading it.
        let mut panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(local)).is_err();
        for share in woken..shares {
            // SAFETY: as in `worker_loop`, and this thread owns the frame.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                job.run(share)
            }));
            panicked |= outcome.is_err();
        }
        if woken > 0 {
            let mut slot = lock(&self.shared);
            while slot.outstanding != 0 {
                slot = self
                    .shared
                    .idle
                    .wait(slot)
                    .unwrap_or_else(|e| e.into_inner());
            }
            panicked |= slot.panicked;
            slot.panicked = false;
            slot.job = None;
        }
        assert!(!panicked, "a BLAKE2sp leaf worker panicked");
    }
}

impl<J: Batch> Drop for LeafPool<J> {
    fn drop(&mut self) {
        {
            let mut slot = lock(&self.shared);
            slot.shutdown = true;
        }
        self.shared.ready.notify_all();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

// ---- The resident helper for a team of two ----
//
// A team of two runs the NEON kernel's two halves on two threads, and
// until this helper the second thread was a `std::thread::scope` spawn per
// batch of at least `THREAD_MIN_GROUPS`: about 32 for a 16 MiB member, on
// the member's own thread. That is the arrangement every stream beside
// another takes (`checksum::blake2sp`'s census), so eight members decoded
// at once paid it eight times over. The helper is a one-worker
// `LeafPool` that outlives the stream: leased when a stream has earned it,
// on the same bytes-so-far rule the scalar team's pool uses, handed a
// batch over a condvar, and parked again when the stream is dropped, so a
// stream of many members starts no thread in the steady state.
//
// The `unsafe` is the persistent leaf team's own, argued there: the batch
// reaches the worker as pointers, and `dispatch` does not return until the
// worker has signalled, so no pointer outlives the frame it addresses.
// Spec L's erratum of 18 Sep 2026, which names this module, is the
// permission for it; no other module gains any.

/// Parked helpers, as many as streams have ever needed at once, up to
/// [`parked_cap`]. A helper past the cap is joined when its stream ends
/// rather than kept.
static PARKED: Mutex<Vec<LeafPool<HalfJob>>> = Mutex::new(Vec::new());

/// [`PARKED`], or on the thread of a test that scoped its own parked sets
/// (`scoped::Scope`), that test's.
fn parked() -> &'static Mutex<Vec<LeafPool<HalfJob>>> {
    #[cfg(test)]
    if let Some(set) = scoped::HELPERS.with(std::cell::Cell::get) {
        return set;
    }
    &PARKED
}

/// The most helpers kept parked: one per core, which is more streams at a
/// team of two than a box can run at once. Read once.
fn parked_cap() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

/// A stream's lease on one parked helper, given back when dropped.
pub(crate) struct Helper(Option<LeafPool<HalfJob>>);

impl Helper {
    /// A parked helper, or a new one if none is parked. `None` only if
    /// the thread cannot be started, in which case the caller keeps its
    /// spawn per batch.
    fn lease() -> Option<Helper> {
        let parked = parked().lock().unwrap_or_else(|e| e.into_inner()).pop();
        let pool = parked.unwrap_or_else(|| LeafPool::new(1));
        if pool.workers.is_empty() {
            return None;
        }
        Some(Helper(Some(pool)))
    }

    /// Run `job` on the helper and `local` here, returning once both are
    /// done.
    fn dispatch(&self, job: HalfJob, local: impl FnOnce()) {
        self.0
            .as_ref()
            .expect("a lease holds its helper until dropped")
            .dispatch(job, 1, local);
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let Some(pool) = self.0.take() else {
            return;
        };
        let mut parked = parked().lock().unwrap_or_else(|e| e.into_inner());
        let spare = if parked.len() < parked_cap() {
            parked.push(pool);
            None
        } else {
            Some(pool)
        };
        // Joined, if at all, with the lock released.
        drop(parked);
        drop(spare);
    }
}

// ---- The parked team of eight ----
//
// The scalar team's pool used to be BUILT when a stream earned it and
// JOINED when the stream ended: seven `pthread_create`s and seven joins per
// member on the read path, which holds one hasher and resets it per member,
// and per call on the one-shot path. The helper above already parks the
// team of two's one thread between streams; this is the same arrangement
// for the wider teams. A pool is leased by its exact worker count (seven at
// a width of eight, three at four), built only when none of that count is
// parked, and parked again when its team is dropped, up to
// [`parked_team_cap`]; past the cap it is joined as before.
//
// No `unsafe` is added: a lease moves a `LeafPool` between owners and the
// pool's own argument is unchanged, because `LeafPool::dispatch` still
// returns only once every share has signalled and clears `slot.job` before
// it does. A parked pool therefore holds no pointer into any frame, and no
// leaf state or input: its workers wait on the condvar with eight words of
// stack each, which is what a live stream's team already held.

/// Parked pools of the scalar team, each with the worker count it was built
/// at, up to [`parked_team_cap`].
static PARKED_TEAMS: Mutex<Vec<(usize, LeafPool)>> = Mutex::new(Vec::new());

/// [`PARKED_TEAMS`], or a scoping test's own, as [`parked`] is.
fn parked_teams() -> &'static Mutex<Vec<(usize, LeafPool)>> {
    #[cfg(test)]
    if let Some(set) = scoped::TEAMS.with(std::cell::Cell::get) {
        return set;
    }
    &PARKED_TEAMS
}

/// The most teams kept parked: one per eight cores, and at least one. A
/// team of eight wants a core per leaf, so a box runs about that many at
/// once and no more are worth keeping warm. Read once.
fn parked_team_cap() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::thread::available_parallelism().map_or(1, |n| (n.get() / PARALLELISM).max(1))
    })
}

/// A team's lease on one pool of `workers` resident threads, given back to
/// [`PARKED_TEAMS`] when dropped.
pub(crate) struct TeamLease {
    workers: usize,
    pool: Option<LeafPool>,
}

impl TeamLease {
    /// A parked pool of exactly `workers` threads, or a new one if none is
    /// parked.
    fn lease(workers: usize) -> TeamLease {
        let parked = {
            let mut parked = parked_teams().lock().unwrap_or_else(|e| e.into_inner());
            parked
                .iter()
                .rposition(|(count, _)| *count == workers)
                .map(|at| parked.swap_remove(at).1)
        };
        TeamLease {
            workers,
            pool: Some(parked.unwrap_or_else(|| LeafPool::new(workers))),
        }
    }

    fn pool(&self) -> &LeafPool {
        self.pool
            .as_ref()
            .expect("a lease holds its pool until dropped")
    }
}

impl Drop for TeamLease {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        let mut parked = parked_teams().lock().unwrap_or_else(|e| e.into_inner());
        let spare = if parked.len() < parked_team_cap() {
            parked.push((self.workers, pool));
            None
        } else {
            Some(pool)
        };
        // Joined, if at all, with the lock released.
        drop(parked);
        drop(spare);
    }
}

// ---- The pipe: a lent batch, hashed while the caller gathers the next ----
//
// A streaming caller that feeds the hasher runs under its in-place
// threshold has every byte gathered into the hasher's stage, and each full
// stage used to be handed to the team and WAITED for: the calling thread
// gathered, then hashed its own leaf share while seven workers hashed
// theirs, then joined them, then gathered again with all seven idle. The
// profile of 26 Sep 2026 put that serial stage at
// 12 to 37 percent of the chunked rows' wall. The pipe takes a full stage
// OWNED, as an `Arc` of the buffer, and hashes it on one worker per share
// with the calling thread taking none, so the caller gathers the next
// stage while this one is hashed, and waits only when it needs the leaves
// or the buffer back.
//
// SAFE by construction, unlike the pool above: nothing a worker reads is
// borrowed. The stage is shared through its `Arc` and each worker drops
// its clone before it reports; every leaf's state, withheld block and
// counter go to the worker by value in the slot and come back by value.
// So `Arc::get_mut` on the stage succeeds once the flight is landed, and
// a pipe dropped mid-flight joins workers that own everything they touch.

/// One leaf's part of a lent batch, carried by value both ways.
#[derive(Clone, Copy)]
struct LeafTask {
    state: [u32; 8],
    pending: Option<[u8; BLOCK_BYTES]>,
    withheld: [u8; BLOCK_BYTES],
}

struct PipeSlot {
    /// Bumped once per batch, as the pool's is.
    generation: u64,
    shutdown: bool,
    outstanding: usize,
    stage: Option<Lent>,
    len: usize,
    fed: u64,
    tasks: [LeafTask; PARALLELISM],
    panicked: bool,
}

struct PipeShared {
    slot: Mutex<PipeSlot>,
    ready: Condvar,
    idle: Condvar,
}

/// One resident worker per share of a lent batch.
pub(crate) struct Pipe {
    shared: Arc<PipeShared>,
    workers: Vec<std::thread::JoinHandle<()>>,
    /// Shares a batch is cut into, one per worker.
    shares: usize,
}

fn pipe_lock(shared: &PipeShared) -> std::sync::MutexGuard<'_, PipeSlot> {
    // As `lock` above: a worker runs its share inside `catch_unwind` with
    // the lock released, so no panicking frame ever holds it.
    shared.slot.lock().unwrap_or_else(|e| e.into_inner())
}

fn pipe_worker(shared: &PipeShared, share: usize, shares: usize) {
    let per = PARALLELISM / shares;
    let mut seen = 0u64;
    loop {
        let (stage, len, fed, mut tasks) = {
            let mut slot = pipe_lock(shared);
            loop {
                if slot.shutdown {
                    return;
                }
                if slot.generation != seen {
                    seen = slot.generation;
                    break;
                }
                slot = shared.ready.wait(slot).unwrap_or_else(|e| e.into_inner());
            }
            let stage = slot
                .stage
                .clone()
                .expect("a started batch carries its stage");
            (stage, slot.len, slot.fed, slot.tasks)
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let bytes: &[u8] = &stage;
            let pieces = [&bytes[..len]];
            if let [one, two] = &mut tasks[share * per..(share + 1) * per] {
                let leaf = share * 2;
                [one.withheld, two.withheld] = leaf_pair_run(
                    &mut one.state,
                    &mut two.state,
                    [one.pending, two.pending],
                    fed,
                    &pieces,
                    leaf,
                );
                return;
            }
            let mine = tasks.iter_mut().enumerate().skip(share * per).take(per);
            for (leaf, task) in mine {
                task.withheld = leaf_run(&mut task.state, task.pending, fed, &pieces, leaf);
            }
        }));
        // The clone goes BEFORE the report, so a landed stage is unshared.
        drop(stage);
        let mut slot = pipe_lock(shared);
        slot.tasks[share * per..(share + 1) * per]
            .copy_from_slice(&tasks[share * per..(share + 1) * per]);
        slot.panicked |= outcome.is_err();
        slot.outstanding -= 1;
        if slot.outstanding == 0 {
            shared.idle.notify_all();
        }
    }
}

impl Pipe {
    /// `shares` workers, or `None` if any of them cannot be started (the
    /// ones that were are joined as the partial pipe drops).
    fn new(shares: usize) -> Option<Pipe> {
        let shared = Arc::new(PipeShared {
            slot: Mutex::new(PipeSlot {
                generation: 0,
                shutdown: false,
                outstanding: 0,
                stage: None,
                len: 0,
                fed: 0,
                tasks: [LeafTask {
                    state: [0; 8],
                    pending: None,
                    withheld: [0; BLOCK_BYTES],
                }; PARALLELISM],
                panicked: false,
            }),
            ready: Condvar::new(),
            idle: Condvar::new(),
        });
        let mut pipe = Pipe {
            shared,
            workers: Vec::with_capacity(shares),
            shares,
        };
        for share in 0..shares {
            let mine = Arc::clone(&pipe.shared);
            let spawned = std::thread::Builder::new()
                .name("blake2sp-pipe".to_owned())
                .stack_size(LEAF_STACK)
                .spawn(move || pipe_worker(&mine, share, shares));
            match spawned {
                Ok(handle) => pipe.workers.push(handle),
                Err(_) => return None,
            }
        }
        Some(pipe)
    }

    /// Publish one batch and wake every worker. Returns at once.
    fn start(&self, stage: Lent, len: usize, fed: u64, tasks: [LeafTask; PARALLELISM]) {
        let mut slot = pipe_lock(&self.shared);
        debug_assert_eq!(slot.outstanding, 0, "one flight at a time");
        slot.stage = Some(stage);
        slot.len = len;
        slot.fed = fed;
        slot.tasks = tasks;
        slot.outstanding = self.shares;
        slot.generation = slot.generation.wrapping_add(1);
        drop(slot);
        self.shared.ready.notify_all();
    }

    /// Wait for the batch in flight and take its tasks and its stage.
    fn finish(&self) -> ([LeafTask; PARALLELISM], Lent) {
        let mut slot = self.idle_slot();
        let panicked = std::mem::take(&mut slot.panicked);
        let stage = slot.stage.take().expect("a landed batch carries its stage");
        let tasks = slot.tasks;
        drop(slot);
        assert!(!panicked, "a BLAKE2sp pipe worker panicked");
        (tasks, stage)
    }

    /// Wait for the batch in flight and COPY its tasks, leaving the batch
    /// for [`Self::finish`].
    fn wait_tasks(&self) -> [LeafTask; PARALLELISM] {
        let slot = self.idle_slot();
        assert!(!slot.panicked, "a BLAKE2sp pipe worker panicked");
        slot.tasks
    }

    fn idle_slot(&self) -> std::sync::MutexGuard<'_, PipeSlot> {
        let mut slot = pipe_lock(&self.shared);
        while slot.outstanding != 0 {
            slot = self
                .shared
                .idle
                .wait(slot)
                .unwrap_or_else(|e| e.into_inner());
        }
        slot
    }
}

/// Parked pipes, as many as [`parked_team_cap`] allows: the pipe is the
/// team of eight a lent stage goes to, and it parks between streams for the
/// reason the pool does (see "The parked team of eight" above).
static PARKED_PIPES: Mutex<Vec<Pipe>> = Mutex::new(Vec::new());

/// [`PARKED_PIPES`], or a scoping test's own, as [`parked`] is.
fn parked_pipes() -> &'static Mutex<Vec<Pipe>> {
    #[cfg(test)]
    if let Some(set) = scoped::PIPES.with(std::cell::Cell::get) {
        return set;
    }
    &PARKED_PIPES
}

/// A team's lease on one pipe, given back to [`PARKED_PIPES`] when dropped.
pub(crate) struct PipeLease(Option<Pipe>);

impl PipeLease {
    /// A parked pipe of exactly `shares` workers, or a new one; `None` only
    /// if a new one cannot start all its threads.
    fn lease(shares: usize) -> Option<PipeLease> {
        let parked = {
            let mut parked = parked_pipes().lock().unwrap_or_else(|e| e.into_inner());
            parked
                .iter()
                .rposition(|pipe| pipe.shares == shares)
                .map(|at| parked.swap_remove(at))
        };
        parked
            .or_else(|| Pipe::new(shares))
            .map(|pipe| PipeLease(Some(pipe)))
    }
}

impl std::ops::Deref for PipeLease {
    type Target = Pipe;

    fn deref(&self) -> &Pipe {
        self.0
            .as_ref()
            .expect("a lease holds its pipe until dropped")
    }
}

impl Drop for PipeLease {
    fn drop(&mut self) {
        let Some(pipe) = self.0.take() else {
            return;
        };
        // A team dropped with a stage in flight (a stream abandoned
        // mid-member) is quiesced first, and the stage it lent is let go,
        // so a parked pipe holds no batch and no buffer.
        {
            let mut slot = pipe.idle_slot();
            slot.stage = None;
            slot.panicked = false;
        }
        let mut parked = parked_pipes().lock().unwrap_or_else(|e| e.into_inner());
        let spare = if parked.len() < parked_team_cap() {
            parked.push(pipe);
            None
        } else {
            Some(pipe)
        };
        drop(parked);
        drop(spare);
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        {
            let mut slot = pipe_lock(&self.shared);
            slot.shutdown = true;
        }
        self.shared.ready.notify_all();
        // A worker mid-batch finishes it first: it owns what it reads.
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

// ---- The relay: a leaf runs on into the next feed ----
//
// The pipe above still joins once a batch: the next lend lands the last,
// so every share waits for the slowest at each one. The relay drops that
// join. Feeds are queued, each with the leaf counter it starts at, and
// each share's worker keeps its own leaves' state across them, takes the
// next feed as soon as it is done with the last, and hands its state back
// only when the hasher needs the leaves. A feed leaves the queue, and its
// stage is unshared, once every share is past it; the feeding thread waits
// only while `RELAY_DEPTH` are queued, which bounds how far the fastest
// share can run ahead of the slowest and how many stages are out.
//
// SAFE by the pipe's construction: nothing a worker reads is borrowed.

/// Feeds queued at once before the feeding thread waits. Counted on an M5
/// Max, 16 Oct 2026 (`x` and `t` of one stored 4 GiB member, the default
/// width, a loaded laptop): one ahead gave most of it on `t` and little
/// on `x`, two and four read alike, and eight bought nothing and held
/// more stages.
pub(crate) const RELAY_DEPTH: usize = 2;

/// One queued feed.
struct Feed {
    stage: Lent,
    len: usize,
    /// The leaf counter it starts at.
    fed: u64,
    /// Shares not yet past it.
    left: usize,
}

struct RelaySlot {
    /// The sequence number of `queue[0]`.
    base: u64,
    queue: std::collections::VecDeque<Feed>,
    /// Bumped where a run begins: a worker takes its leaves' state from
    /// `tasks` once a run, at the run's first feed.
    run: u64,
    /// The sequence number of the run's first feed.
    run_start: u64,
    /// Every leaf's state at the run's start, and each share's as it last
    /// left it.
    tasks: [LeafTask; PARALLELISM],
    shutdown: bool,
    panicked: bool,
}

struct RelayShared {
    slot: Mutex<RelaySlot>,
    /// Workers wait here for a feed.
    work: Condvar,
    /// The feeding thread waits here for room, or for the run to end.
    room: Condvar,
}

/// One resident worker per share of a relayed feed.
pub(crate) struct Relay {
    shared: Arc<RelayShared>,
    workers: Vec<std::thread::JoinHandle<()>>,
    shares: usize,
    /// The counter the next feed starts at, and the whole groups of the
    /// run, while one is out.
    fed: u64,
    groups: usize,
    running: bool,
}

fn relay_lock(shared: &RelayShared) -> std::sync::MutexGuard<'_, RelaySlot> {
    // As `lock` above: a share runs inside `catch_unwind` with the lock
    // released, so no panicking frame ever holds it.
    shared.slot.lock().unwrap_or_else(|e| e.into_inner())
}

fn relay_worker(shared: &RelayShared, share: usize, shares: usize) {
    let per = PARALLELISM / shares;
    let mut run = 0u64;
    let mut next = 0u64;
    let mut tasks = [LeafTask {
        state: [0; 8],
        pending: None,
        withheld: [0; BLOCK_BYTES],
    }; PARALLELISM];
    let mine = share * per..(share + 1) * per;
    loop {
        let (stage, len, fed) = {
            let mut slot = relay_lock(shared);
            loop {
                if slot.shutdown {
                    return;
                }
                if slot.run != run {
                    run = slot.run;
                    next = slot.run_start;
                    tasks[mine.clone()].copy_from_slice(&slot.tasks[mine.clone()]);
                }
                if next < slot.base + slot.queue.len() as u64 {
                    break;
                }
                slot = shared.work.wait(slot).unwrap_or_else(|e| e.into_inner());
            }
            let feed = &slot.queue[(next - slot.base) as usize];
            (Arc::clone(&feed.stage), feed.len, feed.fed)
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let bytes: &[u8] = &stage;
            let pieces = [&bytes[..len]];
            for leaf in mine.clone() {
                let task = &mut tasks[leaf];
                task.withheld = leaf_run(&mut task.state, task.pending, fed, &pieces, leaf);
                // The next feed starts from the block this one withheld.
                task.pending = Some(task.withheld);
            }
        }));
        // The clone goes BEFORE the report, so a feed that leaves the
        // queue leaves its stage unshared.
        drop(stage);
        let mut slot = relay_lock(shared);
        slot.tasks[mine.clone()].copy_from_slice(&tasks[mine.clone()]);
        slot.panicked |= outcome.is_err();
        let at = (next - slot.base) as usize;
        slot.queue[at].left -= 1;
        next += 1;
        let mut left_queue = false;
        while slot.queue.front().is_some_and(|feed| feed.left == 0) {
            slot.queue.pop_front();
            slot.base += 1;
            left_queue = true;
        }
        drop(slot);
        if left_queue {
            shared.room.notify_all();
        }
    }
}

impl Relay {
    /// `shares` workers, or `None` if any of them cannot be started (the
    /// ones that were are joined as the partial relay drops).
    fn new(shares: usize) -> Option<Relay> {
        let shared = Arc::new(RelayShared {
            slot: Mutex::new(RelaySlot {
                base: 0,
                queue: std::collections::VecDeque::with_capacity(RELAY_DEPTH),
                run: 0,
                run_start: 0,
                tasks: [LeafTask {
                    state: [0; 8],
                    pending: None,
                    withheld: [0; BLOCK_BYTES],
                }; PARALLELISM],
                shutdown: false,
                panicked: false,
            }),
            work: Condvar::new(),
            room: Condvar::new(),
        });
        let mut relay = Relay {
            shared,
            workers: Vec::with_capacity(shares),
            shares,
            fed: 0,
            groups: 0,
            running: false,
        };
        for share in 0..shares {
            let mine = Arc::clone(&relay.shared);
            let spawned = std::thread::Builder::new()
                .name("blake2sp-relay".to_owned())
                .stack_size(LEAF_STACK)
                .spawn(move || relay_worker(&mine, share, shares));
            match spawned {
                Ok(handle) => relay.workers.push(handle),
                Err(_) => return None,
            }
        }
        Some(relay)
    }

    /// Queue one feed, beginning a run from `leaves` where none is out.
    fn submit(&mut self, leaves: &ManyLeaves, stage: Lent, len: usize) {
        let mut slot = relay_lock(&self.shared);
        while slot.queue.len() >= RELAY_DEPTH {
            slot = self
                .shared
                .room
                .wait(slot)
                .unwrap_or_else(|e| e.into_inner());
        }
        if !self.running {
            slot.run = slot.run.wrapping_add(1);
            slot.run_start = slot.base + slot.queue.len() as u64;
            slot.tasks = leaves.leaf_tasks();
            self.fed = leaves.halves[0].fed;
            self.groups = 0;
            self.running = true;
        }
        let groups = len / GROUP_BYTES;
        slot.queue.push_back(Feed {
            stage,
            len,
            fed: self.fed,
            left: self.shares,
        });
        self.fed += (groups * BLOCK_BYTES) as u64;
        self.groups += groups;
        drop(slot);
        self.shared.work.notify_all();
    }

    /// The idle slot: every queued feed done by every share.
    fn idle_slot(&self) -> std::sync::MutexGuard<'_, RelaySlot> {
        let mut slot = relay_lock(&self.shared);
        while !slot.queue.is_empty() {
            slot = self
                .shared
                .room
                .wait(slot)
                .unwrap_or_else(|e| e.into_inner());
        }
        slot
    }

    /// Wait for the run that is out, if one is, and fold every leaf back.
    fn land(&mut self, leaves: &mut ManyLeaves) {
        if !self.running {
            return;
        }
        let mut slot = self.idle_slot();
        let panicked = std::mem::take(&mut slot.panicked);
        let tasks = slot.tasks;
        drop(slot);
        assert!(!panicked, "a BLAKE2sp relay worker panicked");
        leaves.rejoin_tasks(&tasks, self.groups);
        self.running = false;
        self.groups = 0;
    }

    /// The run that is out, waited for and COPIED, for a clone; the run
    /// stays for [`Self::land`].
    fn wait_tasks(&self) -> Option<([LeafTask; PARALLELISM], usize)> {
        if !self.running {
            return None;
        }
        let slot = self.idle_slot();
        assert!(!slot.panicked, "a BLAKE2sp relay worker panicked");
        Some((slot.tasks, self.groups))
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        relay_lock(&self.shared).shutdown = true;
        self.shared.work.notify_all();
        // A worker mid-feed finishes it first: it owns what it reads.
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Parked relays, as many as [`parked_team_cap`] allows, for the reason
/// the pipe parks: a hasher reset member after member starts no thread.
static PARKED_RELAYS: Mutex<Vec<Relay>> = Mutex::new(Vec::new());

/// [`PARKED_RELAYS`], or a scoping test's own, as [`parked`] is.
fn parked_relays() -> &'static Mutex<Vec<Relay>> {
    #[cfg(test)]
    if let Some(set) = scoped::RELAYS.with(std::cell::Cell::get) {
        return set;
    }
    &PARKED_RELAYS
}

/// A team's lease on one relay, given back to [`PARKED_RELAYS`] when
/// dropped.
pub(crate) struct RelayLease(Option<Relay>);

impl RelayLease {
    /// A parked relay of exactly `shares` workers, or a new one; `None` only
    /// if a new one cannot start all its threads.
    fn lease(shares: usize) -> Option<RelayLease> {
        let parked = {
            let mut parked = parked_relays().lock().unwrap_or_else(|e| e.into_inner());
            parked
                .iter()
                .rposition(|relay| relay.shares == shares)
                .map(|at| parked.swap_remove(at))
        };
        parked
            .or_else(|| Relay::new(shares))
            .map(|relay| RelayLease(Some(relay)))
    }
}

impl std::ops::Deref for RelayLease {
    type Target = Relay;

    fn deref(&self) -> &Relay {
        self.0
            .as_ref()
            .expect("a lease holds its relay until dropped")
    }
}

impl std::ops::DerefMut for RelayLease {
    fn deref_mut(&mut self) -> &mut Relay {
        self.0
            .as_mut()
            .expect("a lease holds its relay until dropped")
    }
}

impl Drop for RelayLease {
    fn drop(&mut self) {
        let Some(mut relay) = self.0.take() else {
            return;
        };
        // A team dropped with a run out (a stream abandoned mid-member) is
        // quiesced first and its stages let go, so a parked relay holds no
        // feed and no buffer; and the run is over, so the next stream to
        // lease it begins its own from its own leaves.
        {
            let mut slot = relay.idle_slot();
            slot.panicked = false;
        }
        relay.running = false;
        relay.groups = 0;
        let mut parked = parked_relays().lock().unwrap_or_else(|e| e.into_inner());
        let spare = if parked.len() < parked_team_cap() {
            parked.push(relay);
            None
        } else {
            Some(relay)
        };
        drop(parked);
        drop(spare);
    }
}

/// `RARKIT_BLAKE_RESIDENT=off` gives a team of two its spawn per batch
/// back: the BEFORE arm of a before-and-after in ONE gate binary, so the
/// two halves cannot differ by code layout. Read
/// once a process. Behind `test-support`, which the gate binary turns on
/// and no shipped build does.
#[cfg(feature = "test-support")]
fn resident_is_off() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| std::env::var("RARKIT_BLAKE_RESIDENT").is_ok_and(|v| v == "off"))
}

#[cfg(not(feature = "test-support"))]
fn resident_is_off() -> bool {
    false
}

/// Whether a team's leased helper is still alive, read without holding
/// it: a helper parked or leased again keeps its shared state alive, and
/// one that was joined does not.
#[cfg(test)]
pub(crate) struct HelperProbe(std::sync::Weak<Shared<HalfJob>>);

#[cfg(test)]
impl HelperProbe {
    fn alive(&self) -> bool {
        self.0.upgrade().is_some()
    }
}

#[cfg(test)]
impl<const THREADS: usize, const POOLED: bool> ScalarLeafTeam<THREADS, POOLED> {
    /// The helper this team leased, if it has one.
    pub(crate) fn helper_probe(&self) -> Option<HelperProbe> {
        let pool = self.helper.as_ref()?.0.as_ref()?;
        Some(HelperProbe(Arc::downgrade(&pool.shared)))
    }

    /// The pool this team leased, if it has one: alive while leased or
    /// parked, dead once joined.
    fn pool_probe(&self) -> Option<std::sync::Weak<Shared<Job>>> {
        let pool = self.pool.as_ref()?.pool.as_ref()?;
        Some(Arc::downgrade(&pool.shared))
    }
}

/// Parked sets private to one test's thread.
///
/// The process-global sets are shared by every test in the binary that
/// hashes a stream past the threshold, so a test that reads one after a
/// drop reads whatever the other threads leased or parked in between: a
/// full set it did not fill, or its own parked pool leased again and
/// joined by a drop on another thread. A test that holds a [`Scope`]
/// leases from and parks into its own empty sets instead, which only its
/// own thread touches, so what it observes is what its own drops did. The
/// product's rules (lease by exact count, park up to the cap, join past
/// it) are the same code either way; only the set they run against moves.
#[cfg(test)]
mod scoped {
    use super::{HalfJob, LeafPool, Mutex, Pipe, Relay};
    use std::cell::Cell;

    type Set<T> = Cell<Option<&'static Mutex<Vec<T>>>>;

    thread_local! {
        pub(super) static HELPERS: Set<LeafPool<HalfJob>> = const { Cell::new(None) };
        pub(super) static TEAMS: Set<(usize, LeafPool)> = const { Cell::new(None) };
        pub(super) static PIPES: Set<Pipe> = const { Cell::new(None) };
        pub(super) static RELAYS: Set<Relay> = const { Cell::new(None) };
    }

    /// This thread's own parked sets, from `new` until dropped. The sets
    /// themselves are leaked, three empty mutexes a test; whatever is parked
    /// in them when the scope ends is joined.
    pub(super) struct Scope(());

    fn install<T: 'static>(key: &'static std::thread::LocalKey<Set<T>>) {
        let set: &'static Mutex<Vec<T>> = Box::leak(Box::new(Mutex::new(Vec::new())));
        assert!(
            key.with(|cell| cell.replace(Some(set))).is_none(),
            "one scope a thread"
        );
    }

    fn remove<T: 'static>(key: &'static std::thread::LocalKey<Set<T>>) {
        if let Some(set) = key.with(|cell| cell.take()) {
            let parked = std::mem::take(&mut *set.lock().unwrap_or_else(|e| e.into_inner()));
            drop(parked);
        }
    }

    impl Scope {
        pub(super) fn new() -> Scope {
            install(&HELPERS);
            install(&TEAMS);
            install(&PIPES);
            install(&RELAYS);
            Scope(())
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            remove(&HELPERS);
            remove(&TEAMS);
            remove(&PIPES);
            remove(&RELAYS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filler(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect()
    }

    /// THE LEAF STACK HAS ROOM IN EVERY PROFILE (a release blocker, 20 Oct
    /// 2026): what a pipe, relay or pool worker runs on its `LEAF_STACK`
    /// (a leaf pair's run and a lone leaf's, over a stage of 1 MiB) is run
    /// here on a thread given HALF of it, so the workers' stack holds at
    /// least twice what they use in the profile this test is built with.
    /// At opt-level 0 with cargo's own full debuginfo, the public tree's
    /// plain `cargo test`, the pipe's worker needs between 64 and 80 KiB on
    /// Apple aarch64, and the 64 KiB it was given aborted the whole test
    /// binary ("thread 'blake2sp-pipe' has overflowed its stack"). An
    /// overflow here aborts this binary too: that is the failure. One
    /// thread; about 1 MiB of memory.
    #[test]
    fn the_leaf_workers_stack_holds_twice_their_use() {
        let stage = filler(1 << 20);
        let ran = std::thread::Builder::new()
            .name("leaf-stack-half".to_owned())
            .stack_size(LEAF_STACK / 2)
            .spawn(move || {
                let pieces = [&stage[..]];
                let (mut h, mut g, mut k) = ([7u32; 8], [9u32; 8], [11u32; 8]);
                let pair = leaf_pair_run(&mut h, &mut g, [None, None], 0, &pieces, 0);
                let lone = leaf_run(&mut k, None, 0, &pieces, 2);
                (pair, lone, h, g, k)
            })
            .expect("a test thread")
            .join()
            .expect("the leaf runs return");
        assert_ne!(ran.2, [7u32; 8]);
        assert_ne!(ran.4, [11u32; 8]);
    }

    /// Eight leaf digests of `data`'s whole groups and its tail, through
    /// `team` in batches of `batch` groups at `workers`.
    fn leaves_through(
        data: &[u8],
        batch: usize,
        workers: usize,
    ) -> ([[u8; OUT_BYTES]; PARALLELISM], bool) {
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        let whole = data.len() / GROUP_BYTES * GROUP_BYTES;
        for run in data[..whole].chunks(batch * GROUP_BYTES) {
            team.absorb_groups_at(run, workers);
        }
        let leased = team.helper_probe().is_some();
        (team.finalize(&data[whole..]), leased)
    }

    /// A team of two with its resident helper gives the NEON halves' own
    /// leaf digests, eight streams at once, at batches under, at and over
    /// the helper's threshold.
    #[test]
    fn eight_teams_of_two_at_once_agree_with_the_halves_on_one_thread() {
        let data = filler((4 << 20) + 7 * GROUP_BYTES + 100);
        let whole = data.len() / GROUP_BYTES * GROUP_BYTES;
        let mut reference = ManyLeaves::new();
        for piece in data[..whole].chunks(GROUP_BYTES) {
            reference.absorb_groups(piece);
        }
        let want = reference.finalize(&data[whole..]);
        std::thread::scope(|scope| {
            let handles: Vec<_> = [1, 1023, THREAD_MIN_GROUPS, 2048, 3001, 8192, 1024, 4096]
                .into_iter()
                .map(|batch| {
                    let data = &data;
                    scope.spawn(move || (batch, leaves_through(data, batch, 2)))
                })
                .collect();
            for handle in handles {
                let (batch, (got, leased)) = handle.join().expect("no stream panics");
                assert_eq!(got, want, "a team of two fed {batch} groups at a time");
                assert!(leased, "a stream past the threshold leases its helper");
            }
        });
    }

    /// A stream under the threshold never leases; one past it does; and a
    /// dropped team PARKS its helper rather than joining it, so the next
    /// stream starts no thread.
    ///
    /// Against this test's own parked set ([`scoped::Scope`]), so no other
    /// test's drop can fill the set before this one parks.
    #[test]
    fn a_dropped_team_parks_its_helper_and_a_short_stream_leases_none() {
        let _scope = scoped::Scope::new();
        let short = filler((THREAD_MIN_GROUPS - 1) * GROUP_BYTES);
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        team.absorb_groups_at(&short, 2);
        assert!(team.helper_probe().is_none(), "under the threshold");

        let long = filler(THREAD_MIN_GROUPS * GROUP_BYTES);
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        team.absorb_groups_at(&long, 2);
        let probe = team.helper_probe().expect("past the threshold");
        drop(team);
        assert!(probe.alive(), "parked, not joined");

        // A clone starts with no helper of its own, and a team of any
        // other width never leases one.
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        team.absorb_groups_at(&long, 2);
        assert!(team.clone().helper_probe().is_none(), "a clone re-earns it");
        for workers in [1, 4, 8] {
            let mut other = ScalarLeafTeam::<PARALLELISM, true>::new();
            other.absorb_groups_at(&long, workers);
            assert!(other.helper_probe().is_none(), "width {workers}");
        }
    }

    /// The team of eight's pool, the same way: a stream under the threshold
    /// leases none; one past it does; a dropped team PARKS its pool rather
    /// than joining it; the leaf digests are the halves' own through a pool
    /// that served an earlier stream; and a clone starts with none.
    ///
    /// Against this test's own parked set ([`scoped::Scope`]). It used to
    /// read the process-global one, which every test hashing a long stream
    /// leases from and parks into, and so could not tell its own drop
    /// joining a pool from another thread filling the set or leasing its
    /// parked pool away; under a full parallel `cargo test` that failed
    /// about one run in three. In its own set, which starts empty and only
    /// this thread touches, the drop always parks, and the next round
    /// leases that very pool.
    #[test]
    fn a_dropped_team_of_eight_parks_its_pool_and_a_short_stream_leases_none() {
        let _scope = scoped::Scope::new();
        let short = filler((THREAD_MIN_GROUPS - 1) * GROUP_BYTES);
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        team.absorb_groups_at(&short, 8);
        assert!(team.pool_probe().is_none(), "under the threshold");

        let data = filler((3 * THREAD_MIN_GROUPS + 5) * GROUP_BYTES + 77);
        let whole = data.len() / GROUP_BYTES * GROUP_BYTES;
        let mut reference = ManyLeaves::new();
        reference.absorb_groups(&data[..whole]);
        let want = reference.finalize(&data[whole..]);

        let mut served: Option<std::sync::Weak<Shared<Job>>> = None;
        for round in 0..4 {
            let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
            for run in data[..whole].chunks(THREAD_MIN_GROUPS * GROUP_BYTES) {
                team.absorb_groups_at(run, 8);
            }
            let probe = team.pool_probe().expect("past the threshold");
            if let Some(earlier) = &served {
                assert!(
                    earlier.ptr_eq(&probe),
                    "round {round}: the pool the last round parked, leased again"
                );
            }
            assert!(team.clone().pool_probe().is_none(), "a clone re-earns it");
            assert_eq!(team.finalize(&data[whole..]), want, "round {round}");
            assert!(
                probe.upgrade().is_some(),
                "round {round}: parked, not joined"
            );
            let parked = parked_teams()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            assert_eq!(parked, 1, "round {round}: parked in this test's set");
            served = Some(probe);
        }
        for workers in [1, 2] {
            let mut other = ScalarLeafTeam::<PARALLELISM, true>::new();
            other.absorb_groups_at(&data[..whole], workers);
            assert!(other.pool_probe().is_none(), "width {workers}");
        }
        // A width of four leases a pool of three, never one of seven.
        let mut four = ScalarLeafTeam::<PARALLELISM, true>::new();
        four.absorb_groups_at(&data[..whole], 4);
        let pool = four
            .pool
            .as_ref()
            .expect("a team of four past the threshold");
        assert_eq!((pool.workers, pool.pool().workers.len()), (3, 3));
        assert_eq!(four.finalize(&data[whole..]), want, "width four");
    }

    /// A team's pipe parks when the team is dropped, mid-flight included,
    /// and a parked pipe holds no stage: the one lent is let go.
    ///
    /// Against this test's own parked set ([`scoped::Scope`]), for the
    /// reason the team of eight's test gives.
    #[test]
    fn a_dropped_team_parks_its_pipe_and_lets_go_of_the_stage() {
        let _scope = scoped::Scope::new();
        let data = filler(3 * THREAD_MIN_GROUPS * GROUP_BYTES);
        let batch = THREAD_MIN_GROUPS * GROUP_BYTES;
        for finish in [true, false] {
            let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
            let stage: Lent = Arc::new(data[..batch].to_vec().into_boxed_slice());
            let held = Arc::downgrade(&stage);
            assert!(team.lend(stage, batch, 8).is_ok(), "a whole stage is lent");
            let shared = Arc::downgrade(&team.pipe.as_ref().expect("lent").shared);
            if finish {
                let back = team.settle().expect("the lent stage comes back");
                assert_eq!(Arc::strong_count(&back), 1, "unshared once landed");
            }
            drop(team);
            assert!(
                shared.upgrade().is_some(),
                "finish {finish}: parked, not joined"
            );
            let parked = parked_pipes()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            assert_eq!(parked, 1, "finish {finish}: parked in this test's set");
            if !finish {
                assert!(held.upgrade().is_none(), "a parked pipe keeps no stage");
            }
        }
    }

    /// Deterministic noise, so a block's words are no pattern a mistake
    /// in the message order could hide behind.
    fn noise(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// The pair kernel is two single runs exactly: every pair of adjacent
    /// leaves a share of two can hold, with both, one or neither leaf
    /// carrying a withheld block in, over one piece and over several.
    /// One thread; under a megabyte.
    #[test]
    fn a_pair_of_leaves_is_two_single_runs() {
        let data = noise(7, 9 * GROUP_BYTES);
        let shapes: [&[usize]; 3] = [&[1], &[5], &[1, 3, 4]];
        let block =
            |seed: u64| -> [u8; BLOCK_BYTES] { noise(seed, BLOCK_BYTES).try_into().unwrap() };
        for leaf in [0, 2, 4, 6] {
            for shape in shapes {
                let mut pieces = Vec::new();
                let mut at = 0;
                for groups in shape {
                    pieces.push(&data[at..at + groups * GROUP_BYTES]);
                    at += groups * GROUP_BYTES;
                }
                for pending in [
                    [Some(block(1)), Some(block(2))],
                    [Some(block(3)), None],
                    [None, Some(block(4))],
                    [None, None],
                ] {
                    let fed = 64 * 1000 + BLOCK_BYTES as u64;
                    let start: [[u32; 8]; 2] = [
                        std::array::from_fn(|i| IV[i] ^ (leaf as u32) << i),
                        std::array::from_fn(|i| IV[i] ^ (leaf as u32 + 1) << i),
                    ];
                    let mut one = start;
                    let want = [
                        leaf_run(&mut one[0], pending[0], fed, &pieces, leaf),
                        leaf_run(&mut one[1], pending[1], fed, &pieces, leaf + 1),
                    ];
                    let mut two = start;
                    let [h, g] = &mut two;
                    let got = leaf_pair_run(h, g, pending, fed, &pieces, leaf);
                    assert_eq!(got, want, "leaf {leaf}, {shape:?}: withheld");
                    assert_eq!(two, one, "leaf {leaf}, {shape:?}: states");
                }
            }
        }
    }

    /// A team of four to seven workers (two leaves a share, the pair
    /// kernel) gives the leaves a width of one gives, pooled and lent and
    /// not, at batches under, at and over the pool's threshold, and when
    /// a stream's width changes between batches. A pool of up to three
    /// workers beside the calling thread; about 13 MiB.
    #[test]
    fn teams_of_four_to_seven_give_the_leaves_of_one_worker() {
        let _scope = scoped::Scope::new();
        let data = noise(11, (4 << 20) + 7 * GROUP_BYTES + 100);
        let whole = data.len() / GROUP_BYTES * GROUP_BYTES;
        let (want, _) = leaves_through(&data, THREAD_MIN_GROUPS, 1);
        for workers in 4..=7 {
            for batch in [1, 64, THREAD_MIN_GROUPS, 3 * THREAD_MIN_GROUPS + 5] {
                let (got, _) = leaves_through(&data, batch, workers);
                assert_eq!(got, want, "pooled, {workers} workers, batch {batch}");
                // Unpooled: every batch through a scope of its own.
                let mut team = ScalarLeafTeam::<PARALLELISM, false>::new();
                for run in data[..whole].chunks(batch * GROUP_BYTES) {
                    team.absorb_groups_at(run, workers);
                }
                let got = team.finalize(&data[whole..]);
                assert_eq!(got, want, "unpooled, {workers} workers, batch {batch}");
            }
        }
        // The width moving between batches: 8, 4, 2, 6, 1 in turn.
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        let widths = [8, 4, 2, 6, 1];
        let batch = THREAD_MIN_GROUPS * GROUP_BYTES;
        for (i, run) in data[..whole].chunks(batch).enumerate() {
            team.absorb_groups_at(run, widths[i % widths.len()]);
        }
        assert_eq!(team.finalize(&data[whole..]), want, "a width that moves");
        // Lent at four: each stage to the pipe's four workers, two leaves
        // apiece, landed by the next call.
        let mut team = ScalarLeafTeam::<PARALLELISM, true>::new();
        team.absorb_groups_at(&data[..batch], 4);
        let mut at = batch;
        while at + batch <= whole - GROUP_BYTES {
            let stage: Lent = Arc::new(data[at..at + batch].to_vec().into_boxed_slice());
            assert!(team.lend(stage, batch, 4).is_ok(), "lent at {at}");
            at += batch;
        }
        assert!(team.pipe.as_ref().is_some_and(|pipe| pipe.shares == 4));
        team.absorb_groups_at(&data[at..whole], 4);
        assert_eq!(team.finalize(&data[whole..]), want, "lent at four");
    }

    /// Spec L 5.3's nine digests, `rar -htb`'s own, through a team of four
    /// and of six that runs the pair kernel from its first batch (the
    /// unpooled team spreads every batch), fed whole and in steps. They
    /// are read from the committed vector inputs, so the gate the wiring
    /// test carries is carried here too.
    #[cfg(feature = "repo-tests")]
    #[test]
    fn spec_l_digests_hold_through_a_team_of_two_leaves_a_share() {
        const L_IN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-L/in");
        const K_IN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-K/in");
        let rows: [(String, &str); 9] = [
            (
                format!("{L_IN}/b0.bin"),
                "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f",
            ),
            (
                format!("{L_IN}/b1.bin"),
                "456da349adc8eaa1ee5fd8397d9c181c21a8e9173ad90f22613fd34e1d576d44",
            ),
            (
                format!("{L_IN}/b64.bin"),
                "e375bba69fb1c84c7f202f06e71090695f81786b7413da0cd0126e15a0f80181",
            ),
            (
                format!("{L_IN}/b511.bin"),
                "63a8cc6d628b88d471d4f81035b367f62b8a14dbf55bd9cca0d945dae8e226cf",
            ),
            (
                format!("{L_IN}/b512.bin"),
                "201135254f94f0cf5307da6ae28daf819258fd08df8249684ffbbded6c23e0e5",
            ),
            (
                format!("{L_IN}/b513.bin"),
                "4524c7cfa3a7cde180691ba1a3c0d4b9fc20ced214f27e65f5c76dbb0ff44c91",
            ),
            (
                format!("{L_IN}/b4096.bin"),
                "3f24ed36a1ecaa90c53a5e2568dfb42198cc5d852cd1fe5210f64b3d36989483",
            ),
            (
                format!("{L_IN}/b4097.bin"),
                "bbb0935c0ad88571fece336d8d4a3782c795821491ba9d86392236920288c8dd",
            ),
            (
                format!("{K_IN}/data.bin"),
                "ee89fcc4ec33fa184bd925d48f54171034cd1057372b93eef6da9fcc782df3d2",
            ),
        ];
        for (path, digest) in rows {
            let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            let want: Vec<u8> = (0..OUT_BYTES)
                .map(|i| u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            for workers in [4, 6] {
                for step in [1, 3, usize::MAX] {
                    // Every group but the last TWO goes through the team,
                    // as the seam hands it over; the rest is the tail.
                    let tail = data.len().div_ceil(GROUP_BYTES).saturating_sub(2) * GROUP_BYTES;
                    let mut team = ScalarLeafTeam::<PARALLELISM, false>::new();
                    for run in data[..tail].chunks(step.saturating_mul(GROUP_BYTES)) {
                        team.absorb_groups_at(run, workers);
                    }
                    let rest = &data[tail..];
                    let whole = rest.len() / GROUP_BYTES * GROUP_BYTES;
                    if whole > 0 {
                        team.absorb_groups_at(&rest[..whole], 1);
                    }
                    // The root over the eight leaf digests (RFC 7693 2.8:
                    // node depth 1, the last-node flag), by the crate.
                    let mut root = blake2s_simd::Params::new();
                    root.hash_length(OUT_BYTES)
                        .fanout(PARALLELISM as u8)
                        .max_depth(2)
                        .node_depth(1)
                        .inner_hash_length(OUT_BYTES)
                        .last_node(true);
                    let mut root = root.to_state();
                    for leaf in team.finalize(&rest[whole..]) {
                        root.update(&leaf);
                    }
                    let got = root.finalize();
                    let got = got.as_bytes();
                    assert_eq!(got.to_vec(), want, "{path}, {workers} workers, step {step}");
                }
            }
        }
    }
}
