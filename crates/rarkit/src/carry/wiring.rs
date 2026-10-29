//! This repository's own adapters between the carried kernels and the
//! packages that call them.
//!
//! NOTHING here is carried. These few lines are written in this repository,
//! from the behaviour the kernel and the caller each state, because the
//! predecessor's own adapter is donor text by the provenance census and
//! so may not cross. They live beside the carry modules because they bind
//! the carried code, and they are kept in a file of their
//! own so that nothing in `a_containers`, `b_writers`, `c_lz`, `g_recovery`
//! or `h_ours` is anything but carried text.

/// `data` folded into the finished CRC32 `finished`, answering a finished
/// CRC32 (specification L 3.1, as amended by its erratum of 18 Sep 2026).
///
/// The carried eight-lane PMULL fold where this CPU reports PMULL, the CRC32
/// instructions and SHA3; `crc32fast` on every other CPU and architecture,
/// and as the fallback wherever the kernel declines. Both answer the same
/// value for the same bytes, so which one runs is invisible to the caller.
///
/// The kernel works on the raw, pre-inversion register and this interface is
/// in finished CRCs, so the two inversions are the whole of the adaptation.
#[inline]
pub(crate) fn crc32_update(finished: u32, data: &[u8]) -> u32 {
    if let Some(raw) = super::h_ours::crc32::pmull::update(!finished, data) {
        return !raw;
    }
    let mut hasher = crc32fast::Hasher::new_with_initial(finished);
    hasher.update(data);
    hasher.finalize()
}

/// The bindings for the carried many-lane BLAKE2sp kernel
/// ([`crate::carry::h_ours::rar50::blake2sp::many`]).
///
/// The kernel's 48 items are ours from birth by the provenance census. Four
/// items it calls are not, and neither are the four constants and the
/// `LeafSet` trait the predecessor kept beside it, so every one of them is
/// written here instead, bound to package L's own items wherever L has
/// them. Nothing in this module is carried.
///
/// | name | where it comes from |
/// |---|---|
/// | `BLOCK_BYTES`, `GROUP_BYTES`, `OUT_BYTES`, `PARALLELISM` | re-exported from package L's `checksum::blake2sp::lanes` |
/// | `LANES` | the lanes of one 128-bit register at 32-bit words, which is four |
/// | `IV` | RFC 7693 section 2.6, written here |
/// | `g` | RFC 7693 section 3.1, written here, composed from the kernel's OWN rotates |
/// | `load` | sixteen little-endian bytes into one lane vector, written here |
/// | `LeafSet` | the interface the kernel implements, written here |
///
/// `IV` and `LANES` are package L's values too, at
/// `checksum::blake2sp::lanes`, but both are module-private there and
/// reaching them would mean editing `lanes.rs`, which is written from the
/// specification alone and is left as it is. `g` is deliberately NOT
/// bound to L's `lanes::neon::g`: L's rotates choose different instructions
/// (a shift pair where this kernel uses `tbl` for the rotate by eight), and
/// substituting them would change the thing being measured. Whether to
/// collapse the three onto L's by widening `lanes.rs` is an open
/// question.
pub(crate) mod blake2sp {
    use crate::checksum::blake2sp::lanes;

    pub(crate) use lanes::{
        BLOCK as BLOCK_BYTES, DIGEST as OUT_BYTES, GROUP as GROUP_BYTES, LEAVES as PARALLELISM,
    };

    /// Leaves one vector kernel call advances at once. Two halves cover the
    /// eight BLAKE2sp leaves.
    ///
    /// Used on aarch64, where `Inner::Lanes` is a production arm. Off
    /// aarch64 the SIMD arm replaces it and nothing reads this.
    #[allow(dead_code)]
    pub(crate) const LANES: usize = 4;

    /// The smallest batch, in bytes, for which the carried leaf team builds
    /// its RESIDENT pool.
    ///
    /// Read from the kernel rather than repeated here, so that the hasher
    /// that stages to it and the kernel that tests it are one constant.
    /// Below this the kernel opens a `std::thread::scope` of its own for
    /// every call, which is what made `l/blake2sp/chunk256k-8w` read 0.273x
    /// of the old engine with a 64 KiB staging buffer; the pool, once built,
    /// takes every later batch whatever its size. Package L's
    /// `checksum::blake2sp` stages `POOL_MIN_BATCH + 2 * GROUP_BYTES` so
    /// that every batch it hands over clears this, and never hands the team
    /// a first batch that does not.
    ///
    /// **Off aarch64 this is a staging size and not a threshold.** The
    /// carried many-way SIMD kernel is the arm there, it starts no thread
    /// and has no pool, so there is nothing for a batch to clear; the figure
    /// is written out because `many` is not compiled on those targets and
    /// has no constant to read, and it is kept equal so that the hasher's
    /// working memory is the same number on every target.
    #[cfg(target_arch = "aarch64")]
    pub(crate) const POOL_MIN_BATCH: usize =
        super::super::h_ours::rar50::blake2sp::many::THREAD_MIN_GROUPS * GROUP_BYTES;

    /// See the aarch64 arm above: a staging size, not a threshold.
    #[cfg(not(target_arch = "aarch64"))]
    pub(crate) const POOL_MIN_BATCH: usize = 1024 * GROUP_BYTES;

    /// The smallest run the kernel behind this seam wants handed over ONCE
    /// IT IS RUNNING, which is what package L's streaming hasher absorbs
    /// where the caller's bytes lie instead of gathering them.
    ///
    /// It is a DISPATCH cost against a MEMCPY cost, and the two arms answer
    /// it differently because their kernels do:
    ///
    /// - **aarch64**: [`POOL_MIN_BATCH`]. The team's workers are resident,
    ///   so a batch costs a condvar wake of up to seven of them rather than
    ///   seven `pthread_create`s - but a batch below the pool threshold runs
    ///   on the calling thread (see [`Leaves::absorb`]), so a run handed
    ///   over under this figure would leave the team idle and hash at one
    ///   worker. Gathering to the threshold is what keeps the team engaged,
    ///   and the gather is the cheaper of the two.
    /// - **every other target**: one group. The carried many-way SIMD
    ///   kernel is one thread with no pool and no dispatch at all - an
    ///   `absorb` is a streaming `update` call - so there is nothing for a
    ///   larger batch to amortise and a gather is pure loss. This is what
    ///   the chunked legs pay for off aarch64: the staging copy is a second
    ///   pass over every byte that the one-shot entry point never makes.
    #[cfg(target_arch = "aarch64")]
    pub(crate) const ABSORB_MIN_BATCH: usize = POOL_MIN_BATCH;

    /// See the aarch64 arm above.
    #[cfg(not(target_arch = "aarch64"))]
    pub(crate) const ABSORB_MIN_BATCH: usize = GROUP_BYTES;

    /// A stage lent to the kernel for one flight (see [`Leaves::lend`]):
    /// the streaming hasher's gathering buffer, shared with the workers
    /// that hash it and unshared again once it is landed.
    #[cfg(target_arch = "aarch64")]
    pub(crate) type Lent = std::sync::Arc<Box<[u8]>>;

    /// RFC 7693 section 2.6.
    ///
    /// Read by the aarch64 team arm only; off aarch64 the SIMD kernel
    /// carries its own copy.
    #[allow(dead_code)]
    pub(crate) const IV: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];

    /// The eight leaf states, fed whole [`GROUP_BYTES`] groups and finished
    /// with the final partial group.
    ///
    /// The interface the carried kernel implements. Leaf `i` takes block `i`
    /// of every group (spec L 3.3.1).
    ///
    /// Architecture-conditional, in both directions: off aarch64 nothing
    /// implements this trait at all, because the SIMD arm is the only one
    /// built there; on aarch64 the trait is implemented and used, but
    /// `absorb_group_pieces` has no caller on that side because the batch
    /// dispatch it exists for is the x86-64 kernel's.
    #[allow(dead_code)]
    pub(crate) trait LeafSet: Clone {
        /// Eight leaves over no bytes yet.
        fn new() -> Self;
        /// Feed whole groups. `groups.len()` is a multiple of
        /// [`GROUP_BYTES`].
        fn absorb_groups(&mut self, groups: &[u8]);
        /// [`Self::absorb_groups`] over several group-aligned pieces, hashed
        /// as if they were concatenated. One dispatch where a kernel gains
        /// from the batch size; the default feeds them one at a time.
        fn absorb_group_pieces(&mut self, pieces: &[&[u8]]) {
            for piece in pieces {
                self.absorb_groups(piece);
            }
        }
        /// Finish every leaf. `tail.len() < GROUP_BYTES`, and leaf `i` takes
        /// bytes `i * BLOCK_BYTES..` of it.
        fn finalize(self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM];
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) use neon::{g, load};

    /// The two NEON helpers the carried kernel calls and the census would
    /// not let cross.
    #[cfg(target_arch = "aarch64")]
    mod neon {
        #![allow(unsafe_code)]

        use std::arch::aarch64::{vaddq_u32, vcombine_u32, vcreate_u32, veorq_u32};

        use super::super::super::h_ours::rar50::blake2sp::many::{rot12, rot16, rot7, rot8, V};

        /// Sixteen little-endian bytes as one lane vector.
        ///
        /// Through `vcreate` on two integers rather than a pointer load, so
        /// that no pointer reaches an intrinsic, which is the property the
        /// carried kernel's own comment relies on.
        #[inline]
        #[target_feature(enable = "neon")]
        pub(crate) fn load(bytes: &[u8]) -> V {
            let (lo, hi) = bytes.split_at(8);
            let lo = u64::from_le_bytes(lo.try_into().expect("eight bytes"));
            let hi = u64::from_le_bytes(hi[..8].try_into().expect("eight bytes"));
            vcombine_u32(vcreate_u32(lo), vcreate_u32(hi))
        }

        /// The BLAKE2s mixing function G of RFC 7693 section 3.1, four
        /// leaves wide: every word of the scalar G is one lane of a
        /// `uint32x4_t` and there is no cross-lane work at all.
        ///
        /// The rotates are the carried kernel's own, not package L's, so
        /// that binding this item changes nothing about the instructions
        /// the kernel issues.
        #[inline]
        #[target_feature(enable = "neon")]
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn g(v: &mut [V; 16], a: usize, b: usize, c: usize, d: usize, x: V, y: V) {
            v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), x);
            v[d] = rot16(veorq_u32(v[d], v[a]));
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rot12(veorq_u32(v[b], v[c]));
            v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), y);
            v[d] = rot8(veorq_u32(v[d], v[a]));
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rot7(veorq_u32(v[b], v[c]));
        }
    }

    /// Whether this box has a core for every leaf.
    ///
    /// A BLAKE2sp leaf is a serial chain and there are eight of them, so
    /// eight workers is the whole of the tree's parallelism. Read once:
    /// the answer cannot change and `available_parallelism` is a syscall.
    #[cfg(target_arch = "aarch64")]
    fn wide_team_fits() -> bool {
        static FITS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *FITS.get_or_init(|| {
            std::thread::available_parallelism().is_ok_and(|n| n.get() >= PARALLELISM)
        })
    }

    /// The root of the tree: one BLAKE2s at node depth 1 over the eight leaf
    /// digests, carrying the last-node flag (spec L 3.3.1, RFC 7693 2.8).
    ///
    /// Package L computes the same root in `lanes::root`, which is private
    /// to that module; this one goes through `blake2s_simd`, which the
    /// crate already depends on. The differential test holds the two to each
    /// other on every input it tries.
    #[cfg(target_arch = "aarch64")]
    pub(super) fn root(leaves: &[[u8; OUT_BYTES]; PARALLELISM]) -> [u8; OUT_BYTES] {
        let mut params = blake2s_simd::Params::new();
        params
            .hash_length(OUT_BYTES)
            .fanout(PARALLELISM as u8)
            .max_depth(2)
            .max_leaf_length(0)
            .node_offset(0)
            .node_depth(1)
            .inner_hash_length(OUT_BYTES)
            .last_node(true);
        let mut state = params.to_state();
        for leaf in leaves {
            state.update(leaf);
        }
        let mut out = [0u8; OUT_BYTES];
        out.copy_from_slice(state.finalize().as_bytes());
        out
    }

    /// The eight BLAKE2sp leaves, behind whichever kernel this box and this
    /// worker allowance want. Package L's [`lanes::Leaves`] surface exactly,
    /// so the seam in `checksum::blake2sp` is the constructor and nothing
    /// else.
    ///
    /// Which kernel, and why. Each arm is the arrangement the OLD ENGINE
    /// picks for itself on that target, which is what the 0.97x wall gate
    /// is measured against:
    ///
    /// - **aarch64, one worker, or fewer than eight cores**: package L's own
    ///   lane kernel. Spec L question 6 asks that a caller passing one
    ///   worker keeps its CPU, and L's NEON kernel is the thriftier one per
    ///   byte there - it beats the old engine by about 1.7x per CPU second.
    ///   Nothing here takes that away.
    /// - **aarch64, more than one worker, a core per leaf**: the carried
    ///   eight-worker leaf team, each worker reading its own blocks in place
    ///   at a stride of 512.
    /// - **every other target**: the carried many-way SIMD hasher, which is
    ///   `blake2s_simd`'s own blake2sp - eight leaves compressed side by
    ///   side, eight-wide under AVX2 or four-wide under SSE4.1, chosen by
    ///   the crate's own run-time detection at construction with its
    ///   portable compression as the fallback, all on ONE thread. No
    ///   `unsafe` block is written here or in the carried file: the run-time
    ///   dispatch and every intrinsic are the crate's.
    ///
    /// **Why no leaf team off aarch64, when the team is architecture
    /// neutral.** Because it is the losing arm there and the old engine
    /// measured that for itself: its own audit round 25 (2026-09-03)
    /// replaced a four-thread gathering leaf team with this single-threaded
    /// many-way kernel as its x86 production path, and the carried team's
    /// lane kernel off aarch64 would be exactly the one-leaf-at-a-time
    /// scalar compression that team used. The x86-64 gate's own numbers
    /// agree from the other side: `l/blake2sp/64MiB-8w` costs 1.6x the CPU
    /// of `-1w` for a 5% wall gain on eight vCPUs
    /// (measured 19 Sep 2026). So off aarch64
    /// the worker count is not consulted at all, and one worker and eight
    /// get the same kernel and the same CPU.
    ///
    /// Package L's lane kernel stays the fallback and the differential
    /// reference: it is the aarch64 non-team production path, it is what
    /// every target without a measured alternative keeps, and the tests
    /// below hold all three kernels to one another and to the nine digests
    /// spec L 5.3 pins.
    #[derive(Clone)]
    pub(crate) struct Leaves {
        inner: Inner,
    }

    // The lint wants the 264-byte `Lanes` boxed. It stays inline on purpose:
    // it is the variant on the one-worker hot path, where package L holds it
    // inline today and a `blake2sp(data)` call allocates nothing, and boxing
    // it would add a heap allocation per hasher to the very arrangement spec
    // L question 6 asks to keep cheap. `Simd` is inline for the same reason
    // and on the same path; `Team` is already boxed.
    #[derive(Clone)]
    #[allow(clippy::large_enum_variant)]
    // `Lanes` is constructed on aarch64 only: `with_workers` builds `Simd`
    // everywhere else, and no arm of this enum is dead on every target.
    #[allow(dead_code)]
    enum Inner {
        Lanes(lanes::Leaves),
        #[cfg(target_arch = "aarch64")]
        Team(
            /// The worker allowance the hasher was BUILT with, which is
            /// the one this arm honours. See [`Leaves::absorb`].
            usize,
            Box<super::super::h_ours::rar50::blake2sp::many::ScalarLeafTeam<{ PARALLELISM }, true>>,
        ),
        #[cfg(not(target_arch = "aarch64"))]
        Simd(super::super::h_ours::rar50::blake2sp::simd::SimdHasher),
    }

    impl Default for Leaves {
        fn default() -> Leaves {
            Leaves::new()
        }
    }

    /// The width the carried team runs a batch of `total` bytes at, given
    /// the allowance the hasher was BUILT with.
    ///
    /// ONE rule for both entry points, because the smallest run worth
    /// handing over and the smallest run worth spreading are one decision
    /// and splitting them is how one arrives at a hasher that
    /// absorbs 256 KiB in place and then hashes it at one worker.
    #[cfg(target_arch = "aarch64")]
    fn team_width_for(total: usize, allowance: usize) -> usize {
        if total >= ABSORB_MIN_BATCH {
            allowance
        } else {
            1
        }
    }

    impl Leaves {
        /// Eight leaves over no bytes yet, on the calling thread.
        pub(crate) fn new() -> Leaves {
            Leaves::with_workers(1)
        }

        /// Eight leaves allowed `workers` threads.
        ///
        /// Off aarch64 the allowance is not consulted: the many-way SIMD
        /// kernel uses no thread at all and is the faster arm at every
        /// worker count, so there is nothing for a worker count to choose
        /// between.
        pub(crate) fn with_workers(workers: usize) -> Leaves {
            // Package L's own eight-lane kernel where this x86-64 CPU has
            // it (`checksum::blake2sp::lanes::x86`); the carried many-way
            // hasher otherwise, as before.
            #[cfg(target_arch = "x86_64")]
            if lanes::wide_kernel() {
                return Leaves {
                    inner: Inner::Lanes(lanes::Leaves::new()),
                };
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                let _ = workers;
                Leaves {
                    inner: Inner::Simd(
                        super::super::h_ours::rar50::blake2sp::simd::SimdHasher::new(),
                    ),
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if workers > 1 && wide_team_fits() {
                    return Leaves {
                        inner: Inner::Team(workers, Box::new(LeafSet::new())),
                    };
                }
                Leaves {
                    inner: Inner::Lanes(lanes::Leaves::new()),
                }
            }
        }

        /// Feed whole groups, none of which is any leaf's last.
        ///
        /// `workers` is the allowance for THIS BATCH. Package L computes
        /// it per spec L question 6, which gates its own team on a batch
        /// of at least 8 MiB and passes 1 below that, and the `Lanes` arm
        /// takes it as written.
        ///
        /// **The `Team` arm honours the allowance the HASHER was built
        /// with, not the per-batch one, and here is why that is not the
        /// seam lying about what it does.** Question 6's promise is that a
        /// caller who asks for one worker keeps its CPU, and that promise
        /// is kept exactly: with `workers` of 1 at construction there is
        /// no team at all. The 8 MiB gate on top of it is not that
        /// promise; it is the price of a team whose threads start with the
        /// batch, which is what package L's own kernel has and what this
        /// kernel HAD. This kernel's workers are resident, so a small
        /// batch costs a condvar wake rather than seven
        /// `pthread_create`s, and the gate's premise is gone. Applying it
        /// here anyway cost `l/blake2sp/chunk256k-8w` 0.896x of the old
        /// engine's wall for 1.9x of its CPU; that was measured.
        ///
        /// So the argument reaching this arm is the construction
        /// allowance, and the kernel does obey it: it runs at the largest
        /// width of 1, 2, 4 or 8 that the allowance covers. Whether
        /// question 6 should say the same for a resident team is an open
        /// question for the specification.
        pub(crate) fn absorb(&mut self, groups: &[u8], workers: usize) {
            match &mut self.inner {
                Inner::Lanes(leaves) => leaves.absorb(groups, workers),
                #[cfg(target_arch = "aarch64")]
                Inner::Team(allowance, team) => {
                    // A batch below what this seam is willing to spread is
                    // not worth waking up to seven parked workers for: it
                    // runs on the calling thread instead. The hasher hands
                    // over such a batch once per in-place absorb - the
                    // staged remainder that has to precede the caller's own
                    // bytes in stream order - and a dispatch was measured at
                    // about 95 microseconds of wall on a loaded box, which
                    // is more than two groups of hashing could ever be
                    // worth.
                    //
                    // It is [`ABSORB_MIN_BATCH`] and not [`POOL_MIN_BATCH`]
                    // deliberately: the smallest run worth handing over and
                    // the smallest run worth spreading are ONE decision, and
                    // splitting them is how one arrives at a hasher
                    // that absorbs 256 KiB in place and then hashes it at
                    // one worker. Moving that constant moves both ends, and
                    // moving it to
                    // 64 KiB measured on aarch64: `chunk256k-8w-vs8w` from
                    // 0.993x to 0.885x, with CPU up 5 percent. The gather
                    // is the cheaper of the two here, and the constant stays
                    // where the kernel's own threshold puts it.
                    team.absorb_groups_at(groups, team_width_for(groups.len(), *allowance))
                }
                // A streaming tree over the whole message, so the groups go
                // in as they come and the worker count means nothing to it.
                #[cfg(not(target_arch = "aarch64"))]
                Inner::Simd(hasher) => hasher.update(groups),
            }
        }

        /// Feed several group-aligned pieces as ONE batch, hashed as if they
        /// were concatenated.
        ///
        /// This exists for the one place the streaming hasher cannot hand
        /// the kernel a single slice: the bytes it still has staged have to
        /// precede the caller's own in stream order, and they are at most a
        /// [`GROUP_BYTES`] of alignment plus the hold. Dispatched on their
        /// own that short run is a second call through this seam per
        /// `update`, and it runs at width one however wide the caller's
        /// pool is, which is the finer-grained barrier SPEC-API 8.3
        /// forbids. Handed over WITH the batch it precedes it costs
        /// nothing: the width is decided by the total, so the scrap is
        /// carried rather than dispatched.
        ///
        /// Every piece must be a non-empty whole number of groups, and
        /// none of them may hold any leaf's last block.
        pub(crate) fn absorb_pieces(&mut self, pieces: &[&[u8]], workers: usize) {
            let total: usize = pieces.iter().map(|piece| piece.len()).sum();
            if total == 0 {
                return;
            }
            match &mut self.inner {
                // Stateless between calls but for its counter, so feeding
                // the pieces in order is the concatenation exactly.
                //
                // This arm does spread a batch of its own above 8 MiB, so
                // two pieces are two `join`s where one slice would be one.
                // It is left that way: package L passes 1 below 8 MiB, so
                // the scrap case never reaches a `join` at all, and above
                // it two joins over eight megabytes is not a fine grain.
                // The arm is also the ONE-worker path in practice - a
                // hasher built with workers above one takes `Team` wherever
                // a wide team fits.
                Inner::Lanes(leaves) => {
                    for piece in pieces {
                        leaves.absorb(piece, workers);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                Inner::Team(allowance, team) => {
                    team.absorb_pieces_at(pieces, team_width_for(total, *allowance))
                }
                #[cfg(not(target_arch = "aarch64"))]
                Inner::Simd(hasher) => {
                    for piece in pieces {
                        hasher.update(piece);
                    }
                }
            }
        }

        /// Set the allowance the `Team` arm runs its NEXT batches at
        /// (`checksum::blake2sp`'s re-share, which only ever widens it): the team runs every batch at
        /// the largest width of 1, 2, 4 or 8 its allowance covers, each
        /// leaf's state is the same whatever width absorbed the batch
        /// before, and a lent batch in flight is landed at the width it
        /// was lent at before the leaves are next used, so the figure may
        /// change between any two calls. The other arms have no team and
        /// nothing to set.
        #[cfg(target_arch = "aarch64")]
        pub(crate) fn set_allowance(&mut self, workers: usize) {
            if let Inner::Team(allowance, _) = &mut self.inner {
                *allowance = workers.max(1);
            }
        }

        /// Hand the kernel the first `len` bytes of `stage` - whole groups,
        /// none of them any leaf's last - and return at once, the batch
        /// hashed while the caller gathers the next one. `Err` gives the
        /// stage back untouched where this arm takes no lent batch, and the
        /// caller absorbs it in place instead.
        ///
        /// Only the aarch64 team arm takes one, and only at a width above
        /// two: the lane kernel and the SIMD tree are one thread, with
        /// nothing to overlap the gather with, and a team of two runs the
        /// NEON halves. Whatever is in flight is landed by the next call
        /// into this seam that needs the leaves, so the order of the stream
        /// is kept by construction.
        #[cfg(target_arch = "aarch64")]
        pub(crate) fn lend(&mut self, stage: Lent, len: usize) -> Result<(), Lent> {
            match &mut self.inner {
                #[cfg(target_arch = "aarch64")]
                Inner::Team(allowance, team) => team.lend(stage, len, *allowance),
                _ => {
                    let _ = len;
                    Err(stage)
                }
            }
        }

        /// Hand the team one OWNED feed to relay (the first `len` bytes of
        /// `stage`, whole groups, none of them any leaf's last) and return
        /// once it is queued; `Err` gives it back untouched where nothing
        /// takes it. The aarch64 team arm only, at a width above two.
        #[cfg(target_arch = "aarch64")]
        pub(crate) fn relay(&mut self, stage: Lent, len: usize) -> Result<(), Lent> {
            match &mut self.inner {
                Inner::Team(allowance, team) => team.relay(stage, len, *allowance),
                _ => Err(stage),
            }
        }

        /// Whether [`Self::relay`] would take a feed now.
        #[cfg(target_arch = "aarch64")]
        pub(crate) fn will_relay(&self) -> bool {
            match &self.inner {
                Inner::Team(allowance, team) => team.will_relay(*allowance),
                _ => false,
            }
        }

        /// Whether [`Self::lend`] would take a batch of `len` bytes now, so
        /// a caller takes a second stage only where one will be used.
        #[cfg(target_arch = "aarch64")]
        pub(crate) fn will_lend(&self, len: usize) -> bool {
            match &self.inner {
                #[cfg(target_arch = "aarch64")]
                Inner::Team(allowance, team) => team.will_lend(len, *allowance),
                _ => {
                    let _ = len;
                    false
                }
            }
        }

        /// Land any lent batch and give its stage back for the caller to
        /// gather into again; `None` if nothing was lent since the last
        /// call.
        #[cfg(target_arch = "aarch64")]
        pub(crate) fn settle(&mut self) -> Option<Lent> {
            match &mut self.inner {
                #[cfg(target_arch = "aarch64")]
                Inner::Team(_, team) => team.settle(),
                _ => None,
            }
        }

        /// Compress each leaf's last block or two and hash the eight digests.
        ///
        /// `tail` is at most the last TWO groups, which is package L's
        /// convention. The carried kernel withholds its own last block per
        /// lane and so wants a tail inside ONE group: the drain below is the
        /// whole of the difference.
        pub(crate) fn finish(self, tail: &[u8]) -> [u8; OUT_BYTES] {
            match self.inner {
                Inner::Lanes(leaves) => leaves.finish(tail),
                #[cfg(target_arch = "aarch64")]
                Inner::Team(allowance, team) => {
                    let mut team = *team;
                    let whole = tail.len() / GROUP_BYTES * GROUP_BYTES;
                    if whole > 0 {
                        // One or two groups: under the width rule `absorb`
                        // applies, so on the calling thread rather than
                        // waking a team for them.
                        team.absorb_groups_at(&tail[..whole], team_width_for(whole, allowance));
                    }
                    root(&team.finalize(&tail[whole..]))
                }
                // This kernel owns its whole tree, root included, and takes
                // the tail as ordinary input: `absorb` then `finish` is one
                // streaming update of the concatenation, which is what the
                // other two arms compute the long way.
                #[cfg(not(target_arch = "aarch64"))]
                Inner::Simd(mut hasher) => {
                    hasher.update(tail);
                    hasher.finalize()
                }
            }
        }
    }
}

#[cfg(test)]
mod blake2sp_tests {
    //! The carried many-lane kernel against package L's own lane kernel,
    //! against `blake2s_simd`'s BLAKE2sp, and against the nine digests spec
    //! L 5.3 pins.
    //!
    //! Three implementations, not two: L's `lanes` and the carried kernel
    //! share no line of code, and `blake2s_simd` is a fourth party to both.
    //! The digests of 5.3 are `rar -htb`'s own, so agreement here is
    //! agreement with the format and not just with each other.

    use super::blake2sp::*;

    /// Spec L 5.3's filler: byte `i` is `(7i + 3) mod 256`.
    fn filler(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    fn hex(s: &str) -> [u8; OUT_BYTES] {
        let mut out = [0u8; OUT_BYTES];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    /// Spec L 5.3, all nine rows, read from the committed vector inputs
    /// rather than regenerated: eight `b<n>.bin` beside spec L, and
    /// `data.bin`, which 5.3's last row names and which lives beside spec K.
    fn pinned() -> Vec<(Vec<u8>, [u8; OUT_BYTES])> {
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
        rows.into_iter()
            .map(|(path, digest)| {
                let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
                (data, hex(digest))
            })
            .collect()
    }

    /// `data` through one [`Leaves`], fed in `step`-byte chunks gathered into
    /// whole groups the way `checksum::blake2sp` gathers them.
    fn through_leaves(data: &[u8], workers: usize, step: usize) -> [u8; OUT_BYTES] {
        let mut leaves = Leaves::with_workers(workers);
        let mut pending: Vec<u8> = Vec::new();
        for chunk in data.chunks(step.max(1)) {
            pending.extend_from_slice(chunk);
            // Every group but the last TWO, which is package L's rule: a
            // leaf must not compress its final block as an ordinary one.
            let take = pending.len().div_ceil(GROUP_BYTES).saturating_sub(2) * GROUP_BYTES;
            if take > 0 {
                leaves.absorb(&pending[..take], workers);
                pending.drain(..take);
            }
        }
        leaves.finish(&pending)
    }

    /// The independent crate, which is a fourth implementation of the same
    /// tree and is what package L's own tests cross-check against.
    fn crate_reference(data: &[u8]) -> [u8; OUT_BYTES] {
        *blake2s_simd::blake2sp::blake2sp(data).as_array()
    }

    #[cfg(feature = "repo-tests")]
    #[test]
    fn the_nine_sizes_spec_l_5_3_pins() {
        for (data, want) in pinned() {
            let n = data.len();
            assert_eq!(crate_reference(&data), want, "the crate, {n} bytes");
            assert_eq!(
                crate::checksum::blake2sp::blake2sp(&data),
                want,
                "package L, {n} bytes"
            );
            for workers in [1usize, 2, 8] {
                for step in [1usize, 64, 512, 513, 4096, usize::MAX] {
                    assert_eq!(
                        through_leaves(&data, workers, step),
                        want,
                        "{n} bytes, {workers} workers, step {step}"
                    );
                }
            }
        }
    }

    #[test]
    fn random_sizes_and_chunkings_agree_across_arrangements() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut rand = move |bound: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % bound as u64) as usize
        };
        let big = filler(3 << 20);
        for _ in 0..24 {
            let len = rand(big.len());
            let data = &big[..len];
            let want = crate_reference(data);
            assert_eq!(crate::checksum::blake2sp::blake2sp(data), want, "L, {len}");
            for workers in [1usize, 8] {
                let step = rand(70_000) + 1;
                assert_eq!(
                    through_leaves(data, workers, step),
                    want,
                    "{len} bytes, {workers} workers, step {step}"
                );
            }
        }
    }

    /// Past the batch at which the carried team builds its persistent pool
    /// (1024 groups), so the pooled dispatch and its rejoin are exercised
    /// rather than only the scoped fallback.
    #[test]
    fn a_batch_large_enough_to_build_the_pool() {
        let data = filler((12 << 20) + 5_003);
        let want = crate_reference(&data);
        assert_eq!(
            crate::checksum::blake2sp::blake2sp(&data),
            want,
            "L one-shot"
        );
        for step in [256 << 10, 1 << 20, usize::MAX] {
            assert_eq!(
                through_leaves(&data, 8, step),
                want,
                "8 workers, step {step}"
            );
            assert_eq!(
                through_leaves(&data, 1, step),
                want,
                "1 worker, step {step}"
            );
        }
    }

    /// The carried kernels driven directly, so that the two of them are
    /// covered on every aarch64 box and not only where
    /// `available_parallelism` reports a core per leaf.
    #[cfg(target_arch = "aarch64")]
    #[cfg(feature = "repo-tests")]
    #[test]
    fn both_carried_kernels_directly() {
        use crate::carry::h_ours::rar50::blake2sp::many::{ManyLeaves, ScalarLeafTeam};

        /// The predecessor's own drain discipline: whole groups to the
        /// kernel, which withholds its own last block per lane, then the
        /// remainder inside one group.
        fn one_shot<K: LeafSet>(data: &[u8]) -> [u8; OUT_BYTES] {
            let mut kernel = K::new();
            let whole = data.len() / GROUP_BYTES * GROUP_BYTES;
            kernel.absorb_groups(&data[..whole]);
            super::blake2sp::root(&kernel.finalize(&data[whole..]))
        }

        let mut inputs: Vec<Vec<u8>> = pinned().into_iter().map(|(data, _)| data).collect();
        inputs.extend([65, 1023, 1024, 1025, 1 << 20, (1 << 20) + 7].map(filler));
        for data in inputs {
            let n = data.len();
            let want = crate_reference(&data);
            assert_eq!(one_shot::<ManyLeaves>(&data), want, "NEON halves, {n}");
            assert_eq!(
                one_shot::<ScalarLeafTeam<8, true>>(&data),
                want,
                "leaf team, {n}"
            );
            assert_eq!(
                one_shot::<ScalarLeafTeam<8, false>>(&data),
                want,
                "leaf team, unpooled, {n}"
            );
        }
    }

    /// Off aarch64 the production kernel is the carried many-way SIMD
    /// hasher, so this is the differential that matters there, and it needs
    /// an arm the crate did not write.
    ///
    /// The tests above compare `Leaves` to `crate_reference`, and off
    /// aarch64 BOTH of those are now `blake2s_simd`: agreement between them
    /// says the two entry points agree, not that the digest is right. So
    /// package L's own lane kernel is driven directly here, beside the
    /// carried hasher, and both are held to the nine digests spec L 5.3
    /// pins, which are `rar -htb`'s own. Three independent things: L's
    /// lanes, the crate, and the format.
    ///
    /// Run it for x86-64 on a Mac with
    /// `cargo test --target x86_64-apple-darwin -p rarkit`, which is
    /// Rosetta: it reports and uses AVX2, and NOT AVX-512.
    #[cfg(not(target_arch = "aarch64"))]
    // It reads `specs/vectors-L` and `specs/vectors-K` through `pinned`,
    // which a vendored copy of this crate does not have (`make
    // mirror-check` builds exactly that copy): the gate its siblings carry.
    #[cfg(feature = "repo-tests")]
    #[test]
    fn package_l_lanes_and_the_carried_simd_hasher_agree_off_aarch64() {
        use crate::carry::h_ours::rar50::blake2sp::simd::SimdHasher;
        use crate::checksum::blake2sp::lanes;

        /// Package L's lane kernel on its own, fed in `step`-byte chunks
        /// under L's own drain rule: every group but the last TWO.
        fn through_lanes(data: &[u8], workers: usize, step: usize) -> [u8; OUT_BYTES] {
            let mut leaves = lanes::Leaves::new();
            let mut pending: Vec<u8> = Vec::new();
            for chunk in data.chunks(step.max(1)) {
                pending.extend_from_slice(chunk);
                let take = pending.len().div_ceil(GROUP_BYTES).saturating_sub(2) * GROUP_BYTES;
                if take > 0 {
                    leaves.absorb(&pending[..take], workers);
                    pending.drain(..take);
                }
            }
            leaves.finish(&pending)
        }

        /// The carried hasher on its own, fed the same way.
        fn through_simd(data: &[u8], step: usize) -> [u8; OUT_BYTES] {
            let mut hasher = SimdHasher::new();
            for chunk in data.chunks(step.max(1)) {
                hasher.update(chunk);
            }
            hasher.finalize()
        }

        for (data, want) in pinned() {
            let n = data.len();
            assert_eq!(crate_reference(&data), want, "the crate, {n}");
            for step in [1usize, 64, 512, 513, 4096, usize::MAX] {
                for workers in [1usize, 8] {
                    assert_eq!(
                        through_lanes(&data, workers, step),
                        want,
                        "L lanes, {n}, {workers} workers, step {step}"
                    );
                }
                assert_eq!(
                    through_simd(&data, step),
                    want,
                    "carried SIMD hasher, {n}, step {step}"
                );
            }
        }

        // Past a megabyte and off every alignment, where the production
        // path's own drain and the kernel's internal buffering both bite.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let big = filler((3 << 20) + 4_099);
        for _ in 0..12 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x as usize) % big.len();
            let data = &big[..len];
            let step = ((x >> 32) as usize) % 70_000 + 1;
            let want = through_lanes(data, 1, usize::MAX);
            assert_eq!(crate_reference(data), want, "the crate, {len}");
            assert_eq!(through_simd(data, step), want, "SIMD, {len}, step {step}");
            assert_eq!(
                through_leaves(data, 8, step),
                want,
                "the production seam, {len}, step {step}"
            );
        }
    }

    /// The carried team takes a SMALL batch without starting a thread or
    /// allocating, whatever the size of the stream behind it.
    ///
    /// Package L no longer feeds it one - it stages to
    /// [`POOL_MIN_BATCH`] so that every batch clears the kernel's own
    /// threshold - so nothing in that package would notice if this broke
    /// again. It is the kernel's property and it is asserted here, on the
    /// seam that owns the kernel.
    ///
    /// It did break. Until the resident pool work of 19 Sep 2026 the
    /// team built its pool only on a batch past the threshold, so a caller
    /// handing it 256 KiB opened a `std::thread::scope` on every call:
    /// seven `pthread_create`s and about 2,700 bytes left behind each
    /// time, a heap growing at 10.8 KiB per MiB of input. The team now
    /// earns the pool on the bytes absorbed SO FAR, so it is built once
    /// and every later batch reaches it whatever its size. Measured over
    /// a 16-fold range of input: about 2,200 bytes at 4 MiB, at 16 MiB
    /// and at 64 MiB alike, which is the pool itself - one `Arc`, seven
    /// `JoinHandle`s and the `Vec` holding them. The reading moves by a
    /// few hundred bytes run to run, a high-water mark on a thread the
    /// harness also allocates on not being repeatable to the byte; what
    /// does not move is its independence of the input, and ONE bound held
    /// across that range is what asserts it. The 4 MiB row carries it:
    /// that cost 43,880 bytes when the kernel allocated per call, five
    /// times the bound below.
    #[test]
    fn the_team_takes_small_batches_with_no_thread_start_and_no_heap() {
        use crate::rar3_filters::tests::counting;

        /// Room for the pool and for nothing that scales with the input.
        const POOL_BOUND: u64 = 8 << 10;
        const BATCH: usize = 256 << 10;

        // The team's first batch builds the pool, and the counting
        // allocator is per thread, so warm one up and throw it away
        // before the readings that matter.
        let data = filler(4 << 20);
        let _warm = through_leaves(&data[..BATCH * 3], 8, BATCH);

        let want = crate_reference(&data);
        // Package L's drain rule: every group but the last TWO goes through
        // `absorb`, and the last two are the tail `finish` takes, so that no
        // leaf's final block is compressed as an ordinary one. The streaming
        // arms (the carried team, `blake2s_simd`) accept everything through
        // `absorb` and an empty tail; a LANE arm cannot, and on x86-64 with
        // the AVX-512VL kernel the `Lanes` arm is what `with_workers`
        // builds, which is how this test found its own shape wrong (found
        // on a Zen 5 rental, 28 Sep 2026). The batches
        // stay 256 KiB, whole groups; the heap assertion's meaning is
        // unchanged.
        let hold = data.len() - 2 * GROUP_BYTES;
        for reps in [1usize, 4, 16] {
            counting::reset_peak();
            let mut leaves = Leaves::with_workers(8);
            for _ in 0..reps {
                for batch in data[..hold].chunks(BATCH) {
                    leaves.absorb(batch, 8);
                }
            }
            let digest = leaves.finish(&data[hold..]);
            let peak = counting::peak_bytes();
            assert!(
                peak <= POOL_BOUND,
                "{reps} passes of {} KiB batches: peak {peak} bytes",
                BATCH >> 10
            );
            if reps == 1 {
                assert_eq!(digest, want, "one pass must still be the digest");
            }
        }
    }
}
