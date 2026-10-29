//! Carried from the predecessor's `rar50/blake2sp/simd.rs` at an earlier revision
//! (the fork tip): all five items, ours from birth per the
//! provenance census, re-verified 19 Sep 2026 with a WHOLE-TREE provenance
//! run over the predecessor's source tree (the donor's main branch against
//! the fork point), which is the run that counts: a narrow-prefix run
//! cannot see the other files and under-reports. Five items, zero donor
//! lines each, `at_fork` "no" for every one.
//!
//! The one item this file calls that would not cross is `OUT_BYTES`
//! (held back on a short-name collision, zero donor lines); it is
//! bound to package L's `checksum::blake2sp::lanes::DIGEST` in
//! [`crate::carry::wiring::blake2sp`], exactly as `many.rs`'s four bindings
//! are. Nothing below is anything but carried text.
//!
//! BLAKE2sp over `blake2s_simd`'s own many-way kernel: the eight leaves
//! compressed side by side in one SIMD batch, on one thread.
//!
//! The default everywhere except aarch64, where that crate's many-way
//! kernel does not exist (`guts::MAX_DEGREE` is 1 off x86) and
//! [`super::many::ManyLeaves`] takes over; compiled there too so the tests
//! can hold every kernel to the same digests.
//!
//! This replaced the predecessor's `portable::PortableLeaves` as the x86
//! production path on 2026-09-03. That one held the eight leaves as eight
//! independent `blake2s_simd::State`s and spread them over four scoped
//! threads per buffered chunk, each thread GATHERING its leaves' 64-byte
//! blocks out of the 512-byte groups into a scratch buffer first - so a
//! megabyte of input cost a megabyte of zeroed allocation, a megabyte of
//! copying and four thread spawns before a single compression, and each leaf
//! then ran on the crate's ONE-instance kernel. `blake2s_simd::blake2sp`
//! needs none of it: its leaves read their blocks in place at a stride of
//! eight (`guts`' `Stride::Parallel`) and compress eight-wide under AVX2 or
//! four-wide under SSE4.1, picked by `Implementation::detect()` at
//! construction with the crate's portable compression as the fallback.
//!
//! It is the same tree package L builds by hand - eight leaves, fanout 8,
//! depth 2, 32-byte inner hashes, last-node flag on leaf 7, one root pass -
//! so the digests are equal by construction, and the differential test in
//! `carry/wiring.rs` asserts it.
#![cfg_attr(target_arch = "aarch64", allow(dead_code))]

use crate::carry::wiring::blake2sp::OUT_BYTES;

/// BLAKE2sp-256 as `blake2s_simd`'s own streaming blake2sp state.
#[derive(Clone)]
pub(crate) struct SimdHasher {
    state: blake2s_simd::blake2sp::State,
}

impl SimdHasher {
    pub(crate) fn new() -> Self {
        Self {
            state: blake2s_simd::blake2sp::Params::new()
                .hash_length(OUT_BYTES)
                .to_state(),
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// [`Self::update`] over several pieces hashed as if concatenated.
    ///
    /// This kernel has no batch to gain - its leaves read their blocks in
    /// place at a stride of eight on ONE thread, so a piece costs what its
    /// bytes cost wherever the boundary falls. It carries the method only
    /// because the shared caller hands whole batches over, and the aarch64
    /// leaf team does gain from them. (The carried caller that did so was
    /// itself unreferenced and went with `carry/a_containers` on
    /// 19 Sep 2026, which is why this method now has no caller on x86-64
    /// either; the trait method it satisfies is still the seam.)
    #[allow(dead_code)]
    pub(crate) fn update_pieces(&mut self, pieces: &[&[u8]]) {
        for piece in pieces {
            self.state.update(piece);
        }
    }

    pub(crate) fn finalize(self) -> [u8; OUT_BYTES] {
        let mut out = [0u8; OUT_BYTES];
        out.copy_from_slice(self.state.finalize().as_bytes());
        out
    }
}
