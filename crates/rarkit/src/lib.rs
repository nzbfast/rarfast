//! A RAR engine: open an archive, list it, get the bytes out, write one,
//! put a damaged one back together.
//!
//! What a caller sees - the types, the functions and the traits - is fixed
//! by `SPEC-API-rarkit.md` of 18 Sep 2026, and this crate is that document
//! in Rust. What happens BEHIND each entry point is fixed elsewhere, one
//! specification per work package: F for the containers and the read API,
//! G for the writers, H for the codecs, I for PPMd, J for the RAR 3
//! filters, K for crypto, L for checksums and recovery.
//!
//! # What is in reach, and what is not
//!
//! Section 1 of the API specification draws the line here, and it is drawn
//! in terms of what a caller can and cannot ask for.
//!
//! - **Reading** covers every RAR there has been: 1.3 and 1.4, 1.5, 2.0,
//!   the RAR 4 family (2.9 through 4.x) and RAR 5. Volumes or a single
//!   file, solid or not, encrypted or not, and a self-extracting
//!   executable is read like any other.
//! - **Writing** covers RAR 5 and the RAR 4 family, at 2.9, 3.0 and 4.0.
//!   The older formats are read-only on purpose rather than by omission:
//!   the type that names a write target has no variant for them, so a
//!   caller cannot ask and be disappointed later.
//! - **There is no filter interpreter.** RAR 3 members may carry a small
//!   program; six of them are standard and are implemented as themselves,
//!   and anything else is refused by name as
//!   [`Unsupported::FilterProgram`], with its length and CRC32 so a report
//!   can say which. In a non-solid archive the members around it still
//!   come out.
//! - **Nothing touches the filesystem on the archive's behalf.** No file
//!   is created, named, stamped or removed here. Names arrive as the
//!   bytes that were stored, with a lossy decoding beside them, and what
//!   to do about traversal, overwriting and timestamps stays the
//!   caller's decision. Two entry points are exceptions, and both only
//!   ever open a path the caller itself named and read it:
//!   [`Archive::open_path`] and [`checksum::crc32_file`].
//! - **Repair** covers RAR 5 `.rev` recovery volumes ([`rev5`]) and the
//!   recovery record carried inside a volume of either family
//!   ([`recovery`]).
//!
//! # What every entry point promises
//!
//! Section 2 states these as testable claims, and each package
//! specification restates the ones it touches with figures attached.
//!
//! 1. **Nothing here panics, aborts or spins**, on any bytes a source can
//!    produce and on any behaviour a caller's own trait implementation can
//!    show. A panic raised inside a caller's method is its own and passes
//!    through unchanged.
//! 2. **No filesystem side effect**, beyond the two read-only helpers
//!    named above.
//! 3. **Untrusted input cannot make the engine allocate without bound.**
//!    A size read out of an archive is checked against [`MemoryPolicy`]
//!    BEFORE anything is allocated to it, so asking for too much is
//!    [`ErrorKind::LimitExceeded`], which names the resource, what was
//!    wanted and what was allowed. It is never an allocation failure.
//! 4. **Reading costs no allocation per header or per member.** Listing N
//!    members is O(1) allocations amortised; extracting adds none beyond
//!    the caller's own sink.
//! 5. **A source is opened once and, on the extract path, read once.** The
//!    exceptions are the ones the formats force, and section 5.4 lists
//!    them.
//! 6. **Output is deterministic**: same inputs, same options, same
//!    entropy, same bytes - on any platform, with `parallel` on or off,
//!    at any number of threads.
//! 7. **Everything public is [`Send`]**, and [`Archive`], [`MemberInfo`],
//!    [`ReadOptions`], [`WriteOptions`], [`MemoryPolicy`] and the report
//!    types are [`Sync`] as well. A [`Session`] holds mutable caches, so
//!    it is `Send` and not `Sync`: keep one per thread, or wrap it.
//! 8. **An error keeps its cause.** When a caller's source, sink, volume
//!    provider, progress observer or entropy source fails, the value
//!    comes back out through [`Error::into_caller_error`], so a caller can
//!    tell its own abort from a broken archive.
//!
//! # How far the packages have got
//!
//! IN PROGRESS, package by package. The reading surface ([`detect`],
//! [`Session`], [`Archive`], [`extract`]), the checksums, the crypto, the
//! RAR 3 filters, PPMd and recovery are implemented; the LZ decoders and
//! everything under [`Writer`] and [`edit`] are `unimplemented!()` until
//! the package that owns each lands. A member whose decoder is not in the
//! build is refused BY NAME through its own [`Sink::close`], never skipped
//! with no trace.
#![deny(unsafe_code)]
// Without `repo-tests` the tests that read this repository's vectors are
// compiled out and their helpers are left unused.
#![cfg_attr(
    all(test, not(feature = "repo-tests")),
    allow(dead_code, unused_imports)
)]
// The skeleton's reason for this is long gone; what keeps it is smaller
// and permanent-looking. Every site is a TRAIT DEFAULT BODY that ignores
// parameters the implementor is expected to use - `Sink::close`,
// `ParallelSink::close` and the three `Progress` methods, each of which
// defaults to `Ok(())` - plus one genuinely unused parameter in
// `write::engine::copy_payload`. Narrowing this to those six items means
// editing five packages' files and deciding whether that last
// parameter is dead API or a missed use, neither of which was settled
// here: it is not done yet.
#![allow(unused_variables)]
// There is no crate-wide `allow(dead_code)` any more, and nothing here
// needs one. It came off on 19 Sep 2026: the carried third went
// with the prune of the carried code, and the 86 items it still hid outside
// `src/carry` were deleted where nothing reached them on any
// configuration, and given their own narrow allow, with the
// configuration or the specification section named beside it, where
// something did. The crate compiles with no dead_code warning on
// aarch64-apple-darwin, x86_64-apple-darwin, x86_64-unknown-linux-gnu,
// armv7-unknown-linux-musleabihf and x86_64-pc-windows-gnu, under
// default features, --no-default-features and --all-features, with and
// without --all-targets. Keep it that way: a new unreferenced item is a
// warning to answer, not a line to re-add here.

#[cfg(feature = "bench-internals")]
mod bench_bytes;
mod carry;
pub mod checksum;
#[cfg(feature = "parallel")]
mod cores;
mod crypto;
pub mod edit;
mod encode;
mod error;
#[cfg(feature = "bench-internals")]
mod internals_a;
#[cfg(feature = "bench-internals")]
mod internals_g;
#[cfg(feature = "bench-internals")]
mod internals_h;
#[cfg(feature = "bench-internals")]
mod internals_h2;
#[cfg(feature = "bench-internals")]
mod internals_h3;
#[cfg(feature = "bench-internals")]
mod internals_i;
#[cfg(feature = "bench-internals")]
mod internals_j;
#[cfg(feature = "bench-internals")]
mod internals_l;
// The environment's tuning words, read only under `reader-knobs` and
// `writer-knobs`: a shipped build reads none.
mod knob;
mod lz20;
pub mod memory;
mod pages;
mod ppmd;
/// Counters this repository's own tests read (feature `test-support`), and
/// the gate bench's dials (`probe-dials`, turned on by each knob feature).
#[cfg(feature = "probe-dials")]
pub mod probe;
mod rar1x;
mod rar3_filters;
mod rar3_lz;
mod rar5_lz;
mod read;
pub mod recovery;
pub mod rev5;
mod source;
mod threads;
mod types;
/// The write side guard every ring in this crate runs in test builds.
#[cfg(debug_assertions)]
mod window_guard;
mod write;

pub use error::{
    Corruption, Error, ErrorKind, PpmFault, Rar20Fault, Rar3Fault, Rar5Fault, RecoveryFailure,
    Resource, Result, Unsupported,
};
pub use memory::MemoryPolicy;

/// The paired chain search's counters by name (feature `pair-census`, a
/// lab instrument no shipped build has): for `rarfast` to print as it ends.
#[cfg(feature = "pair-census")]
pub fn pair_census() -> Vec<(&'static str, u64)> {
    encode::chain::census::read()
}
/// The batched region's turn counts by name (feature `lane-census`, a lab
/// instrument no shipped build has): for `rarfast` to print as it ends.
#[cfg(all(feature = "lane-census", feature = "parallel"))]
pub fn lane_census() -> Vec<(&'static str, u64)> {
    rar5_lz::tape::batch::census::read()
}
pub use read::{
    detect, extract, Archive, BlockInfo, BlockKind, DamagedHeader, Disposition, ExtractReport,
    FileVersion, Format, Found, MemberInfo, MemberOutcome, Progress, ReadOptions, Redirection,
    RedirectionKind, ServiceInfo, ServiceKind, Session, Sink, SplitCheck, VolumeInfo,
    DAMAGED_HEADERS_KEPT, DEFAULT_SFX_SCAN,
};
#[cfg(feature = "parallel")]
pub use read::{extract_parallel, ParallelSink};
pub use source::{Offset, RangeSource, Volumes};
pub use types::{Checksum, HostOs, Method, Password, Timestamp};
/// Crate internals for this repository's benches and fuzz targets only
/// (feature `bench-internals`). Not API: nothing here is stable.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod internals {
    /// Spec K's crypto package.
    pub mod crypto {
        pub use crate::crypto::*;
    }
    /// Spec G's writers.
    pub mod writers {
        pub use crate::internals_g::*;
    }
    /// Spec H3's RAR 2.0 codec.
    pub mod rar20 {
        pub use crate::internals_h3::*;
    }
    /// Spec I's PPMd text model.
    pub mod ppmd {
        pub use crate::internals_i::*;
    }
    /// Spec J's RAR 3 filters.
    pub mod rar3 {
        pub use crate::internals_j::*;
    }
    /// Spec H2's RAR 5 LZ decoder.
    pub mod rar5 {
        pub use crate::internals_h2::*;
    }
    /// The RAR 3 window's COPY CENSUS, a counting instrument behind the
    /// `copy-census` feature and off unless `RARKIT_H1_COPY_CENSUS` is
    /// set. It is NOT behind `bench-internals`, because the counting sits
    /// in a function the bench calls and would then run inside the
    /// measured arm.
    /// It answers which of `Window::copy`'s paths issues the `memmove`
    /// calls a sampled profile can see but cannot attribute.
    #[cfg(feature = "copy-census")]
    pub mod window_census {
        pub use crate::rar3_lz::window::census::*;
    }
    /// Spec L's CRC, BLAKE2sp and recovery package.
    pub mod recovery {
        pub use crate::internals_l::*;
    }
    /// Spec A's RAR 1.5 decoder.
    pub mod rar15 {
        pub use crate::internals_a::*;
    }
    /// Spec H1's RAR 2.9 / 3.x / 4.x LZ decoder.
    pub mod rar3_lz {
        pub use crate::internals_h::*;
    }
}
pub use write::revset::{RevCount, VolumeSet};
pub use write::volume_file_name;
pub use write::{
    ChecksumKind, Entropy, EntropySource, FilterPolicy, Layout, MemberOrder, MemberSortKey,
    MemberSpec, Payload, Rar4Version, ReadSeek, VolumeNaming, VolumeOut, WriteFormat, WriteMethod,
    WriteOptions, WriteReport, Writer,
};
