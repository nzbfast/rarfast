//! A BIG member's output written PAST THE OS CACHE: `FILE_FLAG_NO_BUFFERING`
//! on Windows (the Windows extract write path's lever 2) and `O_DIRECT` on Linux.
//!
//! NTFS takes an unbuffered write at 8.4 to 9.4 GB/s on the Zen 5 PCs this
//! was counted on, against about 6.0 for a cached one, and a cached write
//! leaves the copy into the cache manager on the CPU and the bytes still to
//! be written back. Timed on two Ryzen 7 9800X3D PCs, a 12 GiB stored member
//! was on disk (process wall plus flush) 1.60 to 1.66 times sooner than
//! written cached and 1.61 to 1.68 times sooner than UnRAR.exe 7.23, at half
//! the CPU (29 Sep 2026). On Linux ext4 (a Zen 4 rental,
//! Ryzen 7 7700, a 1.4 GB/s-class NVMe) the same 12 GiB was on disk in 5.7 s
//! by `O_DIRECT` against 7.6 s through the page cache, at 0.6 s of system
//! time against 5.1.
//!
//! The member's file is opened ONCE, by `safepath::make_member_file_with`,
//! with the flag: no second open by path, so nothing can be swapped in
//! between. Such a handle takes only whole sectors from sector aligned
//! memory at sector aligned offsets. The engine's bytes are staged in 4 MiB
//! blocks aligned to 4 KiB, and each full block is handed to the output's
//! WRITER THREAD, which writes the blocks in order, each at its own offset,
//! while the engine fills the next ([`Staged`]; [`depth_or`] blocks in flight).
//! At a depth of 0, the earlier form, each block is
//! written on the engine's thread, and a piece already on a sector boundary
//! with nothing staged before it (the seam's stored slabs) straight from its
//! buffer. At close every block in flight lands, the last partial block is
//! padded to a whole sector and written, and the file is cut back to the
//! bytes that arrived (`TimedFile`'s drop).
//!
//! FALLBACK, silent and byte exact. Where the open is refused (a network
//! share, FAT or exFAT removable media, a filter driver; on Linux a tmpfs, or
//! a filesystem without direct I/O), the member is created as every other
//! member is. Where a direct write fails, the file is opened again cached,
//! positioned after the last sector that landed, and the member completes
//! cached: the staged bytes, then the rest. Only a failure of that cached
//! path is the member's error.
//!
//! THE WRITE-RATE GATE (30 Sep 2026). Past the cache the
//! process runs at the disk's pace, and on a slow disk that is the whole
//! wall: 2 GiB stored took 42.9 s to return direct on a 50 MB/s device
//! against 0.33 s cached, where the cached path's bytes reach such a disk
//! no later. So the first direct writes to a DEVICE are TIMED, every
//! output's together (its [`Probe`], at most [`SPAN`] bytes over the
//! device's busy wall), and where they cannot reach [`GATE_RATE`] over the
//! span every output on it leaves direct writing mid-file by the same byte
//! exact fall back a failed write takes, and completes in [`slow_form`]
//! (write-behind on Linux, cached elsewhere). The verdict is remembered for
//! the device for the rest of the process ([`remembered`]), so a volume set
//! or a many-member extract probes once: a later member on a device
//! remembered slow is never opened direct, one remembered fast is not timed
//! again.
//!
//! THE RULE ON FACTS (a KNOB, off in every shipped build, [`rule`]). The line
//! above answers one question, how fast the device takes direct writes, and
//! what is best on a slow device turned out to depend on whether the device
//! is being READ while it is written and on who paces the job
//! (1 Oct 2026: 40 cells on an NVMe pair and
//! a SATA pair). Under [`Rule::Facts`] a device the line finds slow takes,
//! for each member of an extract, the form [`facts_form`] reads off facts
//! the extract already holds: whether the member is stored or coded, and if
//! coded whether its archive is solid ([`Member`]); whether its archive was
//! WHOLLY in the page cache when the run began (`residency`, every sampled
//! page of the set: [`whole_residency`]); whether the output is
//! on the archive's own device; and whether that device is a parity array.
//! A member whose form is direct STAYS direct through a slow verdict;
//! write-behind is kept for one case alone, a solid archive's coded member
//! written to another device; the verdict is still the device's, once a
//! process. An archive's output (`a`) is not asked: it keeps the line.
//!
//! Safe Rust: std's `OpenOptionsExt::custom_flags`, `Write`, `Seek` and
//! `File::set_len`, the alignment by slicing an allocation. No crate.
//!
//! **macOS keeps the cached path (30 Sep 2026).** Its
//! `F_NOCACHE` form was built and TIMED on an Apple M3 Ultra Mac (APFS, K=5,
//! `F_FULLFSYNC` per output): the 12 GiB member was on disk in 2.40 to 2.53 s
//! against 1.96 s cached, 0.78x to 0.89x on every row, because APFS writes
//! a cached extract back as it goes (the `F_FULLFSYNC` of 12 GiB just
//! written took 0.06 s) and the cached path runs above the `F_NOCACHE`
//! rate. On the fastest
//! Apple disk (the M5 Ultra, 14 GB/s direct) cached is still level with it
//! or ahead, 1.009x to 1.019x on disk for the big member's extract and 1.036x to
//! 1.038x for its create (the rivals comparison's K=7 pairs, 30 Sep 2026), so the
//! write-rate gate below has no macOS arm. By design it is
//! compiled out of the default: [`ABLE`] is false there, and the `fcntl`
//! survives only as a count arm of the `reserve-knob` build
//! (`RARFAST_DIRECT=nocache`), one call under the per-function allow,
//! declared by hand so the crate grows no dependency. A target with no
//! open flag never takes the path.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::residency::Residency;

// The parts, one module a seam. A part's names are taken whole.
mod output;
mod probe;
mod rules;
mod staged;
#[allow(unused_imports)]
pub(crate) use output::*;
#[allow(unused_imports)]
pub(crate) use probe::*;
#[allow(unused_imports)]
pub(crate) use rules::*;
#[allow(unused_imports)]
pub(crate) use staged::*;

/// The least declared size written unbuffered. Below it a member is written
/// cached, as everywhere else: the flag's gain is in the gigabytes, and a
/// small member's bytes are better left in the cache for whoever reads them
/// next.
pub(crate) const LEAST: u64 = 64 << 20;

/// `FILE_FLAG_NO_BUFFERING`.
#[cfg(windows)]
pub(crate) const FLAG: u32 = 0x2000_0000;

/// `O_DIRECT`, from the C library's own table, which is per architecture:
/// `0o40000` on x86-64 (asm-generic's) and `0o200000` on arm64, whose own
/// `asm/fcntl.h` gives four open flags other numbers. Until 1 Oct 2026 this
/// was the generic number written by hand for both, and on arm64 that
/// number is `O_DIRECTORY`: no open on aarch64 Linux was ever direct (with
/// create the kernel refuses the pair, and the output was written cached;
/// see `safepath`'s note on `O_NOFOLLOW` for the same shape). Only the two
/// architectures a direct write was measured on take it; every other Linux
/// target is left cached, below.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) const FLAG: u32 = libc::O_DIRECT as u32;

/// No open flag takes a handle past the cache on this target (macOS takes
/// it after the open, by [`take_direct`]).
#[cfg(not(any(
    windows,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) const FLAG: u32 = 0;

/// Whether this target takes a member past the cache by default: by the
/// open flag alone. macOS ships the cached path; its
/// `F_NOCACHE` count arm is reached only by `RARFAST_DIRECT=nocache` in a
/// `reserve-knob` build, never by a test, so the tests that read this skip
/// there. Read by the tests alone since 30 Sep 2026, hence the allow.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ABLE: bool = FLAG != 0;

#[cfg(test)]
mod tests;
