//! Repair from the recovery data an archive carries INSIDE itself, in
//! either family (API spec section 9).
//!
//! Spec L owns the behaviour: 3.5 and 3.8 for the RAR 5 record, 3.7 for
//! the RAR 2.x protect header and the RAR 3.x `RR` subblock.

use std::io::Write;
use std::ops::Range;

pub(crate) mod gf16;
pub(crate) mod inline;
pub(crate) mod io;
pub(crate) mod legacy;
pub(crate) mod rr5;
pub(crate) mod scan;
pub(crate) mod stripe;
mod verify;

pub use verify::{check_inline, repair_checked, GroupCheck, InlineCheck};

use crate::rev5::RepairReport;
use crate::{ErrorKind, RangeSource, ReadOptions, RecoveryFailure, Result};

/// Rebuild `src` from the recovery record inside it, writing the mended
/// volume to `out`.
///
/// Both families are served here, and so is the case a caller used to have
/// to detect and route around: a RAR 5 volume whose headers are too broken
/// to walk. There is no header walk to fail. The record is located by
/// scanning for it, so the only thing this needs of the volume is that the
/// record itself survived, and the choice between the two ways in is made
/// below rather than by the caller.
///
/// `src` is read once end to end. Working memory stays inside
/// `MemoryPolicy::repair_limit`, which `opts` carries. A volume with no
/// record at all comes back as [`RecoveryFailure::NoRecord`] rather than as
/// a repair that mends nothing.
pub fn repair_inline(
    src: &dyn RangeSource,
    opts: &ReadOptions,
    out: &mut dyn Write,
) -> Result<RepairReport> {
    match scan::scan(src, &opts.memory) {
        Ok(found) => inline::repair(src, &found, &opts.memory, out),
        Err(error) if no_record(&error) => {
            let record = legacy::scan(src)?;
            legacy::repair(src, &record, &opts.memory, out)
        }
        Err(error) => Err(error),
    }
}

/// Say which ranges of `src` hold recovery data, and repair nothing.
///
/// This is the diagnostic half of the module, and what a fuzz target
/// drives: it reaches the same two scanners as [`repair_inline`] and stops
/// where they finish, so it answers what the repair would have worked
/// from without spending the repair.
pub fn scan_inline(src: &dyn RangeSource) -> Result<Vec<InlineChunk>> {
    let policy = crate::memory::repair_only(u64::MAX);
    match scan::scan(src, &policy) {
        Ok(found) => Ok(found
            .records
            .iter()
            .map(|record| InlineChunk {
                range: record.offset..record.offset + record.len,
            })
            .collect()),
        Err(error) if no_record(&error) => {
            let record = legacy::scan(src)?;
            Ok(vec![InlineChunk {
                range: record.data_at..record.data_at + record.area,
            }])
        }
        Err(error) => Err(error),
    }
}

/// What a volume's MAIN HEADER says about a recovery record, and nothing
/// about whether one is there (API spec section 9; spec L 3.5.5 O5).
/// The answer of [`main_header_record`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MainHeaderRecord {
    /// The main header reads and says a recovery record follows (RAR 5:
    /// its archive flag 0x0008 is set).
    Present,
    /// The main header reads and says there is none. Only this ends a
    /// search for a record, whatever the volume holds.
    Absent,
    /// A main header stands there and fails its check: it says nothing
    /// about a record, and the volume is damaged there.
    Corrupt,
    /// None is found where it would stand, as behind enciphered headers
    /// or a lost head (a signature that does not read at byte 0, another
    /// format). Nothing is said about a record either way.
    NoMainHeader,
}

/// What `src`'s main header says about a RAR 5 recovery record.
///
/// It is for a caller that decides, as the reference's repair command
/// does, whether to look for a record at all, and that answers for a
/// main header it found damaged: the search is made on every value but
/// [`MainHeaderRecord::Absent`], a SOUND main header that says there is
/// no record. It reads the main header and no more, never scans for
/// records, and writes nothing. [`repair_inline`] and [`check_inline`]
/// do not ask it; they look.
pub fn main_header_record(src: &dyn RangeSource) -> MainHeaderRecord {
    scan::main_header_record(src)
}

fn no_record(error: &crate::Error) -> bool {
    matches!(error.kind(), ErrorKind::Recovery(RecoveryFailure::NoRecord))
}

/// Where one run of recovery data sits.
///
/// Spec L fixes what a chunk is in each family; what this type adds is the
/// coordinate system, which is the SOURCE's, not the record's: `range`
/// indexes the volume the caller handed in, so it can be read back without
/// knowing how either family lays its record out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineChunk {
    /// The bytes this chunk occupies in the source.
    pub range: Range<u64>,
}
