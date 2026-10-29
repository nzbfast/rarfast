//! Package J: the RAR 3 standard filters (SPEC-J).
//!
//! A RAR 3 filter record names a program by its bytes. This crate has no
//! interpreter and does not hold a single program: a program is recognised
//! by its LENGTH and CRC32 as one of six standard programs and replaced by
//! a native transform, and every other program is refused with
//! [`Unsupported::FilterProgram`] before any byte of its span is delivered.
//!
//! The six programs' byte strings were RARLAB's, and the project's decision of
//! 19 Sep 2026 answers SPEC-J section 0 question 1 with NO: nothing here
//! writes a filter record, so nothing here needs those bytes. Reading is
//! unchanged, because reading never compared them.
//!
//! - [`identify`]: the fingerprint table (section 3.4).
//! - [`FilterState`]: the record reader, the program slots and the queue of
//!   pending spans of one decoding stream (sections 3.2 to 3.8).
//! - [`refuse_written_filters`]: the seam spec G section 3.14.7 left
//!   separable, closed (section 3.9).
//! - `delta_*`, `rgb_*`, `audio_*`: the three transforms of section 3.7. The
//!   x86 and Itanium transforms are SPEC-C's, in
//!   [`address_filters`](crate::carry::h_ours::codec::address_filters).
//!
//! [`Unsupported::FilterProgram`]: crate::Unsupported::FilterProgram

use crate::error::{Error, ErrorKind, Result, Unsupported};
use crate::write::{FilterPolicy, WriteFormat};

mod delta16;
mod record;
#[cfg(not(test))]
mod transforms;
#[cfg(test)]
pub(crate) mod transforms;

/// Section 3.9's field layout, as a builder the reader's own tests drive.
/// Test-only: no shipped build holds code that emits a filter record.
#[cfg(test)]
mod builder;

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
#[allow(unused_imports)] // Used across this package's tests and spec H1's.
pub(crate) use builder::{stand_in, stand_in_program, BodyBits, Params, RecordBuilder, RecordSink};
#[allow(unused_imports)] // FilteredSpan: named by the decoders of specs H and I.
pub(crate) use record::{
    longest_span, FilterState, FilteredSpan, MemberBounds, RecordBytes, SpanBytes, SLOTS_AT_MOST,
    STAGE_SPAN, WAITING_AT_MOST,
};
#[allow(unused_imports)] // Called by the decoders of specs H and I, and spec G's writer.
pub(crate) use transforms::{
    audio_decode, audio_encode, delta_decode, delta_encode, rgb_decode, rgb_encode,
};

/// The six programs a RAR 3 record can name, in the order of section
/// 3.4's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum StandardProgram {
    /// Interleaved byte channels, section 3.7.1.
    Delta,
    /// x86 near calls (`E8`), SPEC-C Part 3.
    X86Call,
    /// x86 near calls and jumps (`E8`, `E9`), SPEC-C Part 3.
    X86CallJump,
    /// IA-64 branches, SPEC-C Part 5.
    Itanium,
    /// Three-channel image rows, section 3.7.2.
    Rgb,
    /// Adaptive per-channel predictor, section 3.7.3.
    Audio,
}

/// One row of section 3.4's table: a standard program is known by the
/// count of its bytes and their CRC32, and by nothing else about them
/// but a zero XOR, which the record reader asks for. The two numbers are
/// facts about the format, the way a header field's width is; the bytes
/// they are numbers OF are not in this crate.
struct Row {
    /// `k`, the count of program bytes.
    bytes: u32,
    /// `C`, the CRC32 of those bytes.
    crc32: u32,
    program: StandardProgram,
}

/// Section 3.4's table. The rows stand in ascending order of `k`, the
/// first part of the key (rule T1): 29, 53, 57, 120, 149, 216. The six
/// values of `k` all differ, so no definition can match two rows and the
/// answer is the same in any order; the order says nothing about which
/// program is commoner or older, and nothing here depends on it.
const ROWS: [Row; 6] = [
    Row {
        bytes: 29,
        crc32: 0x0e06_077d,
        program: StandardProgram::Delta,
    },
    Row {
        bytes: 53,
        crc32: 0xad57_6887,
        program: StandardProgram::X86Call,
    },
    Row {
        bytes: 57,
        crc32: 0x3cd7_e57e,
        program: StandardProgram::X86CallJump,
    },
    Row {
        bytes: 120,
        crc32: 0x3769_893f,
        program: StandardProgram::Itanium,
    },
    Row {
        bytes: 149,
        crc32: 0x1c2c_5dc8,
        program: StandardProgram::Rgb,
    },
    Row {
        bytes: 216,
        crc32: 0xbc85_e701,
        program: StandardProgram::Audio,
    },
];

impl StandardProgram {
    /// This program's key in section 3.4's table: the count of its bytes
    /// and their CRC32.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn fingerprint(self) -> (u32, u32) {
        ROWS.iter()
            .find(|row| row.program == self)
            .map(|row| (row.bytes, row.crc32))
            .expect("section 3.4's table has a row for each of the six")
    }
}

/// Section 3.4's rule, less its XOR: the standard program whose row has
/// this count of bytes and this CRC32, or `None` where no row has both.
/// A definition is that program only if the XOR of its bytes is zero as
/// well, which the record reader holds it to.
pub(crate) fn identify(len: u32, crc32: u32) -> Option<StandardProgram> {
    ROWS.iter()
        .find(|row| (row.bytes, row.crc32) == (len, crc32))
        .map(|row| row.program)
}

/// The seam of spec G section 3.14.7, closed: no filter record is written.
///
/// A filter record that DEFINES a program carries that program's bytes,
/// and the six standard programs' bytes are RARLAB's, so no target this
/// crate writes emits a filter record of any kind. Spec G 3.14.7 offered
/// to resolve [`FilterPolicy::Detect`] to `Off` silently for the RAR 4
/// family; a caller that asked for filters and got none would have no way
/// to tell, so the request is REFUSED instead, with 3.14.9's error kind
/// and before any output. RAR 5's filters are spec H3's and are untouched.
pub(crate) fn refuse_written_filters(format: WriteFormat, filters: FilterPolicy) -> Result<()> {
    match (format, filters) {
        (WriteFormat::Rar4(_), FilterPolicy::Detect) => Err(Error::new(ErrorKind::Unsupported(
            Unsupported::WriteFeature(
                "a RAR 4 archive is written without filter records; \
                 set WriteOptions::filters to FilterPolicy::Off",
            ),
        ))),
        _ => Ok(()),
    }
}
