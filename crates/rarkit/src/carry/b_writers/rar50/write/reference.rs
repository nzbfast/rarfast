//! Carried from the predecessor's `rar50/write/reference.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
pub(crate) const BLOCK_TYPE_MAIN: u64 = 1;
pub(crate) const BLOCK_TYPE_FILE: u64 = 2;
pub(crate) const BLOCK_TYPE_SERVICE: u64 = 3;
pub(crate) const BLOCK_TYPE_END_OF_ARCHIVE: u64 = 5;
pub(crate) const BLOCK_HAS_EXTRA_AREA: u64 = 0x0001;
pub(crate) const BLOCK_HAS_DATA_AREA: u64 = 0x0002;
pub(crate) const BLOCK_SKIP_IF_UNKNOWN: u64 = 0x0004;
pub(crate) const BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME: u64 = 0x0008;
pub(crate) const BLOCK_CONTINUES_IN_NEXT_VOLUME: u64 = 0x0010;
pub(crate) const FILE_IS_DIRECTORY: u64 = 0x0001;
pub(crate) const FILE_HAS_UNIX_MTIME: u64 = 0x0002;
pub(crate) const FILE_HAS_CRC32: u64 = 0x0004;
pub(crate) const MAIN_EXTRA_LOCATOR: u64 = 0x01;
pub(crate) const LOCATOR_HAS_QUICK_OPEN_OFFSET: u64 = 0x01;
pub(crate) const LOCATOR_HAS_RECOVERY_RECORD_OFFSET: u64 = 0x02;
pub(crate) const FILE_EXTRA_HASH: u64 = 0x02;
pub(crate) const FILE_EXTRA_TIME: u64 = 0x03;
pub(crate) const TIME_RECORD_UNIX_FORMAT: u64 = 0x01;
pub(crate) const TIME_RECORD_HAS_MTIME: u64 = 0x02;
pub(crate) const TIME_RECORD_UNIX_NANOSECONDS: u64 = 0x10;
/// Unix epoch as a Windows FILETIME: 100-nanosecond ticks from
/// 1601-01-01 to 1970-01-01.
pub(crate) const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
pub(crate) const ARCHIVE_IS_VOLUME: u64 = 0x0001;
pub(crate) const ARCHIVE_HAS_VOLUME_NUMBER: u64 = 0x0002;
/// The main header's "this archive carries a recovery record" bit, which
/// `rr` sets and `a -rr` sets for the same reason.
pub(crate) const ARCHIVE_HAS_RECOVERY_RECORD: u64 = 0x0008;
pub(crate) const END_OF_ARCHIVE_NOT_LAST_VOLUME: u64 = 0x0001;
/// Data larger than this gets its header cached in the quick-open block.
///
/// Measured: a lone 4096-byte member produces no `QO` block at all and a
/// 4097-byte one does, and in a two-member archive only the large member
/// is cached. So the test is per member and on its data size, not on the
/// size of the archive.
pub(crate) const QUICK_OPEN_MIN_DATA: usize = 4096;
/// The signature every RAR 5 archive opens with.
pub const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
/// Writes `value` in EXACTLY `width` bytes, padding with continuation
/// bytes that carry no bits.
///
/// This is the shape the reference uses wherever it has to patch a field
/// after the fact, and wherever it writes a size it did not know when the
/// header was laid out. A decoder cannot tell the two apart - a vint is
/// read until a byte without the top bit - so the padding is invisible to
/// everything except a byte comparison, which is exactly what the
/// conformance table does.
pub(crate) fn write_vint_padded(out: &mut Vec<u8>, value: u64, width: usize) {
    // AT LEAST `width` bytes, never exactly: a value that needs more takes
    // more, as the reference's does. Until 14 Sep 2026 this wrote exactly
    // `width` and silently dropped the high bits, so a quick-open block
    // whose data ran past 16,383 bytes (about 190 cached headers under
    // `-qo+`, or a few hundred members over 4 KiB under the default) carried
    // a data size of `len & 0x3fff`, and the reference unrar answered
    // "Corrupt header is found" on `t` and `x` while `l` still listed the
    // members. Found by the project bench's create-small-m0 leg.
    let width = width.max(vint_width(value));
    let mut left = value;
    for _ in 0..width.saturating_sub(1) {
        out.push(((left & 0x7f) as u8) | 0x80);
        left >>= 7;
    }
    out.push((left & 0x7f) as u8);
}
/// How many bytes a plain vint of `value` needs.
pub(crate) fn vint_width(value: u64) -> usize {
    let mut width = 1;
    let mut left = value >> 7;
    while left != 0 {
        width += 1;
        left >>= 7;
    }
    width
}
