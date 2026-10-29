//! Finding a RAR 5 inline recovery record in a volume (spec L 3.5.5).
//!
//! The header chain may be unreadable - that is the case
//! `recovery::repair_inline` exists for - so the record is found by
//! scanning for its marker through positional reads of a bounded window,
//! never holding the volume. Every candidate is validated in full before it
//! is believed, and the total bytes hashed while validating is capped, so a
//! crafted volume of overlapping markers each declaring a long record costs
//! linear time rather than quadratic.

use std::collections::HashMap;

use crate::memory::MemoryPolicy;
use crate::recovery::io::{length, read_at_most, read_exact_at};
use crate::recovery::rr5::{self, Candidate, Record, Rr5Plan, GROUP_MAX, MARKER};
use crate::source::RangeSource;
use crate::{Error, ErrorKind, RecoveryFailure, Result};

/// Bytes read per positional scan window.
const WINDOW: usize = 1 << 20;
/// The floor on the hashing budget (spec L 3.5.5).
const HASH_FLOOR: u64 = 16 << 20;
/// Records one scan keeps. A record costs tens of bytes, and the hashing
/// budget alone would let a crafted volume of minimum-length records fill
/// memory with them; nothing real comes close to this many (a 64 GiB
/// volume at `k = 200` and ten rows has about 52,000).
const MAX_RECORDS: usize = 1 << 18;

/// What a scan found.
#[derive(Debug, Clone)]
pub(crate) struct Found {
    /// The geometry every surviving record agrees on.
    pub(crate) plan: Rr5Plan,
    /// The surviving records, each with the group its POSITION gives it,
    /// at most one per (row, group).
    pub(crate) records: Vec<Record>,
}

impl Found {
    /// The distinct recovery rows that survive for `group`, ascending.
    // Repair takes every group's rows at once (`rows_by_group`); this
    // single-group form stays for the callers that judge one group.
    #[allow(dead_code)]
    pub(crate) fn rows_for(&self, group: u64) -> Vec<u16> {
        let mut rows: Vec<u16> = self
            .records
            .iter()
            .filter(|r| r.group == group)
            .map(|r| r.row)
            .collect();
        rows.sort_unstable();
        rows.dedup();
        rows
    }

    /// The distinct recovery rows that survive for each group, ascending,
    /// indexed by group: one pass over the records.
    pub(crate) fn rows_by_group(&self) -> Vec<Vec<u16>> {
        let groups = usize::try_from(self.plan.group_count).unwrap_or(0);
        let mut rows = vec![Vec::new(); groups];
        for record in &self.records {
            if let Some(slot) = rows.get_mut(record.group as usize) {
                slot.push(record.row);
            }
        }
        for slot in &mut rows {
            slot.sort_unstable();
            slot.dedup();
        }
        rows
    }

    /// The record holding row `row` of `group`.
    pub(crate) fn record(&self, row: u16, group: u64) -> Option<&Record> {
        self.records
            .iter()
            .find(|r| r.row == row && r.group == group)
    }
}

/// Find `src`'s inline recovery record.
///
/// The headers first (spec L 3.5.5: "with the main header readable, the
/// locator names the `RR` header"): when the main header passes its own
/// check and its locator, or failing a locator the header chain, leads to
/// a service header named `RR` that passes ITS check, the records are
/// walked where that header's data area says they are, and the protected
/// bytes are not read. Only when the headers do not lead there, or the
/// records they lead to do not anchor, is the whole volume scanned for
/// markers. The walk and the scan validate every
/// record the same way and hand the same `anchor` what they found, so a
/// volume whose record area the scan would have found is repaired from
/// the same records either way; the walk just does not read the protected
/// bytes to get there.
///
/// Either way a set of records is believed only where it is `src`'s OWN
/// (3.5.5, "Whose records they are"; `stands_as_own`): the marker scan
/// reads member data too, and a stored member that is itself an archive
/// with a record holds a whole valid set that describes another file.
pub(crate) fn scan(src: &dyn RangeSource, _policy: &MemoryPolicy) -> Result<Found> {
    let volume = length(src);
    let mut budget = Budget {
        cap: (volume.saturating_mul(4)).max(HASH_FLOOR),
        hashed: 0,
    };
    if let Some(area) = record_area(src, volume) {
        let mut found = Vec::new();
        walk(src, area, &mut budget, &mut found)?;
        let anchored = anchor(found, &mut |records, start| {
            stands_as_own(src, volume, &mut budget, records, start)
        });
        if let Ok(anchored) = anchored {
            return Ok(anchored);
        }
    }
    let mut found = Vec::new();
    scan_range(src, 0..volume, &mut budget, &mut found)?;
    anchor(found, &mut |records, start| {
        stands_as_own(src, volume, &mut budget, records, start)
    })
}

/// The bytes hashed while validating, against the cap of 3.5.5. One
/// budget covers the walk and any scan after it.
struct Budget {
    cap: u64,
    hashed: u64,
}

impl Budget {
    /// Charge `len` bytes, or say the budget is spent (and charge nothing).
    fn take(&mut self, len: u64, found: usize) -> bool {
        if self.hashed.saturating_add(len) > self.cap || found >= MAX_RECORDS {
            return false;
        }
        self.hashed += len;
        true
    }
}

/// The largest block header the locator path reads. The two it reads, the
/// main header and the `RR` service header, are tens of bytes; a declared
/// size past this is not believed and the scan takes over.
const LOCATED_HEAD_MAX: u64 = 1 << 20;

/// The data area of the volume's `RR` service header, found without
/// reading the protected bytes, or `None` for the scan to take over.
///
/// The RAR 5 signature must open the volume and the main header after it
/// must pass its CRC32. Then the main header's locator, when it carries a
/// recovery offset, names the `RR` header directly (reference `rar` writes
/// one on every archive with a record). Without that offset (rarkit's own
/// writer writes none yet) the header chain is followed from the main
/// header, each header checked against its CRC32 and each data area
/// stepped over unread, to the `RR` header or the end header. Either way
/// the `RR` header must pass its CRC32, be a service header named `RR`
/// with a data area, and lie inside the volume. `None` at the first link
/// that fails, and for a volume whose headers are enciphered.
pub(crate) fn record_area(src: &dyn RangeSource, volume: u64) -> Option<std::ops::Range<u64>> {
    use crate::read::block::Fields;
    use crate::read::detect::SIG_RAR5;
    use crate::read::rar5::{self as r5, TYPE_END, TYPE_MAIN};

    let mut signature = [0u8; 8];
    read_exact_at(src, 0, &mut signature).ok()?;
    if signature[..] != *SIG_RAR5 {
        return None;
    }
    let sig_end = SIG_RAR5.len() as u64;
    let (main_common, main_head) = located_head(src, sig_end, volume)?;
    if main_common.btype != TYPE_MAIN {
        return None;
    }
    let Fields::Main(main) = r5::parse_main(&main_head, &main_common, sig_end).ok()? else {
        return None;
    };
    if let Some(rr_at) = main.locator.and_then(|locator| locator.recovery) {
        let (common, head) = located_head(src, rr_at, volume)?;
        return rr_data_area(&common, &head, rr_at, volume);
    }
    let mut at = next_block(&main_common, sig_end)?;
    while at < volume {
        let (common, head) = located_head(src, at, volume)?;
        if let Some(area) = rr_data_area(&common, &head, at, volume) {
            return Some(area);
        }
        if common.btype == TYPE_END {
            return None;
        }
        at = next_block(&common, at)?;
    }
    None
}

/// What the volume's main header says about a recovery record (spec L
/// 3.5.5 O5; API spec section 9): see
/// [`crate::recovery::MainHeaderRecord`].
pub(crate) fn main_header_record(src: &dyn RangeSource) -> crate::recovery::MainHeaderRecord {
    use crate::read::block::Fields;
    use crate::read::detect::SIG_RAR5;
    use crate::read::rar5::{self as r5, TYPE_MAIN};
    use crate::recovery::MainHeaderRecord as Says;

    let volume = length(src);
    let mut signature = [0u8; 8];
    if read_exact_at(src, 0, &mut signature).is_err() || signature[..] != *SIG_RAR5 {
        return Says::NoMainHeader;
    }
    // Enciphered headers (O6): no main header stands in the clear,
    // whether or not the encryption header passes its own check.
    if headers_enciphered(src) {
        return Says::NoMainHeader;
    }
    let sig_end = SIG_RAR5.len() as u64;
    let Some((common, head)) = located_head(src, sig_end, volume) else {
        return Says::Corrupt;
    };
    if common.btype != TYPE_MAIN {
        return Says::NoMainHeader;
    }
    match r5::parse_main(&head, &common, sig_end) {
        Ok(Fields::Main(main)) if main.recovery => Says::Present,
        Ok(Fields::Main(_)) => Says::Absent,
        _ => Says::Corrupt,
    }
}

/// Where the block after the one at `at` starts.
fn next_block(common: &crate::read::rar5::Common, at: u64) -> Option<u64> {
    let data = if common.flags & crate::read::rar5::HF_DATA != 0 {
        common.data_size
    } else {
        0
    };
    at.checked_add(common.head_len as u64)?.checked_add(data)
}

/// The data area of the header at `at`, if it is the `RR` service header.
fn rr_data_area(
    common: &crate::read::rar5::Common,
    head: &[u8],
    at: u64,
    volume: u64,
) -> Option<std::ops::Range<u64>> {
    use crate::read::block::FileHdr;
    use crate::read::rar5::{self as r5, TYPE_SERVICE};

    if common.btype != TYPE_SERVICE || common.flags & r5::HF_DATA == 0 {
        return None;
    }
    let from = at.checked_add(common.head_len as u64)?;
    let mut fields = FileHdr::empty();
    let name = r5::parse_file_into(head, common, from, &mut fields).ok()?;
    if head.get(name)? != b"RR" {
        return None;
    }
    let to = from.checked_add(common.data_size)?;
    (to <= volume).then_some(from..to)
}

/// One RAR 5 block header at `at`, read and checked against its own CRC32.
fn located_head(
    src: &dyn RangeSource,
    at: u64,
    volume: u64,
) -> Option<(crate::read::rar5::Common, Vec<u8>)> {
    use crate::read::rar5 as r5;
    // The CRC field, then a size vint of at most three bytes for any size
    // under `LOCATED_HEAD_MAX`.
    let mut prefix = [0u8; 7];
    let got = read_at_most(src, at, &mut prefix).ok()?;
    let mut size_at = 4usize;
    let size = crate::read::vint::read(&prefix[..got], &mut size_at)?;
    let head_len = (size_at as u64).checked_add(size)?;
    if size == 0 || head_len > LOCATED_HEAD_MAX || at.checked_add(head_len)? > volume {
        return None;
    }
    let mut head = vec![0u8; head_len as usize];
    read_exact_at(src, at, &mut head).ok()?;
    let common = r5::parse_common(&head).ok()?;
    (r5::header_checksum(&head) == common.crc).then_some((common, head))
}

/// Whether the set `records`, its data area starting at `start`, is
/// `src`'s OWN (spec L 3.5.5, rules O1, O1b, O1c, O6 and O7).
///
/// 3.5.1 gives what an own set rests on: its protected length `P` is the
/// file offset of the `RR` service header, and its table fits the file's
/// bytes from byte 0. A set that an archive stored inside this one
/// carries describes a file that begins further on, and is never applied
/// (O2). A set is own:
///
/// - **By its header (O1)**: the bytes at `P` are a RAR 5 service header
///   that ends where the data area starts; its CRC32 failing, its size
///   and type fields must still say so, which is all a passing CRC32 adds
///   to them here. A start a whole number of group records past that
///   end, inside row 0, counts too: that is every group 0 record lost,
///   and `anchor`'s ambiguity rule is what answers for it.
/// - **Behind an enciphered header (O6)**, in place of O1 and only in a
///   volume whose headers are enciphered (`headers_enciphered`): what
///   stands at `P` is an initialisation vector and the `RR` header in
///   whole cipher blocks, so the data area starts 16 bytes and at least
///   one 16-byte block past `P`. No key is asked for. In a clear volume
///   this distance is never asked: a carried set's is whatever the outer
///   layout makes it, and could be that by chance.
/// - **By shard 0 (O1b)**, in either kind of volume: entry 0 of the
///   set's table is the CRC-64 of the file's first shard. One shard, and
///   that one: the file begins with its own signature and headers, which
///   a carried set's shard 0 never is, while a count of fitting shards
///   tells the two apart in neither direction.
/// - **By distance (O1c)**, in either kind of volume: the data area
///   starts no more than [`OWN_GAP_MAX`] bytes behind `P`. An own set's
///   distance is the length of its own `RR` header; a carried set's is
///   that and the offset the stored archive begins at. It asks nothing
///   of the bytes at `P` nor of shard 0, so it holds where both are
///   damaged.
///
/// There is no other way (O7): a data area with no header before it is
/// own by shard 0 or by its distance, which is 0. Past these, nothing
/// says whose the records are, and the answer is no, never a guess.
fn stands_as_own(
    src: &dyn RangeSource,
    volume: u64,
    budget: &mut Budget,
    records: &[Record],
    start: u64,
) -> bool {
    let plan = &records[0].plan;
    let Some(gap) = start.checked_sub(plan.protected) else {
        return false;
    };
    let by_place = if headers_enciphered(src) {
        gap >= 32 && gap.is_multiple_of(16)
    } else {
        header_end(src, plan.protected, volume)
            .and_then(|area| start.checked_sub(area))
            .and_then(|shift| decompose(plan, shift))
            .is_some_and(|(row, _)| row == 0)
    };
    by_place || gap <= OWN_GAP_MAX || shard_0_fits(src, budget, records)
}

/// The greatest distance from a set's `P` to its data area at which the
/// set is own by that alone (spec L 3.5.5 O1c). It is the longest `RR`
/// service header its fields allow: 18 bytes and three vints, two sizes
/// of at most ten bytes each and a percentage of at most two. A set
/// carried in a stored member stands at least 51 bytes from its `P`: a
/// signature, a main header and the member's own file header come to 33
/// at the least, and the carried archive's `RR` header to 18.
const OWN_GAP_MAX: u64 = 40;

/// Whether the block right behind the signature is an archive encryption
/// header (spec L 3.5.5 O6, point 1): its type field reads 4, which is
/// what a passing CRC32 and a failing one both leave to ask. The
/// signature itself is not read: the reference mends such a volume with
/// a signature bit changed, and this is what lets it.
fn headers_enciphered(src: &dyn RangeSource) -> bool {
    use crate::read::detect::SIG_RAR5;
    use crate::read::rar5::TYPE_ENCRYPTION;

    // The CRC field, a size vint of at most three bytes, then the type.
    let mut prefix = [0u8; 8];
    let Ok(got) = read_at_most(src, SIG_RAR5.len() as u64, &mut prefix) else {
        return false;
    };
    let mut next = 4usize;
    crate::read::vint::read(&prefix[..got], &mut next).is_some()
        && crate::read::vint::read(&prefix[..got], &mut next) == Some(TYPE_ENCRYPTION)
}

/// Where the RAR 5 service header at `at` ends, by its size and type
/// fields, or `None` when they do not say it is one.
fn header_end(src: &dyn RangeSource, at: u64, volume: u64) -> Option<u64> {
    use crate::read::rar5::TYPE_SERVICE;

    // The CRC field, a size vint of at most three bytes, then the type.
    let mut prefix = [0u8; 8];
    let got = read_at_most(src, at, &mut prefix).ok()?;
    let mut next = 4usize;
    let size = crate::read::vint::read(&prefix[..got], &mut next)?;
    let head_len = (next as u64).checked_add(size)?;
    let btype = crate::read::vint::read(&prefix[..got], &mut next)?;
    let end = at.checked_add(head_len)?;
    (size != 0 && head_len <= LOCATED_HEAD_MAX && end <= volume && btype == TYPE_SERVICE)
        .then_some(end)
}

/// Whether entry 0 of the set's table is the CRC-64 of `src`'s first
/// shard: the file's bytes from 0, as far as a group 0 record's slice of
/// shard 0 runs (3.5.5 O1b). A set with no group 0 record left has no
/// table over the file's first bytes and does not fit. The bytes hashed
/// are charged to the scan's budget, since a crafted volume can hold as
/// many sets as records.
fn shard_0_fits(src: &dyn RangeSource, budget: &mut Budget, records: &[Record]) -> bool {
    let Some(record) = records.iter().find(|record| record.group == 0) else {
        return false;
    };
    let (at, real) = slice(&record.plan, 0, 0);
    if at != 0 || !budget.take(real, 0) {
        return false;
    }
    let Ok(table) = rr5::read_table(src, record) else {
        return false;
    };
    let mut first = vec![0u8; real as usize];
    if read_exact_at(src, 0, &mut first).is_err() {
        return false;
    }
    let mut register = crate::checksum::crc64::Crc64Register::new();
    register.update(&first);
    table.first() == Some(&register.state())
}

/// Walk the records of a known record area in order, each starting where
/// the last one ended, reading each once. At the first bytes that are not
/// a valid record the walk resyncs by scanning the rest of the area for
/// markers, so one damaged record costs the records behind it nothing.
fn walk(
    src: &dyn RangeSource,
    area: std::ops::Range<u64>,
    budget: &mut Budget,
    found: &mut Vec<Record>,
) -> Result<()> {
    let mut body: Vec<u8> = Vec::new();
    let mut at = area.start;
    while area.end - at >= u64::from(rr5::HEADER_BASE) {
        let mut head = [0u8; rr5::HEADER_BASE as usize];
        read_exact_at(src, at, &mut head)?;
        let Some(candidate) = Candidate::parse(&head) else {
            break;
        };
        if candidate.plan.protected > at || at.saturating_add(candidate.len) > area.end {
            break;
        }
        if !budget.take(candidate.len, found.len()) {
            return Ok(());
        }
        body.clear();
        body.resize(candidate.len as usize, 0);
        read_exact_at(src, at, &mut body)?;
        let Some(record) = rr5::finish(&candidate, &body, at, candidate.declared_group) else {
            break;
        };
        found.push(record);
        at += candidate.len;
    }
    if at < area.end {
        scan_range(src, at + 1..area.end, budget, found)?;
    }
    Ok(())
}

/// Scan `range` of `src` for records by their marker, through positional
/// reads of a bounded window; a record must lie wholly inside `range`.
fn scan_range(
    src: &dyn RangeSource,
    range: std::ops::Range<u64>,
    budget: &mut Budget,
    found: &mut Vec<Record>,
) -> Result<()> {
    let end = range.end;
    // One window, one record buffer: the only per-volume allocations.
    let mut window = vec![0u8; WINDOW];
    let mut body: Vec<u8> = Vec::new();

    let mut at = range.start;
    'windows: while at < end {
        let want = (end - at).min(WINDOW as u64) as usize;
        let got = read_at_most(src, at, &mut window[..want])?;
        if got < MARKER.len() {
            break;
        }
        let mut search = 0usize;
        while let Some(hit) = memchr::memmem::find(&window[search..got], &MARKER) {
            let offset = at + (search + hit) as u64;
            search += hit + 1;
            // The record's fixed fields, then its whole body.
            let mut head = [0u8; rr5::HEADER_BASE as usize];
            if read_at_most(src, offset, &mut head)? < head.len() {
                continue;
            }
            let Some(candidate) = Candidate::parse(&head) else {
                continue;
            };
            if candidate.plan.protected > offset || offset.saturating_add(candidate.len) > end {
                continue;
            }
            if !budget.take(candidate.len, found.len()) {
                // Past the budget the scan stops with what it has.
                break 'windows;
            }
            body.clear();
            body.resize(candidate.len as usize, 0);
            read_exact_at(src, offset, &mut body)?;
            let group = candidate.declared_group;
            let Some(record) = rr5::finish(&candidate, &body, offset, group) else {
                continue;
            };
            found.push(record);
            // A record that checked out is believed: resume after it, in
            // this window or in a later one.
            let after = offset + candidate.len;
            if after >= at + got as u64 {
                at = after;
                continue 'windows;
            }
            search = (after - at) as usize;
        }
        // Overlap by one less than the marker, so a marker straddling two
        // windows is still seen.
        at += (got - (MARKER.len() - 1)) as u64;
    }
    Ok(())
}

/// Turn validated records into a layout, or refuse (spec L 3.5.5).
///
/// `own` answers whether a set, its data area starting where its records
/// imply, is the volume's own (`stands_as_own`). A set that is not is
/// never applied, however many records it has (3.5.5 O2); the choice is
/// among own sets (O3); and with none the volume has no record (O4).
fn anchor(found: Vec<Record>, own: &mut dyn FnMut(&[Record], u64) -> bool) -> Result<Found> {
    let no_record = || Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord));
    if found.is_empty() {
        return Err(no_record());
    }
    // Records that disagree about the geometry cannot be the same record.
    // Of the sets that are this volume's own the largest agreeing one
    // wins; a tie goes to the one that anchors earliest, which is the same
    // rule the start itself follows.
    let mut by_plan: HashMap<(u16, u16, u64, u64), Vec<Record>> = HashMap::new();
    for record in found {
        let plan = record.plan;
        by_plan
            .entry((plan.k, plan.m, plan.shard_len, plan.protected))
            .or_default()
            .push(record);
    }
    let mut groups: Vec<Vec<Record>> = by_plan.into_values().collect();
    groups.sort_by_key(|records| {
        (
            std::cmp::Reverse(records.len()),
            records.iter().map(|r| r.offset).min().unwrap_or(0),
        )
    });
    // The smallest data-area start a set's records imply, at or after its
    // protected length.
    let implied_start = |records: &[Record]| -> Option<u64> {
        let plan = records[0].plan;
        records
            .iter()
            .filter_map(|record| {
                record
                    .offset
                    .checked_sub(plan.position(record.row, record.group))
                    .filter(|&start| start >= plan.protected)
            })
            .min()
    };
    let (records, start) = groups
        .into_iter()
        .find_map(|records| {
            let start = implied_start(&records)?;
            own(&records, start).then_some((records, start))
        })
        .ok_or_else(no_record)?;
    let plan = records[0].plan;

    let explained = |base: u64| -> usize {
        records
            .iter()
            .filter(|record| {
                record
                    .offset
                    .checked_sub(base)
                    .and_then(|relative| decompose(&plan, relative))
                    .is_some_and(|(row, group)| {
                        row == record.row
                            && record.len - u64::from(plan.header) == plan.group_len(group)
                    })
            })
            .count()
    };
    let here = explained(start);

    // Ambiguity (3.5.5): if the same records are explained just as well by
    // a start a whole number of group boundaries earlier, then every
    // group-0 record is gone and there is no way to tell which group's
    // parity these records hold. Repairing one group from another group's
    // parity would write plausible wrong bytes, so the scan refuses.
    for skipped in 1..plan.group_count {
        let Some(earlier) = start.checked_sub(plan.group_prefix(skipped)) else {
            break;
        };
        // The shift grows with every group, so once it has passed `P` no
        // later one can come back inside.
        if earlier < plan.protected {
            break;
        }
        if explained(earlier) >= here {
            return Err(Error::new(ErrorKind::Recovery(
                RecoveryFailure::RecoveryDamaged,
            )));
        }
    }

    // Keep what the chosen start explains, with the group its POSITION
    // gives it, one record per (row, group).
    let mut kept: Vec<Record> = Vec::new();
    for mut record in records {
        let Some((row, group)) = record
            .offset
            .checked_sub(start)
            .and_then(|relative| decompose(&plan, relative))
        else {
            continue;
        };
        if row != record.row || record.len - u64::from(plan.header) != plan.group_len(group) {
            continue;
        }
        record.group = group;
        if kept.iter().any(|k| k.row == row && k.group == group) {
            continue;
        }
        kept.push(record);
    }
    if kept.is_empty() {
        return Err(Error::new(ErrorKind::Recovery(
            RecoveryFailure::RecoveryDamaged,
        )));
    }
    kept.sort_by_key(|r| r.offset);
    Ok(Found {
        plan,
        records: kept,
    })
}

/// The (row, group) a position `relative` to the data area's start would
/// hold, if any.
///
/// Every group's record starts a fixed stride apart, because a group's
/// prefix is `g * (H + 65,536)` for every valid `g`: only the LAST group
/// is shorter than 64 KiB, and nothing follows it inside its own row. So
/// this is arithmetic, not a table - which matters, because `m` and the
/// group count are both taken from an untrusted header and a table of
/// their product would be an allocation sized by declared fields.
fn decompose(plan: &Rr5Plan, relative: u64) -> Option<(u16, u64)> {
    let row = u16::try_from(relative / plan.span).ok()?;
    if row >= plan.m {
        return None;
    }
    let stride = u64::from(plan.header) + GROUP_MAX;
    let within = relative % plan.span;
    if !within.is_multiple_of(stride) {
        return None;
    }
    let group = within / stride;
    (group < plan.group_count).then_some((row, group))
}

/// Where a record's parity bytes sit in the volume.
pub(crate) fn parity_at(record: &Record) -> u64 {
    record.offset + u64::from(record.plan.header)
}

/// A group's window inside a shard, and how much of shard `j` is real
/// there. Slices never cross a shard edge and never run past `P`.
pub(crate) fn slice(plan: &Rr5Plan, j: u16, group: u64) -> (u64, u64) {
    let start = group * GROUP_MAX;
    let len = plan.group_len(group);
    let real = plan.shard_real(j).saturating_sub(start).min(len);
    (u64::from(j) * plan.shard_len + start, real)
}

/// The whole-volume marker scan alone, which is what `scan` did before it
/// read the headers first: the arm the header path is held to.
#[cfg(test)]
pub(crate) fn scan_whole(src: &dyn RangeSource) -> Result<Found> {
    let volume = length(src);
    let mut budget = Budget {
        cap: (volume.saturating_mul(4)).max(HASH_FLOOR),
        hashed: 0,
    };
    let mut found = Vec::new();
    scan_range(src, 0..volume, &mut budget, &mut found)?;
    anchor(found, &mut |records, start| {
        stands_as_own(src, volume, &mut budget, records, start)
    })
}

#[cfg(all(test, feature = "repo-tests"))]
mod tests {
    use super::*;

    /// `rr5_small.rar`, reference `rar` 7.23 output: two records, one
    /// group, the `RR` data area at 40,241 (spec L 5.4).
    fn small() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/vectors-L/rr5_small.rar"
        );
        std::fs::read(path).expect("spec L vector")
    }

    const AREA: std::ops::Range<u64> = 40_241..40_241 + 2 * 1_398;

    #[test]
    fn the_reference_locator_names_the_record_area() {
        let file = small();
        assert_eq!(record_area(&file, file.len() as u64), Some(AREA));
        let located = scan(&file, &crate::memory::repair_only(u64::MAX)).unwrap();
        assert_eq!(located.records, scan_whole(&file).unwrap().records);
        assert_eq!(located.records.len(), 2);
    }

    #[test]
    fn a_main_header_failing_its_check_falls_back_to_the_scan() {
        let mut file = small();
        file[14] ^= 0x40;
        assert_eq!(record_area(&file, file.len() as u64), None);
        let found = scan(&file, &crate::memory::repair_only(u64::MAX)).unwrap();
        assert_eq!(found.records, scan_whole(&file).unwrap().records);
        assert_eq!(found.records.len(), 2);
    }

    #[test]
    fn a_damaged_first_record_costs_the_walk_that_record_alone() {
        for at in [AREA.start, AREA.start + 0x3A, AREA.start + 700] {
            let mut file = small();
            file[at as usize] ^= 0x01;
            assert_eq!(record_area(&file, file.len() as u64), Some(AREA));
            let found = scan(&file, &crate::memory::repair_only(u64::MAX)).unwrap();
            assert_eq!(found.records, scan_whole(&file).unwrap().records, "at {at}");
            assert_eq!(found.records.len(), 1, "at {at}");
            assert_eq!(found.records[0].row, 1, "at {at}");
        }
    }

    #[test]
    fn a_locator_past_the_volume_is_not_followed() {
        let file = small();
        let short = &file[..AREA.start as usize + 100];
        assert_eq!(record_area(&short, short.len() as u64), None);
    }
}
