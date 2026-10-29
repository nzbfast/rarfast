//! One rewrite, behind every `edit` entry point (spec G 3.15, extended to
//! the member-level rewrite the section names as not yet done).
//!
//! A rewrite opens an archive, decides what each of its blocks becomes,
//! and writes a NEW archive. Member data is never decoded and never
//! recompressed: a member that survives is copied byte for byte, and a
//! member that is RENAMED keeps its data bytes and every header field but
//! the name (`super::header`).
//!
//! **Two passes, because three blocks point at each other.** The main
//! header's locator record carries the offsets of the quick-open block
//! and the recovery record; the quick-open block carries the distance
//! back from itself to each cached header; and the recovery record covers
//! every byte before it. None of the three can be written until the
//! layout is settled, so the first pass settles it - what each block
//! becomes and where it lands - and the second writes the bytes. The
//! first pass reads only headers.
//!
//! **Nothing is written in place.** The library writes a fresh output and
//! never touches the original, so a failed edit at any stage loses
//! nothing and the caller decides when to replace the file.

use std::io::Write;
use std::ops::Range;

use crate::checksum::crc32;
use crate::error::Error;
use crate::read::{BlockKind, ServiceKind};
use crate::write::consts::*;
use crate::write::options::COPY_CHUNK;
use crate::write::rar5::Reserve;
use crate::write::{rar4, rar5};
use crate::{Archive, Format, Result};

use super::header;

/// The RAR 4 marker block's type byte, as the reader reports it.
const RAR4_MARKER_TYPE: u64 = 0x72;

/// The RAR 2.x old sub block's type byte, as the reader reports it.
const RAR4_OLD_SUB_TYPE: u64 = 0x77;

/// Data larger than this earns a cached header in the quick-open block
/// (spec G 3.6.6, measured per member: 4,096 earns none and 4,097 does).
const QUICK_OPEN_MIN_DATA: u64 =
    crate::carry::b_writers::rar50::write::reference::QUICK_OPEN_MIN_DATA as u64;

/// What one rewrite is asked to change. A field left `None` keeps what
/// the source archive has.
#[derive(Default)]
pub(crate) struct Edit<'a> {
    /// `Some(None)` removes the comment, `Some(Some(_))` replaces it.
    pub(crate) comment: Option<Option<&'a [u8]>>,
    /// The lock flag.
    pub(crate) lock: Option<bool>,
    /// Members to drop, by the name the archive stores.
    pub(crate) remove: &'a [&'a [u8]],
    /// Members to rename, old name to new.
    pub(crate) rename: &'a [(&'a [u8], &'a [u8])],
    /// `Some(None)` drops the inline recovery record, `Some(Some(pct))`
    /// builds one over the rewritten archive.
    pub(crate) recovery: Option<Option<u32>>,
    /// The system the rewrite is made on, which the service headers it
    /// builds carry (spec G 3.3.4); `None` is the build's own.
    pub(crate) host: Option<crate::HostOs>,
}

/// What a rewrite did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EditReport {
    /// Members the output holds.
    pub members: u32,
    /// Bytes written.
    pub bytes: u64,
    /// The names that were removed, as the archive stored them.
    pub removed: Vec<Vec<u8>>,
    /// The names that were renamed, as the archive stored them before.
    pub renamed: Vec<Vec<u8>>,
    /// Names the caller asked for that the archive does not hold.
    ///
    /// A rewrite that matched nothing is NOT an error here: it writes the
    /// archive it was given, unchanged in that respect, and says so. A
    /// caller for whom a name that matched nothing is a failure - a
    /// command line tool reporting to a user, say - checks this.
    pub unmatched: Vec<Vec<u8>>,
    /// Whether the output carries a rebuilt quick-open index.
    pub quick_open: bool,
    /// Whether the output carries an inline recovery record.
    pub recovery: bool,
    /// The RAR 5 record's data shard count, `k` of SPEC-L 3.5.1; zero
    /// when no RAR 5 record was written.
    ///
    /// It is reported because it is the unit the operation makes progress
    /// in: the reference prints one counter tick per shard while it builds
    /// the record, so a caller that wants to say the same thing needs the
    /// count and cannot derive it without the protected length.
    pub recovery_shards: u32,
}

/// One piece of the output, decided in the first pass.
enum Piece {
    /// Bytes copied from the source, verbatim.
    Copy(Range<u64>),
    /// A header this rewrite built, held because it is small.
    Bytes(Vec<u8>),
}

impl Piece {
    fn len(&self) -> u64 {
        match self {
            Piece::Copy(range) => range.end - range.start,
            Piece::Bytes(bytes) => bytes.len() as u64,
        }
    }
}

/// The whole rewrite.
pub(crate) fn rewrite(src: &Archive, edit: &Edit<'_>, mut out: impl Write) -> Result<EditReport> {
    refuse_what_is_not_built(src, edit)?;

    let rar5_family = src.format() == Format::Rar5;
    let source = src.source();
    let volume = src.volume();

    // ---- what each member becomes ------------------------------------
    let names: Vec<Vec<u8>> = src.members().map(|m| m.name.to_vec()).collect();
    // Taken once: `Archive::members` is an iterator, and asking it for the
    // nth member inside the block walk made the walk quadratic in the
    // member count.
    let packed_sizes: Vec<u64> = src.members().map(|m| m.packed_size).collect();
    let mut report = EditReport::default();
    let mut drop_member = vec![false; names.len()];
    let mut new_name: Vec<Option<Vec<u8>>> = vec![None; names.len()];

    // **A name names EVERY member that stores it.** An archive may store
    // one name twice, and the reference's `d` and `rn` then take both
    // (measured on `rar` 7.x, both families, 4 Oct 2026); a rewrite that
    // took the first alone left a member of the removed name in the
    // archive and returned Ok.
    for wanted in edit.remove {
        let mut matched = false;
        for (index, _) in names.iter().enumerate().filter(|(_, n)| n == wanted) {
            drop_member[index] = true;
            matched = true;
        }
        if matched {
            report.removed.push(wanted.to_vec());
        } else {
            report.unmatched.push(wanted.to_vec());
        }
    }
    for (from, to) in edit.rename {
        crate::write::check_name(to, !rar5_family)?;
        let mut matched = false;
        for (index, _) in names.iter().enumerate().filter(|(_, n)| n == from) {
            // A member removed in the same call is not also renamed.
            if !drop_member[index] {
                new_name[index] = Some(to.to_vec());
                matched = true;
            }
        }
        if matched {
            report.renamed.push(from.to_vec());
        } else {
            report.unmatched.push(from.to_vec());
        }
    }

    // ---- pass one: the layout ----------------------------------------
    // A comment the caller names is built here. One the caller did not
    // name is NOT rebuilt from what the read decoded: `Archive::comment`
    // is `None` for a comment above the read's `max_comment`, for a codec
    // this build does not decode and for a comment that did not read, and
    // a rewrite that took that for "no comment" dropped the block and
    // returned Ok. Its BLOCK is copied instead, as it lies (`lead`
    // below), which needs nothing decoded and holds nothing.
    let comment = match edit.comment {
        Some(value) => value.map(|bytes| bytes.to_vec()),
        None => None,
    };
    let mut kept_comment = false;
    let locked = edit.lock.unwrap_or_else(|| src.is_locked());
    let recovery_percent = match edit.recovery {
        Some(value) => value,
        // An inline record is parity over the bytes of the archive AS IT
        // STOOD, so after a rewrite it protects a file that no longer
        // exists. It is rebuilt at the same percentage when the source
        // had one and the caller said nothing, and never carried across.
        None => carried_recovery_percent(src)?,
    };
    // The quick-open index is RAR 5 only and is rebuilt when the source
    // carried one, which is what the reference does: `rar d`, `rar rn`,
    // `rar k` and `rar c` all leave an index behind, resized to the
    // members the output holds (measured on `rar` 7.23, 19 Sep 2026).
    let source_had_quick_open = rar5_family
        && src
            .services()
            .any(|svc| svc.header.name == SERVICE_QUICK_OPEN);

    // What goes between the archive head and the first block of the
    // body: the source's own comment block, when this edit keeps it.
    let mut lead: Vec<Piece> = Vec::new();
    let mut body: Vec<Piece> = Vec::new();
    let mut cached: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut end_block: Option<Range<u64>> = None;
    let mut member = 0usize;
    // Whether the file block last passed was REMOVED. A block that
    // belongs to that member goes with it (`depends_on_member`): left in,
    // it would sit after a different member and a reader would give that
    // one the removed member's stream or access list.
    let mut after_removed = false;

    for block in src.blocks() {
        match block.kind {
            // Rebuilt below, in this rewrite's own order.
            BlockKind::Main => continue,
            // Spec F 3.2.9 S3: in RAR 5 the comment is a `CMT` block met
            // before any file header. One after a member is not the
            // comment, so it is not moved to the comment's place: it is
            // copied where it lies, as any other service block is.
            BlockKind::Service(ServiceKind::Comment) if !(rar5_family && member > 0) => {
                if edit.comment.is_none() {
                    lead.push(Piece::Copy(block.range.clone()));
                    kept_comment = true;
                }
                continue;
            }
            BlockKind::Service(ServiceKind::RecoveryRecord) => continue,
            BlockKind::Other(RAR4_MARKER_TYPE) => continue,
            BlockKind::End => {
                // Kept as the source wrote it, so its volume flags and
                // its set checksum survive, but moved: the quick-open
                // block and the recovery record go BEFORE it.
                end_block = Some(block.range.clone());
                continue;
            }
            BlockKind::Service(ServiceKind::Other | ServiceKind::Comment) => {
                // A quick-open index is rebuilt; any other service block
                // this crate does not model is copied through untouched.
                let head = read_head(src, &block.range)?;
                if header::is_quick_open(&head, rar5_family) {
                    continue;
                }
                // A RAR 4 family sub block that is neither the comment
                // nor the recovery record is the member's before it; a
                // RAR 5 service block says whether it is.
                if after_removed && (!rar5_family || header::rar5_depends_on_previous(&head)) {
                    continue;
                }
                body.push(Piece::Copy(block.range.clone()));
                continue;
            }
            BlockKind::File => {}
            BlockKind::Other(kind) => {
                // A RAR 5 block of a type this crate does not model says
                // whether it is the member's before it. In the RAR 4
                // family the one such type is the OLD sub block, which
                // RAR 2.x wrote after the member it describes (an owner,
                // a stream, an access list) and which says nothing: it is
                // that member's always.
                let of_removed = if rar5_family {
                    after_removed
                        && header::rar5_depends_on_previous(&read_head(src, &block.range)?)
                } else {
                    after_removed && kind == RAR4_OLD_SUB_TYPE
                };
                if of_removed {
                    continue;
                }
                body.push(Piece::Copy(block.range.clone()));
                continue;
            }
        }

        // A file block: the member the reader reported at this position.
        let index = member;
        member += 1;
        after_removed = drop_member.get(index).copied().unwrap_or(false);
        if after_removed {
            continue;
        }
        report.members += 1;

        let packed = src.members().nth(index).map(|m| m.packed_size).unwrap_or(0);
        // Saturating, because `packed` comes from a header the READER
        // parsed and a block that says it holds more data than it is long
        // must not make this slice backwards.
        let header_end = block
            .range
            .end
            .saturating_sub(packed)
            .max(block.range.start);
        let data = header_end..block.range.end;

        let header_bytes = match new_name.get(index).and_then(|n| n.clone()) {
            None => None,
            Some(name) => {
                let original = read_range(src, &(block.range.start..header_end))?;
                let spliced = if rar5_family {
                    header::rar5_renamed(&original, &name)
                } else {
                    // The caller's name is in the API's form, with `/`
                    // between components; the family stores a backslash
                    // there (spec G 3.14.5), which is what the Writer
                    // stores for the same name. `check_name` has already
                    // refused a name that holds a backslash of its own.
                    let stored: Vec<u8> = name
                        .iter()
                        .map(|byte| if *byte == b'/' { b'\\' } else { *byte })
                        .collect();
                    header::rar4_renamed(&original, &stored)
                };
                match spliced {
                    Some(bytes) => Some(bytes),
                    None => return Err(crate::write::options::refuse(
                        "renaming a member whose header is not laid out the way the format says",
                    )),
                }
            }
        };

        match header_bytes {
            None => {
                // A RAR 5 member header is RE-EMITTED in the rewrite form
                // of spec G 3.6.5 - the same header with its size field
                // in the natural width - which is what the reference does
                // to every member it re-emits and the last thing between
                // this output and the reference's own. A header this
                // crate cannot parse is copied verbatim instead, so
                // nothing is ever lost by trying.
                let rewritten = if rar5_family {
                    read_range(src, &(block.range.start..header_end))
                        .ok()
                        .and_then(|image| header::rar5_rewritten(&image))
                } else {
                    None
                };
                match rewritten {
                    Some(bytes) => body.push(Piece::Bytes(bytes)),
                    None => body.push(Piece::Copy(block.range.start..header_end)),
                }
            }
            Some(bytes) => body.push(Piece::Bytes(bytes)),
        }
        // The cached header the quick-open index will carry, if this
        // member earns one (spec G 3.6.6).
        if source_had_quick_open && packed > QUICK_OPEN_MIN_DATA {
            let image = match body.last() {
                Some(Piece::Bytes(bytes)) => bytes.clone(),
                _ => read_range(src, &(block.range.start..header_end))?,
            };
            cached.push((body.len() - 1, image));
        }
        body.push(Piece::Copy(data));
    }

    // An index with no entry in it is no index: the block is not written
    // and the locator does not claim one.
    let want_quick_open = source_had_quick_open && !cached.is_empty();
    // A comment that lives in no block of its own - the old form, inside
    // the main header of a RAR 1.5 to 2.x archive - has nothing to copy
    // and is rebuilt from what the read decoded, as it always was.
    let comment = match (edit.comment, kept_comment) {
        (None, false) => src.comment().map(|bytes| bytes.to_vec()),
        _ => comment,
    };
    let plan = Plan {
        rar5_family,
        locked,
        solid: src.is_solid(),
        volume_set: volume.is_volume,
        first_volume: volume.is_first,
        volume_number: volume.number.unwrap_or(0),
        comment: comment.as_deref(),
        recovery_percent,
        want_quick_open,
        host: edit.host.unwrap_or(BUILD_HOST),
        service_form: if source_had_quick_open {
            Reserve::Reference
        } else {
            Reserve::Natural
        },
    };

    // ---- pass one, continued: where everything lands -----------------
    // The locator's offsets are written in a FIXED width, so the main
    // header's length does not move when the offsets are filled in, and
    // the width is the reference's own (spec G 3.6.3): not the width the
    // value needs and not a function of the archive's size, but
    //
    //     estimate = sum over MEMBERS of (payload + 33 + 3 * name length)
    //     width    = vint width of (estimate * 4096)
    //
    // with service blocks contributing nothing. The members counted are
    // the ones the OUTPUT holds, which is what the reference would have
    // counted had it written this archive.
    let width = locator_width(src, &drop_member, &new_name);

    let head = plan.head_bytes(width, 0, 0);
    let head_len = head.len();
    let mut at = head.len() as u64 + lead.iter().map(Piece::len).sum::<u64>();
    let mut offsets: Vec<u64> = Vec::with_capacity(body.len());
    for piece in &body {
        offsets.push(at);
        at += piece.len();
    }

    // The quick-open block, whose entries are the distance BACK from the
    // block's own start to each cached header (spec G 3.6.6).
    let quick_open_at = at;
    let quick_open = if want_quick_open {
        let mut index = Vec::new();
        for (piece, image) in &cached {
            index.extend_from_slice(&rar5::quick_open_entry(
                quick_open_at - offsets[*piece],
                image,
            ));
        }
        let mut block = rar5::quick_open_header(index.len() as u64, plan.service_host());
        block.extend_from_slice(&index);
        at += block.len() as u64;
        Some(block)
    } else {
        None
    };

    // ---- pass two: the bytes -----------------------------------------
    let signature: &[u8] = if rar5_family {
        crate::carry::b_writers::rar50::write::reference::RAR5_SIGNATURE
    } else {
        RAR4_MARKER
    };
    // The offsets the locator records are measured from the byte after
    // the signature (SPEC-L 3.5.1), which is what `at` has been counting.
    let recovery_at = at;
    // **An offset the reserved width cannot hold is written as 0**, which
    // spec F 3.2.8 reads as "no such record": a reader then finds the
    // block by the header chain. The width is an estimate over the
    // members alone (above), so a large comment or large copied blocks
    // can carry a block past it, and the locator would otherwise widen,
    // move the head and fail the check below on a valid edit. It is the
    // rule `Run::write_default_locator` has in the Writer.
    let held = |offset: u64| {
        if rar5::vint_width_of(offset) <= width {
            offset
        } else {
            0
        }
    };
    let head = plan.head_bytes(
        width,
        quick_open.as_ref().map(|_| held(quick_open_at)),
        recovery_percent.map(|_| held(recovery_at)),
    );
    // The two passes only agree because the locator's offsets are written
    // in a FIXED width, so filling in the real values does not move the
    // main header's length. If that ever stopped holding, every offset
    // counted above would be wrong by the difference and the archive
    // would be quietly corrupt - so it is checked, and a mismatch is an
    // error rather than a bad archive.
    if head.len() != head_len {
        return Err(crate::write::options::refuse(
            "a rewrite whose archive head changed length between its two passes",
        ));
    }
    // The recovery record covers every byte before it, and pass one has
    // settled how many that is, so what builds the record is chosen
    // before a byte is written (`Recorder::new`).
    let protected_len = signature.len() as u64 + recovery_at;
    let mut recorder = match recovery_percent {
        Some(percent) => Recorder::new(rar5_family, protected_len, percent, src.memory())?,
        None => Recorder::None,
    };
    let mut sink = Tee {
        out: &mut out,
        recorder: &mut recorder,
        written: 0,
    };
    sink.write(signature)?;
    sink.write(&head)?;
    debug_assert_eq!(sink.written, signature.len() as u64 + head.len() as u64);

    let mut buffer = vec![0u8; COPY_CHUNK];
    for piece in lead.iter().chain(&body) {
        match piece {
            Piece::Bytes(bytes) => sink.write(bytes)?,
            Piece::Copy(range) => copy_range(src, range, &mut buffer, &mut sink)?,
        }
    }
    if let Some(block) = &quick_open {
        sink.write(block)?;
        report.quick_open = true;
    }

    // The record, over the bytes as they now stand.
    if let Some(percent) = recovery_percent {
        debug_assert_eq!(sink.written, protected_len);
        let recorder = std::mem::replace(sink.recorder, Recorder::None);
        let (header_bytes, record) = if rar5_family {
            report.recovery_shards =
                u32::from(crate::recovery::rr5::Rr5Plan::new(protected_len, percent)?.k);
            let record = match recorder {
                Recorder::Held(protected) => crate::recovery::rr5::encode(&protected, percent)?,
                Recorder::Rr5(encoder) => encoder.finish()?,
                _ => unreachable!("a RAR 5 rewrite records for a RAR 5 record"),
            };
            // The data area's CRC32 is the default layout's own; the
            // reference layout's `RR` header has none (spec G 3.11).
            let data_crc = (plan.service_form == Reserve::Natural).then(|| crc32(&record));
            let header = rar5::service_header(
                SERVICE_RECOVERY,
                record.len() as u64,
                data_crc,
                plan.service_host(),
                true,
                Some(u64::from(percent)),
                plan.service_form,
            );
            (header, record)
        } else {
            let (record, counts) = match recorder {
                Recorder::Legacy(encoder) => encoder.finish(),
                _ => unreachable!("a RAR 4 rewrite records for a RAR 4 record"),
            };
            let header = rar4::recovery_sub_block(&record, plan.rar4_service_host(), &counts);
            (header, record)
        };
        sink.write(&header_bytes)?;
        sink.write(&record)?;
        report.recovery = true;
    }

    if let Some(range) = end_block {
        copy_range(src, &range, &mut buffer, &mut sink)?;
    }
    report.bytes = sink.written;
    out.flush().map_err(Error::from)?;
    Ok(report)
}

/// The percentage the source's inline recovery record was written at, for
/// a rewrite the caller gave no percentage: `None` when the source has no
/// record.
///
/// A RAR 5 record states it, in its own extra record. A RAR 4 family `RR`
/// sub block states none, so it is read off the record's geometry: the
/// data area is two bytes a protected sector and 512 a parity sector
/// (SPEC-L 3.7), the protected sectors are the bytes before the block, and
/// the percentage is the least one that gives that many parity sectors
/// over that many protected ones.
///
/// **A record whose percentage cannot be told is a refusal**, because the
/// record itself is never carried (it is parity over the archive as it
/// stood) and a rewrite that dropped it returned Ok over an archive that
/// could no longer be repaired. The caller names a percentage, or asks
/// for the record to go, with `set_recovery`.
fn carried_recovery_percent(src: &Archive) -> Result<Option<u32>> {
    let Some(svc) = src
        .services()
        .find(|svc| svc.kind == ServiceKind::RecoveryRecord)
    else {
        // A RAR 2.x protect block is a recovery record the read reports
        // as a BLOCK and not as a service, so it was passed over here,
        // left out of the output with every other record, and the
        // rewrite returned Ok. It states a count of sectors and no
        // percentage (`-rr8` is eight sectors, whatever the archive's
        // length), and this crate writes no protect block, so there is
        // nothing truthful to rebuild it as. The reference drops it
        // without a word (measured on `rar` 7.23, 4 Oct 2026: `k` and `c`
        // on a RAR 2.50 archive written with `-rr` exit 0 and leave no
        // record); the rule here is that the caller says so.
        if src
            .blocks()
            .any(|block| block.kind == BlockKind::Service(ServiceKind::RecoveryRecord))
        {
            return Err(crate::write::options::refuse(
                "rewriting an archive whose recovery record is a RAR 2.x protect block,                  which states no percentage and which this crate does not write:                  name a percentage, or drop the record",
            ));
        }
        return Ok(None);
    };
    if let Some(percent) = svc.recovery_percent {
        // The stated percentage is one vint of the header, and the record
        // that lies in the archive is the evidence for it: a percentage
        // whose record over these protected bytes would be LONGER than
        // the one present is not what the archive was written at, and
        // rebuilding at it sized the output and the encode from one
        // header field (1 patched to 1,000 wrote eleven times the
        // archive). So what a rewrite adds is held to the record the
        // source really carries. A percentage that gives a shorter record
        // is believed: it can only make the rewrite smaller.
        if src.format() == Format::Rar5 {
            let header_at = src
                .blocks()
                .find(|block| block.kind == BlockKind::Service(ServiceKind::RecoveryRecord))
                .map(|block| block.range.start);
            let present = svc.header.packed_size;
            let borne = header_at.is_some_and(|protected| {
                crate::recovery::rr5::Rr5Plan::new(protected, percent)
                    .is_ok_and(|plan| plan.data_len() <= present)
            });
            if !borne {
                return Err(crate::write::options::refuse(
                    "rewriting an archive whose recovery record is shorter than the percentage \
                     its header states: name one, or drop the record",
                ));
            }
        }
        return Ok(Some(percent));
    }
    let unknown = || {
        crate::write::options::refuse(
            "rewriting an archive whose recovery record does not say what percentage it is: \
             name one, or drop the record",
        )
    };
    if src.format() == Format::Rar5 {
        return Err(unknown());
    }
    let header_at = src
        .blocks()
        .find(|block| block.kind == BlockKind::Service(ServiceKind::RecoveryRecord))
        .map(|block| block.range.start)
        .ok_or_else(unknown)?;
    let sector = crate::recovery::legacy::SECTOR;
    let sectors = header_at.div_ceil(sector).max(1);
    let parity = svc
        .header
        .packed_size
        .checked_sub(2 * sectors)
        .filter(|rest| *rest > 0 && rest.is_multiple_of(sector))
        .map(|rest| rest / sector)
        .ok_or_else(unknown)?;
    let percent = (parity.saturating_mul(100)).div_ceil(sectors).clamp(1, 100);
    Ok(Some(percent as u32))
}

/// Everything a rewrite refuses, before a byte of output.
fn refuse_what_is_not_built(src: &Archive, edit: &Edit<'_>) -> Result<()> {
    let member_level = !edit.remove.is_empty() || !edit.rename.is_empty();

    // RAR 1.3 and 1.4 are a DIFFERENT CONTAINER, not an older dialect of
    // this one: their blocks are not the frame this rewrite rebuilds a
    // main header for, and this crate writes no variant of them (spec G
    // section 1). RAR 1.5 and 2.0 share the frame and are
    // rewritten like any RAR 4 family archive.
    if matches!(src.format(), Format::Rar13) {
        return Err(crate::write::options::refuse(
            "editing an archive older than the RAR 4 family, which this crate does not write",
        ));
    }
    // An archive opened with `ReadOptions::tolerant_tail` whose walk
    // stopped at damage holds only the members before the damage: the
    // members after it, a recovery record that could have repaired it and
    // the end block are not in what the read reports. Rewritten, it would
    // come out as a complete archive of the members that were read, and a
    // caller that put it in the original's place would lose the rest.
    if src.tail().is_some() {
        return Err(crate::write::options::refuse(
            "editing an archive whose read stopped at damage: repair it first",
        ));
    }
    // Every block after the archive encryption header is encrypted as a
    // whole, so a rewrite that rebuilds the main header in clear and
    // copies the rest cannot produce a readable archive. The
    // header-encrypted write path is not built at all (spec G 3.3.6).
    // The reference DOES rewrite these, given the password (measured:
    // `rar d -hppw` succeeds, and without the password exits 13), so
    // this is a gap and not a property of the format.
    if src.headers_encrypted() {
        return Err(crate::write::options::refuse(
            "editing an archive whose headers are encrypted",
        ));
    }
    // A self-extracting archive's stub is an executable this crate never
    // emits and never carries (spec G section 1), and its blocks are laid
    // out behind it; a rewrite would move them out from under it.
    if src.start() != 0 {
        return Err(crate::write::options::refuse(
            "editing a self-extracting archive, whose stub this crate does not write",
        ));
    }
    if member_level && src.volume().is_volume {
        return Err(crate::write::options::refuse(
            "adding or removing a member of one volume of a set, which would not join",
        ));
    }
    // **A solid archive, and why removal alone is refused.** The members
    // of a solid group share one compressed stream: member `n`'s bytes
    // are decoded against the history of every member before it, so
    // dropping one leaves the members after it undecodable. The
    // reference RECOMPRESSES the whole archive instead (measured on
    // `rar` 7.23: a solid `rar d` rewrites the members it keeps), which
    // spec G 3.15 forbids here - a rewrite never decodes and never
    // recompresses. So it is refused by name.
    //
    // A RENAME is a different matter and is allowed: a member's name is
    // in its header and nothing in the solid chain depends on it, so the
    // data bytes are untouched and the chain still decodes. The
    // reference recompresses for this too; it does not have to.
    if !edit.remove.is_empty() && src.is_solid() {
        return Err(crate::write::options::refuse(
            "removing a member of a SOLID archive, which would need the members after it recompressed",
        ));
    }
    // The same bounds the writer keeps (`write::options`): 1 to 1,000 for
    // a RAR 5 record (spec L 3.5.1), 1 to 100 for the RAR 4 family's.
    if let Some(Some(percent)) = edit.recovery {
        if src.format() != Format::Rar5 && !(1..=100).contains(&percent) {
            return Err(crate::write::options::refuse(
                "a RAR 4 recovery record percentage outside 1 to 100",
            ));
        }
        if !crate::recovery::rr5::PERCENT_RANGE.contains(&percent) {
            return Err(crate::write::options::refuse(
                "a recovery record percentage outside 1 to 1000",
            ));
        }
    }
    Ok(())
}

/// What the archive head says, and how long it is.
struct Plan<'a> {
    rar5_family: bool,
    locked: bool,
    solid: bool,
    volume_set: bool,
    first_volume: bool,
    volume_number: u32,
    comment: Option<&'a [u8]>,
    recovery_percent: Option<u32>,
    want_quick_open: bool,
    /// The form of the service headers this rewrite builds (spec G 3.15):
    /// an archive that came in the reference layout goes out in it. Its
    /// mark is a quick-open block, which that layout writes and the
    /// default layout never does (3.5 rule 1); every other source gets
    /// the default layout's shortest forms.
    service_form: Reserve,
    /// The system the service headers name as the one that wrote them.
    host: crate::HostOs,
}

/// The system this build runs on, as far as a service header tells them
/// apart: the host an edit names when its caller names none.
pub(crate) const BUILD_HOST: crate::HostOs = if cfg!(windows) {
    crate::HostOs::Windows
} else {
    crate::HostOs::Unix
};

impl Plan<'_> {
    /// A service block's host byte is the system the rewrite is made on
    /// (spec G 3.3.4), by the caller's word and never the machine's.
    fn service_host(&self) -> u64 {
        crate::write::options::rar5_host_byte(self.host)
    }

    fn rar4_service_host(&self) -> u8 {
        crate::write::options::rar4_host_byte(self.host)
    }

    /// The signature is NOT in here: this is the main header and the
    /// comment block, which is everything between the signature and the
    /// first member.
    ///
    /// `quick_open` and `recovery` are the offsets the locator records,
    /// measured from the byte after the signature (SPEC-L 3.5.1). They
    /// are passed as `0` in the first pass and for real in the second;
    /// the locator writes them in a FIXED width, so the length this
    /// returns is the same either way, which is what makes the two
    /// passes agree.
    fn head_bytes(
        &self,
        width: usize,
        quick_open: impl Into<Option<u64>>,
        recovery: impl Into<Option<u64>>,
    ) -> Vec<u8> {
        let quick_open = quick_open.into();
        let recovery = recovery.into();
        let mut out = Vec::new();
        if self.rar5_family {
            let locator = if self.want_quick_open || self.recovery_percent.is_some() {
                Some(rar5::Locator {
                    quick_open: self
                        .want_quick_open
                        .then(|| (quick_open.unwrap_or(0), width)),
                    recovery: self
                        .recovery_percent
                        .map(|_| (recovery.unwrap_or(0), width)),
                })
            } else {
                None
            };
            out.extend_from_slice(&rar5::main_header(&rar5::MainPlan {
                volume_set: self.volume_set,
                volume_number: self.volume_number,
                solid: self.solid,
                recovery: self.recovery_percent.is_some(),
                locked: self.locked,
                locator,
            }));
            if let Some(comment) = self.comment {
                out.extend_from_slice(&rar5::service_header(
                    SERVICE_COMMENT,
                    comment.len() as u64,
                    Some(crc32(comment)),
                    self.service_host(),
                    false,
                    None,
                    self.service_form,
                ));
                out.extend_from_slice(comment);
            }
        } else {
            out.extend_from_slice(&rar4::main_header(&rar4::MainPlan {
                volume_set: self.volume_set,
                first_volume: self.first_volume,
                numbered_volumes: true,
                locked: self.locked,
                solid: self.solid,
                recovery: self.recovery_percent.is_some(),
                encrypted_headers: false,
            }));
            if let Some(comment) = self.comment {
                out.extend_from_slice(&rar4::comment_sub_block(comment, self.rar4_service_host()));
                out.extend_from_slice(comment);
            }
        }
        out
    }
}

/// What builds the inline recovery record as the output goes by.
///
/// **For a RAR 5 record, a copy of the output while it is within the
/// working limit and the streaming encoder past it; for a RAR 4 family
/// record, the streaming encoder always.** The record covers every byte
/// before it.
/// A rewrite used to keep all of them, whatever their number, and encode
/// from the copy: 6 GiB of heap to lock a 6 GiB archive that carried a
/// record, and an abort, not an error, where the copy could not grow.
///
/// The copy is still what a rewrite within the limit keeps, because it
/// buys the whole-slice encode (`rr5::encode`, a team over the whole
/// prefix), and that path is unchanged: same bytes held, same encode,
/// same wall. Past the limit the bytes are fed to the encoder that takes
/// them in order (`Rr5Encoder`, `LegacyEncoder`), which holds the record
/// and one shard or sector and never the archive; it folds a shard at a
/// time and is the slower encode, which is the price of running at all.
/// Both write the same record (`a_chunked_feed_matches_a_whole_one`).
///
/// Counted at 2 GiB with a 5 percent record, five reps, on a 96 thread
/// x86-64 box under load: the RAR 5 copy 1.87 s and 2.3 GiB resident
/// against 4.12 s and 0.2 GiB streamed, which is why the copy stays; the
/// RAR 4 copy 2.07 s and 2.2 GiB against 0.81 s and 0.1 GiB streamed,
/// which is why that family has none.
///
/// The limit is the one the caller NAMED when the archive was opened
/// (`MemoryPolicy::limit_named`, which the `Archive` keeps): a named limit
/// is a promise, and a copy past it is not kept. Where none was named it
/// is the working limit of the default PROCESS budget
/// (`MemoryPolicy::process_default`): the larger of 512 MiB and a quarter
/// of physical memory, bound by a memory cap of the environment. So a
/// machine with the memory for the copy keeps it, and only what a limit,
/// a cap or the machine cannot hold is streamed.
///
/// What is refused, before a byte of output, is a record this target
/// cannot address.
enum Recorder {
    /// No record is wanted.
    None,
    /// The output so far, whole.
    Held(Vec<u8>),
    /// The RAR 5 record, built as the bytes pass.
    Rr5(Box<crate::recovery::rr5::Rr5Encoder>),
    /// The RAR 4 family record, built as the bytes pass.
    Legacy(Box<crate::recovery::legacy::LegacyEncoder>),
}

impl Recorder {
    fn new(
        rar5_family: bool,
        protected: u64,
        percent: u32,
        opened_under: &crate::MemoryPolicy,
    ) -> Result<Recorder> {
        let limit = if opened_under.limit_named {
            opened_under.working_limit
        } else {
            crate::MemoryPolicy::process_default(0).working_limit
        };
        let most = isize::MAX as u64;
        // The copy is the RAR 5 record's alone. The RAR 4 family's is
        // built as the bytes pass at every size: its encode is one XOR
        // and one tag a sector, with nothing for a whole slice to buy,
        // and the copy only cost it (counted on x86-64 and on arm64).
        //
        // Above 100 percent the record is the larger part (spec L 3.5.1
        // takes percentages to 1,000): the copy is then kept only while
        // it and what the encode holds beside it fit the limit, and the
        // record is otherwise built as the bytes pass, which holds its
        // rows and its data area and no copy, about 20 times the
        // protected length at 1,000 percent. An output that is only
        // written to gives no cheaper way: every record carries a tag
        // taken over the whole of row 0.
        let beside = if rar5_family && percent > 100 {
            let plan = crate::recovery::rr5::Rr5Plan::new(protected, percent)?;
            crate::recovery::rr5::whole_slice_bytes(&plan)
        } else {
            0
        };
        if rar5_family && protected.saturating_add(beside) <= limit.min(most) {
            return Ok(Recorder::Held(Vec::new()));
        }
        let unaddressable = |needed: u64| {
            Error::new(crate::ErrorKind::LimitExceeded {
                resource: crate::Resource::AddressSpace,
                needed,
                limit: most,
            })
        };
        if rar5_family {
            let plan = crate::recovery::rr5::Rr5Plan::new(protected, percent)?;
            // The encoder holds a shard and a row of one for each parity
            // shard, and hands back the data area.
            let held = (u64::from(plan.m) + 1)
                .saturating_mul(plan.shard_len)
                .max(plan.data_len());
            if held > most {
                return Err(unaddressable(held));
            }
            Ok(Recorder::Rr5(Box::new(
                crate::recovery::rr5::Rr5Encoder::new(plan),
            )))
        } else {
            // SPEC-L 3.7: two bytes a protected sector and one sector a
            // parity sector, of which there are at most as many.
            let sector = crate::recovery::legacy::SECTOR;
            let sectors = protected.div_ceil(sector).max(1);
            let held = sectors.saturating_mul(2 + sector);
            if held > most {
                return Err(unaddressable(held));
            }
            Ok(Recorder::Legacy(Box::new(
                crate::recovery::legacy::LegacyEncoder::new(protected, percent),
            )))
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        match self {
            Recorder::None => {}
            Recorder::Held(held) => held.extend_from_slice(bytes),
            Recorder::Rr5(encoder) => encoder.push(bytes),
            Recorder::Legacy(encoder) => encoder.push(bytes),
        }
    }
}

/// The output, and what builds the recovery record from it.
struct Tee<'o, W: Write> {
    out: &'o mut W,
    recorder: &'o mut Recorder,
    written: u64,
}

impl<W: Write> Tee<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes).map_err(Error::from)?;
        self.recorder.push(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }
}

/// The locator's reserved width (spec G 3.6.3), over the members the
/// output holds and the names they will carry.
fn locator_width(src: &Archive, drop_member: &[bool], new_name: &[Option<Vec<u8>>]) -> usize {
    let kept = src.members().enumerate().filter_map(|(index, member)| {
        if drop_member.get(index).copied().unwrap_or(false) {
            return None;
        }
        let name = match new_name.get(index).and_then(|name| name.as_deref()) {
            Some(name) => name,
            None => member.name,
        };
        Some((member.packed_size, name))
    });
    rar5::locator_reserve_width(kept).max(1)
}

/// The first bytes of a block, enough to read its header fields.
fn read_head(src: &Archive, range: &Range<u64>) -> Result<Vec<u8>> {
    let want = (range.end - range.start).min(1024);
    read_range(src, &(range.start..range.start + want))
}

/// A range of the source, whole.
fn read_range(src: &Archive, range: &Range<u64>) -> Result<Vec<u8>> {
    let len = usize::try_from(range.end - range.start).unwrap_or(0);
    let mut out = vec![0u8; len];
    let mut at = 0usize;
    while at < len {
        let read = src
            .source()
            .read_at(range.start + at as u64, &mut out[at..])
            .map_err(Error::from)?;
        if read == 0 {
            return Err(Error::new(crate::ErrorKind::Truncated));
        }
        at += read;
    }
    Ok(out)
}

/// Copies a range of the source through one buffer.
fn copy_range<W: Write>(
    src: &Archive,
    range: &Range<u64>,
    buffer: &mut [u8],
    out: &mut Tee<'_, W>,
) -> Result<()> {
    let mut at = range.start;
    while at < range.end {
        let want = (range.end - at).min(buffer.len() as u64) as usize;
        let read = src
            .source()
            .read_at(at, &mut buffer[..want])
            .map_err(Error::from)?;
        if read == 0 {
            return Err(Error::new(crate::ErrorKind::Truncated));
        }
        out.write(&buffer[..read])?;
        at += read as u64;
    }
    Ok(())
}
