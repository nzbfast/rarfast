//! The RAR 4 family's inline recovery records (spec L 3.7).
//!
//! Both kinds - the RAR 2.x protect header and the RAR 3.x `RR` subblock -
//! protect the archive bytes BEFORE their own header in 512-byte sectors,
//! with one 16-bit tag per sector and `r` parity sectors, parity sector `c`
//! being the XOR of every sector whose index is `c` modulo `r`. One damaged
//! sector per congruence class is recoverable, and a second one in the same
//! class is not.
//!
//! The final sector is PARTIAL, because it would run into the record's own
//! header, and it is covered like any other, zero-padded (spec L 3.7 and
//! 8.1). The genuine RAR 2.50 records show the tags and parity match only
//! when it is included, so this engine repairs it; its predecessor did not.

use std::io::Write;

use crate::checksum::{crc32, Crc32};
use crate::memory::MemoryPolicy;
use crate::recovery::io::{length, read_at_most, read_exact_at};
use crate::rev5::RepairReport;
use crate::source::RangeSource;
use crate::{Error, ErrorKind, RecoveryFailure, Resource, Result};

/// The format's sector.
pub(crate) const SECTOR: u64 = 512;
/// The RAR 2.x protect block's type byte.
const PROTECT_TYPE: u8 = 0x78;
/// Its header length, which the format fixes.
const PROTECT_HEADER: u64 = 26;
/// The eight bytes at offset 18 of a protect header.
const PROTECT_MARK: [u8; 8] = *b"Protect!";
/// The RAR 1.5 to 4.x file header's type.
const FILE_TYPE: u8 = 0x74;
/// The RAR 3.x subblock type.
const SUBBLOCK_TYPE: u8 = 0x7A;
/// The RAR 1.5 to 4.x signature.
const RAR4_SIGNATURE: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
/// Flag bit that says a block header is followed by a data area whose
/// length is the four bytes at offset 7 (its low half, where a file or
/// subblock header also carries [`HIGH_SIZES`]).
const DATA_AREA_FOLLOWS: u16 = 0x8000;
/// Flag bit of a file or subblock header that says the high halves of its
/// two sizes follow the fixed fields (spec F 3.3.6).
const HIGH_SIZES: u16 = 0x0100;
/// The name of the subblock that is the recovery record.
const SUBBLOCK_NAME: [u8; 2] = *b"RR";
/// The eight bytes a RAR 3.x `RR` subblock carries after its name.
const SUBBLOCK_MARK: [u8; 8] = *b"Protect+";
/// What follows the name in an `RR` subblock's header: the mark, `r`,
/// `n` and four bytes that are zero (spec L 3.7).
const SUBBLOCK_FIELDS: u64 = 8 + 4 + 4 + 4;
/// How far into a volume the RAR 4 signature is looked for.
const SIGNATURE_SCAN: u64 = 1 << 20;

/// One inline record of the RAR 4 family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyRecord {
    /// The record's own header offset, which is where the protected bytes
    /// end.
    pub(crate) header_at: u64,
    /// The data area: the tags, then the parity sectors.
    pub(crate) data_at: u64,
    /// Protected sectors, the last one partial and zero-padded.
    pub(crate) sectors: u64,
    /// Parity sectors, which is also the number of congruence classes.
    /// For a RAR 3.x `RR` record this is the header's FIELD, taken as it
    /// is: it names a sector's class and the place of its parity sector,
    /// and sizes no memory and no loop (spec L 3.7).
    pub(crate) parity: u64,
    /// The data area's length as it lies in the file. A protect block's
    /// is `2n + 512r`; an `RR` record's is its header's data size, which
    /// may be longer (the rest is not read) or shorter (a parity sector
    /// held only in part still rebuilds what it covers).
    pub(crate) area: u64,
}

impl LegacyRecord {
    /// The data area a writer makes for these counts: `2n + 512r`.
    pub(crate) fn data_len(&self) -> u64 {
        (2 * self.sectors).saturating_add(SECTOR.saturating_mul(self.parity))
    }

    /// The protected bytes, which end at the header.
    fn protected(&self) -> u64 {
        self.header_at.min(self.sectors * SECTOR)
    }
}

/// The tag of one zero-padded sector: the low 16 bits of the bitwise NOT
/// of its CRC32 (spec L 3.7).
fn tag(sector: &[u8; SECTOR as usize]) -> u16 {
    !crc32(sector) as u16
}

/// Sector `index` of the protected prefix, zero-padded past its end.
fn read_sector(
    src: &dyn RangeSource,
    record: &LegacyRecord,
    index: u64,
) -> Result<[u8; SECTOR as usize]> {
    let mut sector = [0u8; SECTOR as usize];
    let start = index * SECTOR;
    let protected = record.protected();
    if start < protected {
        let want = (protected - start).min(SECTOR) as usize;
        read_exact_at(src, start, &mut sector[..want])?;
    }
    Ok(sector)
}

/// Find a RAR 2.x protect header or a RAR 3.x `RR` subblock in `src`.
pub(crate) fn scan(src: &dyn RangeSource) -> Result<LegacyRecord> {
    if let Some(record) = scan_protect(src)? {
        return Ok(record);
    }
    match scan_subblock(src)? {
        Subblock::Record(record) => Ok(record),
        // A record was there and its fields are out of bounds: refused,
        // and nothing else in the volume is one (spec L section 4).
        Subblock::Refused => Err(Error::new(ErrorKind::Recovery(
            RecoveryFailure::RecoveryDamaged,
        ))),
        Subblock::None => Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord))),
    }
}

/// What the walk for a RAR 3.x `RR` subblock ends with.
enum Subblock {
    Record(LegacyRecord),
    /// A subblock that is the record by its name or its mark, its fields
    /// out of the bounds of spec L section 4.
    Refused,
    None,
}

/// The RAR 2.x protect header, found by its own eight-byte mark.
///
/// The mark sits at offset 18 of a 26-byte header whose type byte is 0x78,
/// and the header's data size must be exactly `2n + 512r` for the counts it
/// declares - which no other block satisfies by accident.
fn scan_protect(src: &dyn RangeSource) -> Result<Option<LegacyRecord>> {
    let volume = length(src);
    let mut window = vec![0u8; 1 << 20];
    let mut at = 0u64;
    while at < volume {
        let got = read_at_most(src, at, &mut window)?;
        if got < PROTECT_MARK.len() {
            break;
        }
        let mut search = 0usize;
        while let Some(hit) = memchr::memmem::find(&window[search..got], &PROTECT_MARK) {
            let mark = at + (search + hit) as u64;
            search += hit + 1;
            let Some(header_at) = mark.checked_sub(18) else {
                continue;
            };
            let mut head = [0u8; PROTECT_HEADER as usize];
            if read_at_most(src, header_at, &mut head)? < head.len() {
                continue;
            }
            if head[2] != PROTECT_TYPE
                || u16::from_le_bytes([head[5], head[6]]) != PROTECT_HEADER as u16
            {
                continue;
            }
            let data_len = u64::from(u32::from_le_bytes(head[7..11].try_into().expect("four")));
            let parity = u64::from(u16::from_le_bytes([head[12], head[13]]));
            let sectors = u64::from(u32::from_le_bytes(head[14..18].try_into().expect("four")));
            let record = LegacyRecord {
                header_at,
                data_at: header_at + PROTECT_HEADER,
                sectors,
                parity,
                area: data_len,
            };
            if parity >= 1
                && sectors >= 1
                && sectors <= header_at.div_ceil(SECTOR)
                && record.data_len() == data_len
                && record.data_at + data_len <= volume
            {
                return Ok(Some(record));
            }
        }
        at += (got - (PROTECT_MARK.len() - 1)) as u64;
    }
    Ok(None)
}

/// The RAR 3.x `RR` subblock, found by walking the block chain.
///
/// The walk reads only what spec L needs of a RAR 1.5 to 4.x block header:
/// its type, its flags, its own length and the length of the data area that
/// follows it. It is self-checking - every header carries a CRC16, which
/// spec L section 1 states is the low 16 bits of this package's CRC32 - so
/// a header the walk lands on out of step is rejected rather than followed.
/// Spec F owns the full header layout; when it lands, `repair_inline` on a
/// readable archive should use its walk and keep this one for the damaged
/// case.
fn scan_subblock(src: &dyn RangeSource) -> Result<Subblock> {
    let volume = length(src);
    let Some(start) = signature_at(src, volume)? else {
        return Ok(Subblock::None);
    };
    let mut refused = false;
    let mut at = start + RAR4_SIGNATURE.len() as u64;
    let mut head = [0u8; 36];
    while at + 7 <= volume {
        let got = read_at_most(src, at, &mut head)?;
        if got < 7 {
            break;
        }
        let kind = head[2];
        let flags = u16::from_le_bytes([head[3], head[4]]);
        let size = u64::from(u16::from_le_bytes([head[5], head[6]]));
        if size < 7 || at + size > volume {
            break;
        }
        let data_len = if flags & DATA_AREA_FOLLOWS != 0 {
            if got < 11 {
                break;
            }
            let low = u64::from(u32::from_le_bytes(head[7..11].try_into().expect("four")));
            // A file or subblock header may carry the high half of its
            // packed size, four bytes at offset 32 (spec F 3.3.6); a walk
            // that steps by the low half alone lands inside the data of
            // any member of 4 GiB or more.
            if matches!(kind, FILE_TYPE | SUBBLOCK_TYPE) && flags & HIGH_SIZES != 0 {
                if got < 36 || size < 36 {
                    break;
                }
                let high = u64::from(u32::from_le_bytes(head[32..36].try_into().expect("four")));
                high << 32 | low
            } else {
                low
            }
        } else {
            0
        };
        if !header_checksum_holds(src, at, size)? {
            break;
        }
        if kind == SUBBLOCK_TYPE && flags & DATA_AREA_FOLLOWS != 0 {
            match rr_fields(src, at, size, flags)? {
                RrFields::NotTheRecord => {}
                RrFields::Stated {
                    parity,
                    sectors,
                    last_four,
                } => {
                    let record = LegacyRecord {
                        header_at: at,
                        data_at: at + size,
                        sectors,
                        parity,
                        area: data_len,
                    };
                    // Spec L section 4, the row of the `RR` fields; and
                    // the data area whole in the file, which is this
                    // reader's own bound (a file cut inside the record
                    // was not measured).
                    let in_bounds = parity >= 1
                        && sectors >= 1
                        && last_four == 0
                        && 2 * sectors <= data_len
                        && at > SECTOR * (sectors - 1)
                        && at <= SECTOR * sectors + SECTOR
                        && record.data_at.checked_add(data_len) <= Some(volume);
                    if in_bounds {
                        return Ok(Subblock::Record(record));
                    }
                    refused = true;
                }
            }
        }
        let Some(next) = at.checked_add(size).and_then(|n| n.checked_add(data_len)) else {
            break;
        };
        if next <= at {
            break;
        }
        at = next;
    }
    Ok(if refused {
        Subblock::Refused
    } else {
        Subblock::None
    })
}

/// What a subblock header says of being the recovery record.
enum RrFields {
    /// Neither named `RR` nor carrying the mark.
    NotTheRecord,
    /// The record, by its name or by its mark, and the three fields its
    /// header states: `r`, `n`, and the four bytes after `n`.
    Stated {
        parity: u64,
        sectors: u64,
        last_four: u32,
    },
}

/// The fields of the subblock header at `at`, if it is the recovery
/// record: named `RR`, or carrying the mark `Protect+` after its name
/// (spec L 3.7: the reference finds the record under another name when
/// the mark is there, and without the mark when the name is there).
///
/// A subblock header has the file header's layout: the name's length is
/// the two bytes at offset 26, and the name starts at 32, or at 40 when
/// the header carries the high halves of its sizes. After the name stand
/// the mark, then `r` and `n` as 4 bytes each, then 4 bytes. Nothing else
/// of the header is read here: not its method, its version, its checksum
/// of the data area nor its unpacked size.
fn rr_fields(src: &dyn RangeSource, at: u64, size: u64, flags: u16) -> Result<RrFields> {
    let name_at: u64 = if flags & HIGH_SIZES != 0 { 40 } else { 32 };
    if size < name_at {
        return Ok(RrFields::NotTheRecord);
    }
    let mut name_len = [0u8; 2];
    read_exact_at(src, at + 26, &mut name_len)?;
    let name_len = u64::from(u16::from_le_bytes(name_len));
    if size < name_at + name_len + SUBBLOCK_FIELDS {
        return Ok(RrFields::NotTheRecord);
    }
    let named = name_len == SUBBLOCK_NAME.len() as u64 && {
        let mut name = [0u8; SUBBLOCK_NAME.len()];
        read_exact_at(src, at + name_at, &mut name)?;
        name == SUBBLOCK_NAME
    };
    let mut fields = [0u8; SUBBLOCK_FIELDS as usize];
    read_exact_at(src, at + name_at + name_len, &mut fields)?;
    if !named && fields[..8] != SUBBLOCK_MARK {
        return Ok(RrFields::NotTheRecord);
    }
    let four = |from: usize| u32::from_le_bytes(fields[from..from + 4].try_into().expect("four"));
    Ok(RrFields::Stated {
        parity: u64::from(four(8)),
        sectors: u64::from(four(12)),
        last_four: four(16),
    })
}

/// A RAR 1.5 to 4.x signature at or near the volume's start.
fn signature_at(src: &dyn RangeSource, volume: u64) -> Result<Option<u64>> {
    let want = SIGNATURE_SCAN.min(volume) as usize + RAR4_SIGNATURE.len();
    let mut head = vec![0u8; want];
    let got = read_at_most(src, 0, &mut head)?;
    Ok(memchr::memmem::find(&head[..got], &RAR4_SIGNATURE).map(|at| at as u64))
}

/// A block header's own CRC16: the low 16 bits of the CRC32 of everything
/// after it, up to the header's declared length.
fn header_checksum_holds(src: &dyn RangeSource, at: u64, size: u64) -> Result<bool> {
    let mut stored = [0u8; 2];
    read_exact_at(src, at, &mut stored)?;
    let mut hasher = Crc32::new();
    let mut buf = vec![0u8; (size - 2) as usize];
    read_exact_at(src, at + 2, &mut buf)?;
    hasher.update(&buf);
    Ok(hasher.finish() as u16 == u16::from_le_bytes(stored))
}

/// The data area for `protected` at `percent`: the tags, then the parity
/// sectors (spec L 3.7's encode).
pub(crate) fn build(protected: &[u8], percent: u32) -> Result<(Vec<u8>, LegacyRecord)> {
    let mut encoder = LegacyEncoder::new(protected.len() as u64, percent);
    encoder.push(protected);
    Ok(encoder.finish())
}

/// The same data area as [`build`], from the protected bytes fed IN ORDER
/// in pieces of any length, so a writer that can read its volume back
/// need not hold it (spec L 3.7's encode; the writer's side is spec G
/// 3.11).
///
/// The record is sized by the protected length, which the caller states
/// first: the tags and the parity class of a sector (`index % parity`)
/// both follow from it. What this holds is the data area itself, `2n +
/// 512r` bytes, and one sector: the record, never the archive.
pub(crate) struct LegacyEncoder {
    record: LegacyRecord,
    out: Vec<u8>,
    sector: [u8; SECTOR as usize],
    filled: usize,
    index: u64,
}

impl LegacyEncoder {
    /// An encoder for `length` protected bytes at `percent`.
    pub(crate) fn new(length: u64, percent: u32) -> LegacyEncoder {
        let sectors = length.div_ceil(SECTOR).max(1);
        let parity = ((sectors * u64::from(percent)) / 100).clamp(1, sectors);
        let mut record = LegacyRecord {
            header_at: length,
            data_at: length,
            sectors,
            parity,
            area: 0,
        };
        record.area = record.data_len();
        LegacyEncoder {
            out: vec![0u8; record.data_len() as usize],
            record,
            sector: [0u8; SECTOR as usize],
            filled: 0,
            index: 0,
        }
    }

    /// Feed the next protected bytes.
    pub(crate) fn push(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (self.sector.len() - self.filled).min(data.len());
            self.sector[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == self.sector.len() {
                self.absorb();
            }
        }
    }

    /// The tag and parity class of the sector now full, zero padded past
    /// what was fed.
    fn absorb(&mut self) {
        self.sector[self.filled..].fill(0);
        let (tags, rows) = self.out.split_at_mut(2 * self.record.sectors as usize);
        let at = 2 * self.index as usize;
        tags[at..at + 2].copy_from_slice(&tag(&self.sector).to_le_bytes());
        let class = (self.index % self.record.parity) as usize * SECTOR as usize;
        for (d, s) in rows[class..class + SECTOR as usize]
            .iter_mut()
            .zip(&self.sector)
        {
            *d ^= *s;
        }
        self.index += 1;
        self.filled = 0;
    }

    /// The data area, once every protected byte has been fed. A last
    /// partial sector is padded; an empty prefix still has its one sector.
    pub(crate) fn finish(mut self) -> (Vec<u8>, LegacyRecord) {
        debug_assert!(
            self.index * SECTOR + self.filled as u64 == self.record.header_at,
            "fed a different length than was stated"
        );
        while self.index < self.record.sectors {
            self.absorb();
        }
        (self.out, self.record)
    }
}

/// Repair `src` from `record` into `out`.
pub(crate) fn repair(
    src: &dyn RangeSource,
    record: &LegacyRecord,
    policy: &MemoryPolicy,
    out: &mut dyn Write,
) -> Result<RepairReport> {
    // The record's own data area is what the repair works from, so its
    // length as it lies is charged before any of it is read (spec L
    // section 4).
    let needed = record.area;
    if needed > policy.repair_limit {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: Resource::RepairWork,
            needed,
            limit: policy.repair_limit,
        }));
    }
    // Bytes of the data area past `2n + 512r` are not read (spec L 3.7).
    let mut area = vec![0u8; needed.min(record.data_len()) as usize];
    read_exact_at(src, record.data_at, &mut area)?;
    let (tags, rows) = area.split_at(2 * record.sectors as usize);

    let mut damaged: Vec<u64> = Vec::new();
    for index in 0..record.sectors {
        let at = 2 * index as usize;
        let stored = u16::from_le_bytes([tags[at], tags[at + 1]]);
        if stored != tag(&read_sector(src, record, index)?) {
            damaged.push(index);
        }
    }
    if damaged.is_empty() {
        copy_through(src, &[], out)?;
        return Ok(RepairReport {
            peak_working_memory: needed,
            ..RepairReport::default()
        });
    }
    // Two damaged sectors of one congruence class cancel in that class's
    // parity, and nothing else holds either of them.
    let mut classes: Vec<u64> = damaged.iter().map(|i| i % record.parity).collect();
    classes.sort_unstable();
    let distinct = {
        let mut c = classes.clone();
        c.dedup();
        c.len()
    };
    if distinct != classes.len() {
        return Err(Error::new(ErrorKind::Recovery(
            RecoveryFailure::TooManyMissing {
                missing: damaged.len() as u32,
                available: distinct as u32,
            },
        )));
    }

    let mut patches: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut failed = false;
    let mut rebuilt = false;
    for &index in &damaged {
        // The class's parity sector is the 512 bytes of the data area
        // from `2n + 512c`, or as many of them as the area holds: none,
        // where `r` puts it outside, and the sector is then not rebuilt.
        let class = index % record.parity;
        let covered: &[u8] = class
            .checked_mul(SECTOR)
            .and_then(|from| usize::try_from(from).ok())
            .filter(|from| *from < rows.len())
            .map_or(&[], |from| {
                &rows[from..rows.len().min(from + SECTOR as usize)]
            });
        if covered.is_empty() {
            failed = true;
            continue;
        }
        // The bytes the parity sector covers are the parity XOR every
        // other sector of the class; the bytes it does not cover are the
        // sector's own as found.
        let mut sector = read_sector(src, record, index)?;
        sector[..covered.len()].copy_from_slice(covered);
        let mut other = class;
        while other < record.sectors {
            if other != index {
                let bytes = read_sector(src, record, other)?;
                for (d, s) in sector[..covered.len()].iter_mut().zip(&bytes) {
                    *d ^= *s;
                }
            }
            match other.checked_add(record.parity) {
                Some(next) => other = next,
                None => break,
            }
        }
        let at = 2 * index as usize;
        if tag(&sector) != u16::from_le_bytes([tags[at], tags[at + 1]]) {
            failed = true;
            continue;
        }
        rebuilt = true;
        // Only the sector's real bytes are written back: the last sector
        // is partial, and its padding is not part of the archive.
        let start = index * SECTOR;
        let real = record.protected().saturating_sub(start).min(SECTOR) as usize;
        if real > 0 {
            patches.push((start, sector[..real].to_vec()));
        }
    }
    patches.sort_by_key(|p| p.0);
    copy_through(src, &patches, out)?;
    Ok(RepairReport {
        rebuilt: if rebuilt { vec![0] } else { Vec::new() },
        failed: if failed { vec![0] } else { Vec::new() },
        peak_working_memory: needed + patches.len() as u64 * SECTOR,
    })
}

/// Copy `src` to `out`, substituting each patch in place.
fn copy_through(
    src: &dyn RangeSource,
    patches: &[(u64, Vec<u8>)],
    out: &mut dyn Write,
) -> Result<()> {
    let volume = length(src);
    let mut buf = vec![0u8; 1 << 20];
    let mut at = 0u64;
    for (start, bytes) in patches {
        while at < *start {
            let want = (*start - at).min(buf.len() as u64) as usize;
            let got = read_at_most(src, at, &mut buf[..want])?;
            if got == 0 {
                break;
            }
            out.write_all(&buf[..got]).map_err(Error::caller)?;
            at += got as u64;
        }
        out.write_all(bytes).map_err(Error::caller)?;
        at += bytes.len() as u64;
    }
    while at < volume {
        let want = (volume - at).min(buf.len() as u64) as usize;
        let got = read_at_most(src, at, &mut buf[..want])?;
        if got == 0 {
            break;
        }
        out.write_all(&buf[..got]).map_err(Error::caller)?;
        at += got as u64;
    }
    Ok(())
}
