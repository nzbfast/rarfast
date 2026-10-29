//! The block walk of spec F section 5.2, printed.
//!
//! A total function of the header bytes: a reader's own walk printed
//! in this format is compared byte for byte with the committed
//! `vectors-F/expected/` files, and a run that reproduces all 30 has parsed
//! every header shape this package claims to read.
//!
//! This is a DIAGNOSTIC walk, not a reader. It marks a header whose
//! checksum failed `BAD` and keeps going, and it never decrypts, so an
//! archive with encrypted headers is walked in the clear and shows the
//! garbage that gives. `Archive::open` does neither (spec F 4.6).

use std::fmt::Write as _;

use crate::error::ErrorKind;
use crate::read::block::{Block, Fields};
use crate::read::reader::{BlockReader, ReadCtx};
use crate::read::{detect, dostime, htime, rar4, rar5, vint, Format, ReadOptions};

/// Flag names, low bit first, with anything left over printed as a hex
/// residue so no bit of a stored word goes unreported.
fn names(value: u64, table: &[(u64, &str)]) -> String {
    let mut out = String::new();
    let mut left = value;
    for (bit, name) in table {
        if value & bit != 0 {
            if !out.is_empty() {
                out.push('|');
            }
            out.push_str(name);
            left &= !bit;
        }
    }
    if left != 0 {
        if !out.is_empty() {
            out.push('|');
        }
        let _ = write!(out, "0x{left:x}?");
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

/// A Python-style `b'...'` rendering of stored name bytes.
fn brepr(bytes: &[u8]) -> String {
    let mut out = String::from("b'");
    for b in bytes {
        match *b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(*b as char),
            other => {
                let _ = write!(out, "\\x{other:02x}");
            }
        }
    }
    out.push('\'');
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn stamp(unix_seconds: i64) -> String {
    let (y, m, d, hh, mm, ss) = dostime::civil(unix_seconds);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

const HEAD_FLAGS_5: &[(u64, &str)] = &[
    (0x0001, "EXTRA"),
    (0x0002, "DATA"),
    (0x0004, "EDITOR_MAY_DROP"),
    (0x0008, "SPLIT_BEFORE"),
    (0x0010, "SPLIT_AFTER"),
    (0x0020, "DEPENDS"),
    (0x0040, "KEEP"),
];

const ARCHIVE_FLAGS_5: &[(u64, &str)] = &[
    (0x0001, "VOLUME"),
    (0x0002, "HAS_PART_INDEX"),
    (0x0004, "SOLID"),
    (0x0008, "RECOVERY"),
    (0x0010, "LOCKED"),
];

const TIME_FLAGS_5: &[(u64, &str)] = &[
    (0x0001, "UNIX"),
    (0x0002, "MTIME"),
    (0x0004, "CTIME"),
    (0x0008, "ATIME"),
    (0x0010, "NANO"),
];

const FILE_FLAGS_5: &[(u64, &str)] = &[
    (0x0001, "DIRECTORY"),
    (0x0002, "MTIME"),
    (0x0004, "CRC32"),
    (0x0008, "UNKNOWNSIZE"),
];

const MAIN_FLAGS_4: &[(u64, &str)] = &[
    (0x0001, "VOLUME"),
    (0x0002, "COMMENT"),
    (0x0004, "LOCK"),
    (0x0008, "SOLID"),
    (0x0010, "NEW_NAMING"),
    (0x0040, "RECOVERY"),
    (0x0080, "ENC_HEADERS"),
    (0x0100, "FIRST_VOLUME"),
    (0x4000, "EDITOR_MAY_DROP"),
    (0x8000, "LENGTH_FOLLOWS"),
];

const FILE_FLAGS_4: &[(u64, &str)] = &[
    (0x0001, "SPLIT_BEFORE"),
    (0x0002, "SPLIT_AFTER"),
    (0x0004, "ENCRYPTED"),
    (0x0008, "COMMENT"),
    (0x0010, "SOLID"),
    (0x0100, "HIGH_SIZES"),
    (0x0200, "UNICODE"),
    (0x0400, "SALT"),
    (0x0800, "VERSION"),
    (0x1000, "EXT_TIME"),
    (0x4000, "EDITOR_MAY_DROP"),
    (0x8000, "LENGTH_FOLLOWS"),
];

const END_FLAGS_4: &[(u64, &str)] = &[
    (0x0001, "NEXT_VOLUME"),
    (0x0002, "ARCHIVE_CRC"),
    (0x0004, "REV_SPACE"),
    (0x0008, "VOL_NUMBER"),
    (0x4000, "EDITOR_MAY_DROP"),
    (0x8000, "LENGTH_FOLLOWS"),
];

const ARCHIVE_FLAGS_13: &[(u64, &str)] = &[
    (0x01, "VOLUME"),
    (0x02, "COMMENT"),
    (0x04, "LOCK"),
    (0x08, "SOLID"),
    (0x80, "ALWAYS"),
];

const FILE_FLAGS_13: &[(u64, &str)] = &[
    (0x01, "SPLIT_BEFORE"),
    (0x02, "SPLIT_AFTER"),
    (0x04, "ENCRYPTED"),
    (0x08, "COMMENT"),
];

/// Print the block walk of `data` in the format of spec F 5.2.
pub(crate) fn walk(name: &str, data: &[u8]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "== {name} ({} bytes)", data.len());
    let found = match detect::detect_in(&data, data.len() as u64) {
        Ok(Some(found)) => found,
        _ => {
            out.push_str("  no signature\n");
            return out;
        }
    };
    if found.start > 0 {
        let _ = writeln!(
            out,
            "  signature at offset {} (stub of {} bytes ahead of it)",
            found.start, found.start
        );
    }
    let _ = writeln!(
        out,
        "  format: {}",
        match found.format {
            Format::Rar5 => "RAR 5.0",
            Format::Rar13 => "RAR 1.3/1.4",
            _ => "RAR 1.5/2.0/4.x",
        }
    );

    let mut ctx = ReadCtx::new(ReadOptions {
        sfx_scan: data.len() as u64,
        ..ReadOptions::default()
    });
    let mut reader = BlockReader::new(&data, &mut ctx, found.format, found.start).permissive();
    let mut end_at = None;
    loop {
        let pos = reader.position();
        match reader.next() {
            Ok(Some(block)) => {
                let stop = print_block(&mut out, &reader, &block, found.format);
                if matches!(block.fields, Fields::End(_)) {
                    end_at = Some(block.end());
                }
                if stop {
                    return out;
                }
            }
            Ok(None) => break,
            Err(e) => {
                if matches!(e.kind(), ErrorKind::Truncated) {
                    let _ = writeln!(
                        out,
                        "  {pos:08x}: header runs past EOF (size {})",
                        reader.declared_size()
                    );
                } else {
                    let _ = writeln!(out, "  {pos:08x}: header does not parse");
                }
                return out;
            }
        }
    }
    if let Some(end) = end_at {
        if (end as usize) < data.len() {
            let _ = writeln!(
                out,
                "  {end:08x}: {} bytes after the end record",
                data.len() - end as usize
            );
        }
    }
    out
}

/// Print one block; `true` means the walk cannot go on.
fn print_block(
    out: &mut String,
    reader: &BlockReader<'_, '_>,
    block: &Block,
    format: Format,
) -> bool {
    let head = reader.header_bytes();
    let at = block.header.start;
    match format {
        Format::Rar5 => print_rar5(out, head, block, at),
        Format::Rar13 => print_rar13(out, head, block, at),
        _ => return print_rar4(out, head, block, at),
    }
    false
}

fn label(out: &mut String, at: u64, name: &str, width: usize) {
    let _ = write!(out, "  {at:08x}: {name:<width$} ");
}

fn print_rar5(out: &mut String, head: &[u8], block: &Block, at: u64) {
    let Ok(common) = rar5::parse_common(head) else {
        return;
    };
    let name = match common.btype {
        rar5::TYPE_MAIN => "MAIN",
        rar5::TYPE_FILE => "FILE",
        rar5::TYPE_SERVICE => "SERVICE",
        rar5::TYPE_ENCRYPTION => "ENCRYPTION",
        rar5::TYPE_END => "END",
        _ => "OTHER",
    };
    label(out, at, name, 10);
    let hsize = common.head_len - 4 - vint_len(&head[4..]);
    let _ = write!(
        out,
        "hsize={:<4} crc={:08x}{} flags=0x{:04x}({})",
        hsize,
        common.crc,
        if block.checksum_ok { "" } else { " BAD" },
        common.flags,
        names(common.flags, HEAD_FLAGS_5)
    );
    if common.flags & rar5::HF_DATA != 0 {
        let _ = write!(out, " data={}", common.data_size);
    }
    out.push('\n');

    match &block.fields {
        Fields::Main(main) => {
            let _ = write!(
                out,
                "      archive flags=0x{:x}({})",
                main.flags,
                names(main.flags, ARCHIVE_FLAGS_5)
            );
            if let Some(n) = main.volume_number {
                let _ = write!(out, " volume_number={n}");
            }
            out.push('\n');
            print_extra(out, head, &common);
        }
        Fields::File(file) => {
            let dict = match file.method {
                crate::types::Method::Compressed { dictionary, .. } => dictionary,
                crate::types::Method::Stored => {
                    file.dictionary.unwrap_or((128 << 10) << file.dict_bits)
                }
            };
            let _ = writeln!(
                out,
                "      name={} fflags=0x{:x}({}) unp={} attr=0x{:x} host={} ver={} solid={} method={} dict={}KiB",
                brepr(&head[file.raw_name.start as usize..file.raw_name.end as usize]),
                file.file_flags,
                names(file.file_flags, FILE_FLAGS_5),
                file.unpacked_size.unwrap_or(0),
                file.attributes,
                file.host_raw,
                file.unpack_version,
                u8::from(file.solid),
                file.method_code,
                dict / 1024,
            );
            // The header's OWN field, which file flag 0x0002 announces.
            // A member whose time is in an extra TIME record has no field
            // here at all and prints none (spec F 3.2.6.1); the record
            // prints below, under `extra TIME`.
            if let Some(t) = file.header_mtime {
                let _ = writeln!(
                    out,
                    "      mtime={} (unix {})",
                    stamp(t.unix_seconds),
                    t.unix_seconds
                );
            }
            if file.file_flags & rar5::FF_CRC32 != 0 {
                let _ = writeln!(out, "      data crc32={:08x}", file.raw_checksum);
            }
            print_extra(out, head, &common);
        }
        Fields::End(end) => {
            let _ = writeln!(
                out,
                "      end flags=0x{:x}({})",
                end.flags,
                if end.next_follows { "NOT_LAST" } else { "LAST" }
            );
        }
        Fields::Encryption => {
            if let Ok(rec) = rar5::parse_archive_crypt(head, &common) {
                let _ = write!(
                    out,
                    "      encryption ver=0 flags=0x{:x} kdf={} salt={}",
                    rec.flags,
                    rec.log2,
                    hex(&rec.salt)
                );
                if let Some(check) = &rec.check {
                    let _ = write!(out, " check={}", hex(check));
                }
                out.push('\n');
            }
        }
        _ => {}
    }
}

/// The length of the header size vint, so the printed `hsize` is the size
/// field's own value.
fn vint_len(bytes: &[u8]) -> usize {
    let mut at = 0usize;
    let _ = vint::read(bytes, &mut at);
    at
}

fn print_extra(out: &mut String, head: &[u8], common: &rar5::Common) {
    let Ok(start) = common.extra_start() else {
        return;
    };
    let Some(area) = head.get(start..common.head_len) else {
        return;
    };
    let _ = rar5::walk_extra(area, |rtype, body| {
        match (common.btype, rtype) {
            (rar5::TYPE_MAIN, rar5::XM_LOCATOR) => {
                if let Ok(loc) = rar5::parse_locator(body, 0) {
                    let _ = write!(out, "      extra LOCATOR flags=0x{:x}", loc.flags);
                    if let Some(v) = loc.raw_quick_open {
                        let _ = write!(out, " quick_open_offset={v}");
                    }
                    if let Some(v) = loc.raw_recovery {
                        let _ = write!(out, " recovery_offset={v}");
                    }
                    out.push('\n');
                }
            }
            (_, rar5::XF_CRYPT) => {
                if let Ok(rec) = crate::crypto::Rar5Record::parse(body, true) {
                    let _ =
                        writeln!(
                        out,
                        "      extra CRYPT ver=0 flags=0x{:x}({}) kdf={} salt={} iv={} check={}",
                        rec.flags,
                        if rec.flags & 1 != 0 { "HAS_CHECK_VALUE" } else { "-" },
                        rec.log2,
                        hex(&rec.salt),
                        rec.iv.map(|iv| hex(&iv)).unwrap_or_default(),
                        rec.check.map(|c| hex(&c)).unwrap_or_default(),
                    );
                }
            }
            (_, rar5::XF_HASH) => {
                let mut at = 0usize;
                if let Some(kind) = vint::read(body, &mut at) {
                    if kind == rar5::HASH_BLAKE2SP {
                        if let Some(bytes) = body.get(at..at + 32) {
                            let _ =
                                writeln!(out, "      extra HASH type=0(BLAKE2sp) {}", hex(bytes));
                        }
                    }
                }
            }
            (rar5::TYPE_FILE | rar5::TYPE_SERVICE, rar5::XF_TIME) => {
                if let Some(times) = htime::parse(body) {
                    let _ = writeln!(
                        out,
                        "      extra TIME flags=0x{:x}({})",
                        times.flags,
                        names(times.flags, TIME_FLAGS_5)
                    );
                    for (name, slot) in [
                        ("mtime", times.mtime),
                        ("ctime", times.ctime),
                        ("atime", times.atime),
                    ] {
                        let Some(s) = slot else { continue };
                        let _ = write!(
                            out,
                            "        {name}={}.{:09} ",
                            stamp(s.at.unix_seconds),
                            s.raw_nanos
                        );
                        if times.unix_form {
                            let _ = writeln!(out, "(unix {} ns {})", s.raw, s.raw_nanos);
                        } else {
                            let _ = writeln!(out, "(filetime {})", s.raw);
                        }
                    }
                }
            }
            (_, rar5::RECOVERY_PERCENTAGE) => {
                let _ = writeln!(out, "      extra RECOVERY_PERCENT {}", hex(body));
            }
            _ => {}
        }
        Ok(())
    });
}

fn print_rar4(out: &mut String, head: &[u8], block: &Block, at: u64) -> bool {
    if matches!(block.fields, Fields::Marker) {
        label(out, at, "MARKER", 10);
        out.push_str("(signature)\n");
        return false;
    }
    let Ok(common) = rar4::parse_common(head) else {
        return true;
    };
    let name = match common.btype {
        rar4::T_MAIN => "MAIN",
        rar4::T_FILE => "FILE",
        rar4::T_COMMENT => "COMMENT",
        rar4::TYPE_76 => "TYPE_76",
        rar4::T_SUB_OLD => "SUB",
        rar4::OLD_RECOVERY_RECORD => "EARLY_REPAIR",
        rar4::TYPE_79 => "TYPE_79",
        rar4::SERVICE_BLOCK => "SERVICE",
        rar4::T_END => "END",
        _ => "OTHER",
    };
    label(out, at, name, 8);
    let _ = writeln!(
        out,
        "hsize={:<4} crc={:04x}{} flags=0x{:04x}",
        common.size,
        common.crc,
        if block.checksum_ok { "" } else { " BAD" },
        common.flags
    );
    match &block.fields {
        Fields::Main(main) => {
            let _ = writeln!(
                out,
                "      main flags=({})",
                names(main.flags, MAIN_FLAGS_4)
            );
            let r1 = u16::from_le_bytes([head[7], head[8]]);
            let r2 = u32::from_le_bytes([head[9], head[10], head[11], head[12]]);
            let _ = writeln!(out, "      reserved1=0x{r1:04x} reserved2=0x{r2:08x}");
            if main.headers_encrypted {
                out.push_str("      HEADERS ENCRYPTED: nothing past this point is parsable\n");
                return true;
            }
        }
        Fields::File(file) => {
            let _ = writeln!(
                out,
                "      name={} psize={} usize={} host={}({}) crc={:08x}",
                brepr(&head[file.raw_name.start as usize..file.raw_name.end as usize]),
                file.packed_size,
                file.unpacked_size.unwrap_or(0),
                file.host_raw,
                host_name(file.host_raw),
                file.raw_checksum,
            );
            let _ = writeln!(
                out,
                "      unp_ver={} method=0x{:02x} attr=0x{:x} dictbits={} ftime={} flags=({})",
                file.unpack_version,
                file.method_code,
                file.attributes,
                file.dict_bits,
                file.mtime
                    .map(|t| stamp(t.unix_seconds))
                    .unwrap_or_default(),
                names(file.file_flags, FILE_FLAGS_4),
            );
        }
        Fields::End(end) => {
            let _ = writeln!(out, "      end flags=({})", names(end.flags, END_FLAGS_4));
        }
        _ => {}
    }
    false
}

fn host_name(raw: u8) -> &'static str {
    match raw {
        0 => "MS-DOS",
        1 => "OS/2",
        2 => "Win32",
        3 => "Unix",
        4 => "MacOS",
        5 => "BeOS",
        _ => "?",
    }
}

fn print_rar13(out: &mut String, head: &[u8], block: &Block, at: u64) {
    match &block.fields {
        Fields::Main(main) => {
            label(out, at, "ARCHIVE", 8);
            let size = u16::from_le_bytes([head[4], head[5]]);
            let _ = writeln!(
                out,
                "size={} flags=0x{:02x}({})",
                size,
                main.flags,
                names(main.flags, ARCHIVE_FLAGS_13)
            );
        }
        Fields::File(file) => {
            label(out, at, "FILE", 8);
            let hsize = u16::from_le_bytes([head[10], head[11]]);
            let _ = writeln!(
                out,
                "hsize={:<4} crc16={:04x} flags=0x{:02x}({})",
                hsize,
                file.raw_checksum,
                file.file_flags,
                names(file.file_flags, FILE_FLAGS_13)
            );
            let _ = writeln!(
                out,
                "      name={} psize={} usize={} attr=0x{:x} ver={} method={} ftime={}",
                brepr(&head[file.raw_name.start as usize..file.raw_name.end as usize]),
                file.packed_size,
                file.unpacked_size.unwrap_or(0),
                file.attributes,
                file.unpack_version,
                file.method_code,
                file.mtime
                    .map(|t| stamp(t.unix_seconds))
                    .unwrap_or_default(),
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod labels {
    use super::*;

    /// Spec F 5.2, "the ten names": the labels a walk prints for the
    /// header bits among them, each from what the specification says the
    /// bit means. Main flag 0x0020 has no stated meaning (3.3.4) and is
    /// printed as the walk prints any bit without one. The block words of
    /// the same table (`TYPE_76`, `EARLY_REPAIR`, `TYPE_79`, `SERVICE`)
    /// and `RECOVERY_PERCENT` are held by the expected walks of
    /// `vectors-F`. Three of the labels are the ones chosen again on 9 Oct
    /// 2026: `HAS_PART_INDEX`, `RECOVERY_PERCENT` and `EDITOR_MAY_DROP`,
    /// the last printed for the older container's flag 0x4000 too, which
    /// the walk gave the same word before and the expected walks hold.
    #[test]
    fn a_walk_prints_the_labels_of_section_5_2() {
        assert_eq!(names(0x0004, HEAD_FLAGS_5), "EDITOR_MAY_DROP");
        assert_eq!(names(0x0002, ARCHIVE_FLAGS_5), "HAS_PART_INDEX");
        assert_eq!(names(0x0002, FILE_FLAGS_5), "MTIME");
        assert_eq!(names(0x0100, FILE_FLAGS_4), "HIGH_SIZES");
        for table in [MAIN_FLAGS_4, FILE_FLAGS_4, END_FLAGS_4] {
            assert_eq!(names(0xc000, table), "EDITOR_MAY_DROP|LENGTH_FOLLOWS");
        }
        assert_eq!(names(0x0020, MAIN_FLAGS_4), "0x20?");
    }
}
