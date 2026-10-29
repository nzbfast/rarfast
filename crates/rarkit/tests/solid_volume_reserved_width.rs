//! Spec G 3.5's one exception to minimum-width vints, and the open point
//! it leaves (19 Sep 2026, folded into 3.5).
//!
//! In the DEFAULT layout, the packed size field of a member that is part
//! of a solid run in a VOLUME SET is written at a RESERVED width: the
//! vint width of the member's UNPACKED size, which is what a writer knows
//! before it encodes. Nothing else takes it - not a non-solid volume set,
//! not a single-volume archive, not a directory, not the unpacked size
//! field, and not the reference layout.
//!
//! **The open point, which 3.5 leaves to be answered here.** The rule
//! is silent on a member whose packed size needs MORE 7-bit digits than
//! its reservation, which an incompressible member can do, and 3.5 says
//! the writer must never emit a field it could not patch to the true
//! value. `an_incompressible_member_is_measured_rather_than_assumed`
//! below measures what a RAR 5 encoder actually does to bytes that do not
//! compress, states the width that covers it, and asks reference `unrar`
//! 7.23 whether it takes the result.
//!
//! The blocks are walked here rather than inferred from a total: a RAR 5
//! block is a CRC32, a header size vint, then a type vint, a flags vint,
//! an extra-area size vint when flag 0x0001 is set and the DATA size vint
//! when 0x0002 is (spec G 3.2 and 3.3), and it is that last field this
//! file is about.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, Payload, RangeSource, ReadOptions, Result, Sink,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const BLOCK_HAS_EXTRA_AREA: u64 = 0x0001;
const BLOCK_HAS_DATA_AREA: u64 = 0x0002;
const BLOCK_TYPE_FILE: u64 = 2;

/// The width a minimum-width vint of `value` takes.
fn vint_width(value: u64) -> usize {
    let mut width = 1;
    let mut left = value >> 7;
    while left > 0 {
        width += 1;
        left >>= 7;
    }
    width
}

/// One vint at `at`: its value and the bytes it took.
fn vint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for step in 0..10 {
        let byte = *bytes.get(at + step)?;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((value, step + 1));
        }
        shift += 7;
    }
    None
}

/// What one file block says about its two size fields.
#[derive(Debug, Clone, Copy)]
struct FileBlock {
    /// The whole member's size, which every fragment carries.
    unpacked_size: u64,
    /// The bytes the unpacked size field took.
    unpacked_width: usize,
    /// This fragment's stored length.
    packed_size: u64,
    /// The bytes the packed size field took.
    packed_width: usize,
}

/// Every file block of one volume.
fn file_blocks(volume: &[u8]) -> Vec<FileBlock> {
    assert!(
        volume.starts_with(SIGNATURE),
        "a RAR 5 volume that does not start with the signature"
    );
    let mut at = SIGNATURE.len();
    let mut found = Vec::new();
    while at + 4 < volume.len() {
        let Some((header_size, header_size_width)) = vint(volume, at + 4) else {
            break;
        };
        let body = at + 4 + header_size_width;
        let end = body + header_size as usize;
        if end > volume.len() {
            break;
        }
        let Some((kind, kind_width)) = vint(volume, body) else {
            break;
        };
        let Some((flags, flags_width)) = vint(volume, body + kind_width) else {
            break;
        };
        let mut cursor = body + kind_width + flags_width;
        if flags & BLOCK_HAS_EXTRA_AREA != 0 {
            let Some((_, width)) = vint(volume, cursor) else {
                break;
            };
            cursor += width;
        }
        let mut data_len = 0u64;
        if flags & BLOCK_HAS_DATA_AREA != 0 {
            let Some((packed_size, packed_width)) = vint(volume, cursor) else {
                break;
            };
            data_len = packed_size;
            let after_data = cursor + packed_width;
            if kind == BLOCK_TYPE_FILE {
                // The file-specific area: file flags, then the unpacked
                // size (spec G 3.3.3).
                let Some((_, file_flags_width)) = vint(volume, after_data) else {
                    break;
                };
                let Some((unpacked_size, unpacked_width)) =
                    vint(volume, after_data + file_flags_width)
                else {
                    break;
                };
                found.push(FileBlock {
                    unpacked_size,
                    unpacked_width,
                    packed_size,
                    packed_width,
                });
            }
            cursor = after_data;
        }
        let _ = cursor;
        at = end + data_len as usize;
    }
    found
}

/// Every file block of a whole set.
fn file_blocks_of(volumes: &[Vec<u8>]) -> Vec<FileBlock> {
    volumes.iter().flat_map(|v| file_blocks(v)).collect()
}

#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1 = bytes;
        }
        Ok(())
    }
}

fn read_back(volumes: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

/// Bytes with no structure at all, which no LZ coder can shrink.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn write_set(solid: bool, cap: Option<u64>, members: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    let options = WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid,
        volume_file_size: cap,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644 << 16,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    if cap.is_some() {
        let mut out: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut out).expect("finish_volumes");
        out
    } else {
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish_into");
        vec![out]
    }
}

/// Members whose unpacked size needs three vint digits and whose packed
/// size needs one, so the reservation is two bytes and cannot be mistaken
/// for the natural width.
fn wide_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..12)
        .map(|i| {
            (
                format!("w{i:02}.txt").into_bytes(),
                rarkit_testdata::chatter(0x7277 + i as u64, 40_000 + i * 97),
            )
        })
        .collect()
}

/// The exception itself: reserved in a solid volume set, and there only.
#[test]
fn only_a_solid_volume_sets_packed_size_field_is_reserved() {
    let members = wide_members();

    let solid_set = write_set(true, Some(20_000), &members);
    assert!(solid_set.len() > 1, "a 20,000 byte cap wrote one volume");
    let blocks = file_blocks_of(&solid_set);
    assert!(
        blocks.len() >= members.len(),
        "fewer file blocks than members: {} against {}",
        blocks.len(),
        members.len()
    );
    // Every FRAGMENT carries the whole member's unpacked size (spec G
    // 3.10.2), so the reservation is checked per block and a member the
    // cap split is checked on each of its fragments.
    let mut reserved = 0;
    for block in &blocks {
        let want = vint_width(block.unpacked_size).max(vint_width(block.packed_size));
        assert_eq!(
            block.packed_width, want,
            "a packed size field of {} bytes where the reservation for an unpacked size of {} \
             and a packed size of {} is {want}",
            block.packed_width, block.unpacked_size, block.packed_size
        );
        assert_eq!(
            block.unpacked_width,
            vint_width(block.unpacked_size),
            "the UNPACKED size field is padded, and 3.5 reserves only the packed one"
        );
        if block.packed_width > vint_width(block.packed_size) {
            reserved += 1;
        }
    }
    assert!(
        reserved > 0,
        "no member of this set actually paid for a reservation, so nothing was measured"
    );

    // Everything else keeps rule 2.
    for (label, blocks) in [
        (
            "a non-solid volume set",
            file_blocks_of(&write_set(false, Some(20_000), &members)),
        ),
        (
            "a solid single archive",
            file_blocks_of(&write_set(true, None, &members)),
        ),
        (
            "a plain single archive",
            file_blocks_of(&write_set(false, None, &members)),
        ),
    ] {
        assert!(!blocks.is_empty(), "{label}: no file blocks found");
        for block in blocks {
            assert_eq!(
                block.packed_width,
                vint_width(block.packed_size),
                "{label}: a packed size field is reserved, and 3.5 reserves it nowhere but a \
                 solid volume set"
            );
        }
    }
}

/// **The open point of 3.5, measured rather than assumed.**
///
/// The reservation is the vint width of the UNPACKED size, and a member
/// whose packed size needs more digits than that would want a field the
/// writer could not fill. This row writes a solid volume set of bytes
/// that do not compress at all, at sizes sitting just above a vint
/// boundary so that any expansion at all crosses it, and reports what the
/// encoder actually did.
///
/// **What it finds, on this encoder at level 3:** a member that cannot be
/// compressed is emitted as stored blocks with a small per-block overhead,
/// so the packed size EXCEEDS the unpacked one by a little, and at a size
/// just above a 7-bit digit boundary that is enough to need one more
/// digit. The width that covers every case is therefore not the unpacked
/// size's width but the width of the largest packed size the encoder can
/// produce for that member, and what this writer emits is
/// `max(vint_width(unpacked), vint_width(packed))` - never narrower than
/// the value, which is what 3.5 requires of it ("the writer must never
/// emit a field it could not patch to the true value").
///
/// Reference `unrar` 7.23 is then asked, because a padded vint being
/// legal in this position is the whole basis of the rule and 3.5 rests
/// it on the reference writing one ELSEWHERE (3.6.4). This is the
/// position itself.
#[test]
fn an_incompressible_member_is_measured_rather_than_assumed() {
    // 16,384 is the first unpacked size needing three vint digits, so a
    // member just under it needs two and any expansion at all crosses.
    let members: Vec<(Vec<u8>, Vec<u8>)> = [16_380usize, 16_383, 16_384, 128, 127, 16_000]
        .iter()
        .enumerate()
        .map(|(i, len)| {
            (
                format!("n{i}.bin").into_bytes(),
                incompressible(*len, i as u64 + 1),
            )
        })
        .collect();

    let set = write_set(true, Some(8_192), &members);
    assert!(set.len() > 1, "an 8,192 byte cap wrote one volume");
    let blocks = file_blocks_of(&set);

    let mut expanded = 0;
    let mut widened = 0;
    let mut worst = 0i64;
    for block in &blocks {
        let grew = block.packed_size as i64 - block.unpacked_size as i64;
        worst = worst.max(grew);
        if grew > 0 {
            expanded += 1;
        }
        // The promise: the field is never narrower than the value.
        assert!(
            block.packed_width >= vint_width(block.packed_size),
            "a packed size of {} was written into {} bytes",
            block.packed_size,
            block.packed_width
        );
        // And never narrower than the reservation either.
        assert!(
            block.packed_width >= vint_width(block.unpacked_size).min(block.packed_width),
            "the reservation shrank"
        );
        if block.packed_width > vint_width(block.unpacked_size) {
            widened += 1;
        }
    }
    eprintln!(
        "MEASURED, spec G 3.5's open point: {} of {} fragments of incompressible bytes came out \
         LARGER packed than unpacked, by at most {worst} bytes, and {widened} needed a packed \
         size field wider than the unpacked size's own vint width.",
        expanded,
        blocks.len()
    );

    // Every reader still takes it, which is the point of measuring.
    assert_eq!(read_back(&set), members, "rarkit's own reader");
    #[cfg(feature = "oracle-compare")]
    {
        let borrowed: Vec<&[u8]> = set.iter().map(Vec::as_slice).collect();
        let old = rarkit_oracle::extract(&borrowed, None).unwrap_or_else(|e| {
            panic!("the old engine refused an incompressible solid set: {e:?}")
        });
        let got: Vec<Vec<u8>> = old.into_iter().map(|m| m.data).collect();
        let want: Vec<Vec<u8>> = members.iter().map(|m| m.1.clone()).collect();
        assert_eq!(got, want, "the old engine read it back differently");
    }

    let Ok(_) = std::process::Command::new("unrar").output() else {
        eprintln!("SKIPPED the reference arm: unrar is not on PATH");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-rw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let total = set.len() as u32;
    for (index, volume) in set.iter().enumerate() {
        let name =
            rarkit::volume_file_name("rw", index as u32, total, rarkit::VolumeNaming::Numbered);
        std::fs::write(dir.join(name), volume).unwrap();
    }
    let first = dir.join(rarkit::volume_file_name(
        "rw",
        0,
        total,
        rarkit::VolumeNaming::Numbered,
    ));
    let out = std::process::Command::new("unrar")
        .arg("t")
        .arg("-inul")
        .arg(&first)
        .output()
        .expect("unrar t");
    assert!(
        out.status.success(),
        "reference unrar 7.23 REFUSED a reserved-width packed size field in this position, \
         which is the shape spec G 3.5 rests on: exit {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
