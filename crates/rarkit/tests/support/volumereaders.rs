//! One member set and one table of volume-set shapes, shared by
//! `tests/volume_reader_pins.rs` and `tests/volume_reader_batch.rs`.
//!
//! Everything here is the public API as it stood before a volume set
//! batched its reader members, so that the pins file can be built, as it
//! is, against the parent of that change and print the digests its
//! writer gave.
#![allow(dead_code)]

use std::io::Cursor;

use rarkit::{
    ChecksumKind, Entropy, MemberSpec, MemoryPolicy, Password, Payload, Progress, Rar4Version,
    WriteFormat, WriteMethod, WriteOptions, WriteReport, Writer,
};

pub const PASSWORD: &str = "volume readers";

/// The dictionary every row names: two MiB, which is also one WINDOW, so
/// a member of 1.1 MiB is batched and sampled, and one of 2.2 MiB is
/// longer than a window and takes the windowed walk.
pub const DICTIONARY: u64 = 2 << 20;

/// One member: its name, its bytes, whether it is a directory.
pub struct Member {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub directory: bool,
}

fn step(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Bytes with nothing in them to compress.
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0xD6E8_FEB8_6659_FD93) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&step(&mut state).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The set: small members by the dozen, which is what a batch and the
/// worker team are for, with every other kind of member standing among
/// them where it can end a batch or meet a boundary: a directory, an
/// empty member, a member spec G 3.8.3 samples and compresses, one it
/// samples and STORES, one longer than a window, and small noise the
/// rule does not sample.
pub fn members() -> Vec<Member> {
    let file = |name: String, data: Vec<u8>| Member {
        name: name.into_bytes(),
        data,
        directory: false,
    };
    let mut out = Vec::new();
    out.push(Member {
        name: b"tree".to_vec(),
        data: Vec::new(),
        directory: true,
    });
    for i in 0..30u64 {
        let len = 3_000 + (i as usize * 7_919) % 57_000;
        out.push(file(
            format!("tree/a{i:02}.c"),
            rarkit_testdata::chatter(i + 1, len),
        ));
    }
    out.push(file("tree/empty.h".into(), Vec::new()));
    out.push(file(
        "tree/sampled.txt".into(),
        rarkit_testdata::chatter(101, 1_150_000),
    ));
    for i in 0..6u64 {
        out.push(file(
            format!("tree/b{i:02}.c"),
            rarkit_testdata::chatter(i + 40, 9_000 + i as usize * 1_733),
        ));
    }
    out.push(file("tree/stored.bin".into(), noise(1_100_000, 7)));
    for i in 0..8u64 {
        out.push(file(
            format!("tree/c{i:02}.c"),
            rarkit_testdata::chatter(i + 60, 5_000 + i as usize * 4_111),
        ));
    }
    out.push(file(
        "tree/long.txt".into(),
        rarkit_testdata::chatter(202, 2_300_000),
    ));
    out.push(file("tree/small-noise.bin".into(), noise(21_000, 9)));
    for i in 0..10u64 {
        out.push(file(
            format!("tree/d{i:02}.c"),
            rarkit_testdata::chatter(i + 80, 2_000 + i as usize * 2_503),
        ));
    }
    out
}

/// A set built so that a solid batch's estimate of the room is WRONG, and
/// its tail lands past a volume boundary: members that pack to almost
/// nothing, which teach the run a ratio near zero, then small members of
/// noise (under the size spec G 3.8.3 samples, so they go to the encoder)
/// that do not pack at all. A batch stages a volume's worth of them by
/// the ratio it has seen, the volume takes a handful, and the rest are
/// discarded at the boundary and staged again; and again in the volumes
/// after, until the ratio has caught up. Text follows, so the ratio moves
/// the other way too.
pub fn ragged() -> Vec<Member> {
    let file = |name: String, data: Vec<u8>| Member {
        name: name.into_bytes(),
        data,
        directory: false,
    };
    let mut out = Vec::new();
    for i in 0..12u64 {
        out.push(file(
            format!("r/flat{i:02}.dat"),
            vec![b'a' + i as u8; 30_000],
        ));
    }
    for i in 0..40u64 {
        out.push(file(
            format!("r/noise{i:02}.dat"),
            noise(4_000 + (i as usize * 613) % 5_000, i + 300),
        ));
    }
    for i in 0..20u64 {
        out.push(file(
            format!("r/text{i:02}.dat"),
            rarkit_testdata::chatter(i + 400, 6_000 + i as usize * 911),
        ));
    }
    for i in 0..10u64 {
        out.push(file(format!("r/tail{i:02}.dat"), noise(7_000, i + 500)));
    }
    out
}

/// One shape of volume set.
#[derive(Clone)]
pub struct Row {
    pub label: String,
    pub format: WriteFormat,
    pub level: u8,
    pub solid: bool,
    /// The cap, and whether it bounds the whole FILE (`volume_file_size`)
    /// or the payload (`volume_size`).
    pub cap: u64,
    pub file_bound: bool,
    pub password: bool,
    pub encrypt_headers: bool,
    pub checksum: ChecksumKind,
    /// A ceiling the caller NAMES, where the row has one.
    pub ceiling: Option<u64>,
}

impl Row {
    fn new(family: &str, format: WriteFormat, level: u8, solid: bool, cap: u64) -> Row {
        Row {
            label: format!(
                "{family}/m{level}/{}/{cap}",
                if solid { "solid" } else { "plain" }
            ),
            format,
            level,
            solid,
            cap,
            file_bound: true,
            password: false,
            encrypt_headers: false,
            checksum: ChecksumKind::Crc32,
            ceiling: None,
        }
    }

    fn tagged(mut self, tag: &str) -> Row {
        self.label = format!("{}+{tag}", self.label);
        self
    }

    pub fn options(&self) -> WriteOptions {
        WriteOptions {
            format: self.format,
            method: WriteMethod::Compressed {
                level: self.level,
                dictionary: Some(DICTIONARY),
            },
            solid: self.solid,
            filters: if matches!(self.format, WriteFormat::Rar4(_)) {
                rarkit::FilterPolicy::Off
            } else {
                rarkit::FilterPolicy::default()
            },
            volume_file_size: self.file_bound.then_some(self.cap),
            volume_size: (!self.file_bound).then_some(self.cap),
            password: self.password.then(|| Password::new(PASSWORD.as_bytes())),
            encrypt_headers: self.encrypt_headers,
            checksum: self.checksum,
            // The same salts and vectors on every run, so an encrypted
            // set can be compared byte for byte (spec G 3.13).
            entropy: Entropy::Seeded([0x5a; 32]),
            memory: self
                .ceiling
                .map_or_else(MemoryPolicy::default, MemoryPolicy::from_limit),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        }
    }
}

/// A cap a batch of this set does not fit: a volume holds a few of the
/// small members' packed bytes, so batches are cut by the room and
/// discarded at boundaries.
pub const SMALL_CAP: u64 = 40_000;
/// A cap of several batches.
pub const WIDE_CAP: u64 = 400_000;

/// Every shape: both families at levels 1 to 5, solid and not, at a cap
/// smaller than a batch and at one of several; then, at level 3, a
/// password, encrypted headers, the BLAKE2sp checksum, a payload bound in
/// place of the file bound, and a ceiling the caller names.
pub fn rows() -> Vec<Row> {
    let r5 = WriteFormat::Rar5;
    let r4 = WriteFormat::Rar4(Rar4Version::V29);
    let mut out = Vec::new();
    for (family, format) in [("r5", r5), ("r4", r4)] {
        for level in 1..=5 {
            for solid in [true, false] {
                for cap in [SMALL_CAP, WIDE_CAP] {
                    out.push(Row::new(family, format, level, solid, cap));
                }
            }
        }
    }
    for solid in [true, false] {
        let mut row = Row::new("r5", r5, 3, solid, SMALL_CAP).tagged("pw");
        row.password = true;
        out.push(row);
        let mut row = Row::new("r5", r5, 3, solid, SMALL_CAP).tagged("hp");
        row.password = true;
        row.encrypt_headers = true;
        out.push(row);
        let mut row = Row::new("r4", r4, 3, solid, SMALL_CAP).tagged("pw");
        row.password = true;
        out.push(row);
        // Header encryption is a RAR 4.0 feature; a 2.9 target refuses it.
        let mut row = Row::new(
            "r4",
            WriteFormat::Rar4(Rar4Version::V40),
            3,
            solid,
            SMALL_CAP,
        )
        .tagged("hp");
        row.password = true;
        row.encrypt_headers = true;
        out.push(row);
        let mut row = Row::new("r5", r5, 3, solid, SMALL_CAP).tagged("blake2");
        row.checksum = ChecksumKind::Blake2sp;
        out.push(row);
        let mut row = Row::new("r5", r5, 3, solid, 30_000).tagged("payload-bound");
        row.file_bound = false;
        out.push(row);
        let mut row = Row::new("r5", r5, 3, solid, SMALL_CAP).tagged("mm512");
        row.ceiling = Some(512 << 20);
        out.push(row);
        let mut row = Row::new("r5", r5, 5, solid, SMALL_CAP).tagged("mm96");
        row.ceiling = Some(96 << 20);
        out.push(row);
    }
    out
}

/// The rows of the [`ragged`] set: solid, both families, at the chain
/// levels and the tree's, with and without a password, at the small cap,
/// in `add` order (the sorted order would group the members another way
/// than the set is built).
pub fn ragged_rows() -> Vec<Row> {
    let mut out = Vec::new();
    for (family, format) in [
        ("ragged-r5", WriteFormat::Rar5),
        ("ragged-r4", WriteFormat::Rar4(Rar4Version::V29)),
    ] {
        for level in [1, 3, 5] {
            out.push(Row::new(family, format, level, true, SMALL_CAP));
        }
        let mut row = Row::new(family, format, 3, true, SMALL_CAP).tagged("pw");
        row.password = true;
        out.push(row);
        out.push(Row::new(family, format, 3, false, SMALL_CAP));
    }
    out
}

/// Every set with its rows, and whether its members are written in `add`
/// order (`MemberOrder::AsAdded`) rather than a solid archive's sorted
/// order.
pub fn sets() -> Vec<(Vec<Member>, Vec<Row>, bool)> {
    vec![(members(), rows(), false), (ragged(), ragged_rows(), true)]
}

/// `row`'s options, in `add` order where `as_added`.
pub fn options_of(row: &Row, as_added: bool) -> WriteOptions {
    let mut options = row.options();
    if as_added {
        options.order = rarkit::MemberOrder::AsAdded;
    }
    options
}

/// How a member's bytes are handed to the writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hand {
    /// `Payload::Bytes`, which a volume set batched before this change.
    Bytes,
    /// `Payload::Reader`, as the command line hands every member.
    Reader,
}

/// Writes `members` under `options`, each member's bytes handed over as
/// `hand` says, and answers the volumes and the writer's report.
pub fn write<P: Progress>(
    options: WriteOptions,
    members: &[Member],
    hand: Hand,
    progress: &mut P,
) -> (Vec<Vec<u8>>, WriteReport) {
    let mut readers: Vec<Cursor<&[u8]>> = members
        .iter()
        .map(|member| Cursor::new(member.data.as_slice()))
        .collect();
    write_from(options, members, &mut readers, hand, progress).expect("finish_volumes")
}

/// [`write`] through the caller's own readers, one a member, answering
/// the writer's error where it ends in one.
pub fn write_from<R: std::io::Read + Send, P: Progress>(
    options: WriteOptions,
    members: &[Member],
    readers: &mut [R],
    hand: Hand,
    progress: &mut P,
) -> rarkit::Result<(Vec<Vec<u8>>, WriteReport)> {
    let mut writer = Writer::new(options).expect("options");
    for (member, reader) in members.iter().zip(readers.iter_mut()) {
        let payload = if member.directory || member.data.is_empty() || hand == Hand::Bytes {
            Payload::Bytes(&member.data)
        } else {
            Payload::Reader {
                reader,
                size: member.data.len() as u64,
                crc32: None,
            }
        };
        writer
            .add(MemberSpec {
                name: &member.name,
                payload,
                mtime: None,
                attributes: if member.directory {
                    0o755 << 16
                } else {
                    0o644 << 16
                },
                host_os: rarkit::HostOs::Unix,
                is_directory: member.directory,
            })
            .expect("add");
    }
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let report = writer.finish_volumes_with(&mut volumes, progress)?;
    Ok((volumes, report))
}

/// One digest over a whole set: every volume's length and bytes, in
/// order.
pub fn set_digest(volumes: &[Vec<u8>]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for volume in volumes {
        hash.update((volume.len() as u64).to_le_bytes());
        hash.update(volume);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
