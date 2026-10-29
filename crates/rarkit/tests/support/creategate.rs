//! The CREATE legs of spec G section 7.1 and spec H3 section 8.5, as
//! shapes: one descriptor per leg, an arm that writes it with rarkit's
//! `Writer`, an arm that writes it with the old engine through
//! `rarkit-oracle`'s create adapters, and the check that says the two
//! arms wrote the same archive.
//!
//! **Why the shapes live here and not in the bench.** Spec G 7.1's gate
//! is a RATIO against the old engine, and the bench record could not compute
//! one because the oracle had no call that wrote an archive. It has one
//! now (`create`, `create_streamed`, `create_rar20`), so every create leg
//! can have a second arm - and a second arm is only worth a ratio if both
//! arms wrote the SAME archive. Two correct writers of one format do not
//! produce the same bytes, so the check cannot be a byte comparison of
//! the archives; it is a byte comparison of what comes back OUT of them.
//! the gate bench times the arms and `tests/create_gate.rs` checks
//! them, from this one list, so neither can drift from the other.
//!
//! Every shape but the `code` ones sets `filters: Off` on the rarkit arm
//! and leaves the oracle's `filters` at its default `false` (by design:
//! rarkit emits no filter records, so an old arm that emits them is
//! measuring a different archive and the ratio over it means nothing).
//! The `code` shapes are the exception, and the reason dates from
//! 28 Sep 2026: rarkit now SHIPS filters on program files at level 3 and
//! up, so a gate that only ever timed `Off` had no row for the path a
//! user's create actually takes. Those shapes give rarkit's arm the
//! SHIPPED policy (`WriteOptions::default().filters`) and the old arm
//! ITS shipped default, which writes no filter: each engine as it ships,
//! over the same executable bytes.
//!
//! A single-archive shape goes through `Writer::finish_seek`, which is
//! the entry whose contract matches the old engine's buffered writers;
//! `rarkit_archive` says why where it calls it.
#![allow(dead_code)]
// The exporter cut the cases of this file that need a crate this tree
// does not have; imports and helpers only they used are left in place.
#![allow(unused_imports, unused_macros)]

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    ChecksumKind, Disposition, Entropy, FilterPolicy, HostOs, MemberInfo, MemberOutcome,
    MemberSpec, Password, Payload, RangeSource, Rar4Version, ReadOptions, Sink, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

/// One seed for every leg, so both arms are deterministic and a leg that
/// draws salts draws the same ones on every run (spec G 3.1).
pub const GATE_SEED: [u8; 32] = [
    0x67, 0x61, 0x74, 0x65, 0x2D, 0x73, 0x65, 0x65, 0x64, 0x2D, 0x73, 0x70, 0x65, 0x63, 0x2D, 0x47,
    0x2D, 0x37, 0x2E, 0x31, 0x2D, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x2D, 0x6C, 0x65, 0x67, 0x73,
];

/// The password the encrypted legs use. A seeded archive has no secrecy
/// and this one is in the source, which is what a bench leg wants.
pub const GATE_PASSWORD: &[u8] = b"spec-G-7.1-gate";

/// Which archive family a leg writes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    /// RAR 5.
    Rar5,
    /// RAR 2.9, which is what the RAR 4 legs mean by "RAR 4".
    Rar29,
    /// RAR 4.0, reached only where the old engine refuses 2.9 - it has no
    /// header encryption on a 2.9 target.
    Rar40,
}

/// What a leg compresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Corpus {
    /// Bytes with no structure, which no writer compresses: the shape the
    /// stored legs want, because a stored leg is a copy and an I/O floor.
    Random,
    /// This repository's own sources and specifications, drawn a word at a
    /// time by a seeded generator. Real token statistics and no stride
    /// (spec H3 8.6 refuses a fixed-stride synthetic corpus).
    Text,
    /// A fixed window of a REAL x86-64 executable, read from a file on the
    /// box: see [`code_corpus`]. The one corpus here that a filter pays
    /// on, which is what the `code` legs are for.
    Code,
}

/// Which old-engine writer family a leg's second arm reaches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OldArm {
    /// `rarkit_oracle::create`: the BUFFERED writers, which are the ones
    /// the baseline profile measured, so they are the ones the 0.97x gate
    /// is against.
    Buffered,
    /// `rarkit_oracle::create_streamed`: the writers that read each member
    /// through a `Read` and never hold one whole. Spec G 7.3 makes the
    /// streamed path a structural requirement of its own.
    Streamed,
}

/// One create leg.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    /// The leg's name, as the bench harness prints it.
    pub name: &'static str,
    /// The family the archive is written in.
    pub family: Family,
    /// 0 is STORED; 1 to 5 are the compression levels of the same number.
    pub level: u8,
    /// The dictionary BOTH arms are told to use, or `None` for each
    /// writer's own default. A compressed leg names one, because the
    /// dictionary is the search space the encoder pays for (spec G 7.3)
    /// and two arms at two window sizes are not one ratio.
    pub dictionary: Option<u64>,
    /// What the members hold.
    pub corpus: Corpus,
    /// How many bytes of it, over all members.
    pub bytes: usize,
    /// How many members to cut those bytes into.
    pub members: usize,
    /// Payload bytes per volume, or `None` for one archive.
    pub volume_size: Option<u64>,
    /// Inline recovery record, in per cent.
    pub recovery_percent: Option<u32>,
    /// Encrypt the member data.
    pub encrypted: bool,
    /// Encrypt the headers as well.
    pub encrypt_headers: bool,
    /// One encoder run across every member.
    pub solid: bool,
    /// rarkit hands its payload as a `Read` rather than as a slice.
    pub reader_payload: bool,
    /// Which of the old engine's writer families the second arm reaches.
    pub old: OldArm,
    /// rarkit's arm writes with the filter policy rarkit SHIPS rather than
    /// `Off`; the old arm keeps its own default, which is no filter.
    pub shipped_filters: bool,
}

impl Shape {
    /// A stored single-member RAR 5 leg, which every other shape is built
    /// from with the `with_*` methods below.
    pub const fn new(name: &'static str, family: Family, corpus: Corpus, bytes: usize) -> Shape {
        Shape {
            name,
            family,
            level: 0,
            dictionary: None,
            corpus,
            bytes,
            members: 1,
            volume_size: None,
            recovery_percent: None,
            encrypted: false,
            encrypt_headers: false,
            solid: false,
            reader_payload: false,
            old: OldArm::Buffered,
            shipped_filters: false,
        }
    }

    /// At compression `level` over a `dictionary` byte window.
    pub const fn level(mut self, level: u8, dictionary: u64) -> Shape {
        self.level = level;
        self.dictionary = Some(dictionary);
        self
    }

    /// Cut into `members` members of equal size.
    pub const fn members(mut self, members: usize) -> Shape {
        self.members = members;
        self
    }

    /// Split into volumes of at most `bytes` payload bytes.
    pub const fn volumes(mut self, bytes: u64) -> Shape {
        self.volume_size = Some(bytes);
        self
    }

    /// With an inline recovery record of `percent` per cent.
    pub const fn recovery(mut self, percent: u32) -> Shape {
        self.recovery_percent = Some(percent);
        self
    }

    /// With the member data encrypted under [`GATE_PASSWORD`].
    pub const fn encrypted(mut self) -> Shape {
        self.encrypted = true;
        self
    }

    /// With the headers encrypted too, which implies the data is.
    pub const fn headers_encrypted(mut self) -> Shape {
        self.encrypted = true;
        self.encrypt_headers = true;
        self
    }

    /// One encoder run across every member.
    pub const fn solid(mut self) -> Shape {
        self.solid = true;
        self
    }

    /// Against the old engine's STREAMED writers rather than its buffered
    /// ones. On its own this changes only the OLD arm: it is what makes a
    /// level 5 leg one encode against one encode rather than one against
    /// the buffered writer's five.
    pub const fn old_streamed(mut self) -> Shape {
        self.old = OldArm::Streamed;
        self
    }

    /// rarkit's payload arrives as a `Read` and is never held whole, and
    /// the old arm is the streamed writer that does the same. This is the
    /// shape spec G 7.4 asks for by name and spec G 7.3 makes a
    /// structural requirement.
    pub const fn streamed(self) -> Shape {
        let mut shape = self.old_streamed();
        shape.reader_payload = true;
        shape
    }

    /// rarkit's arm writes with the filter policy it ships,
    /// and the old arm with the one IT ships, which is none.
    pub const fn shipped_filters(mut self) -> Shape {
        self.shipped_filters = true;
        self
    }

    /// The same shape with rarkit's filters `Off`, which is what the
    /// `g/detect/*` legs time the shipped policy against in one binary.
    pub const fn filters_off(mut self) -> Shape {
        self.shipped_filters = false;
        self
    }

    /// The same shape over `bytes` bytes and at most `members` members,
    /// with the volume size scaled by the same factor.
    ///
    /// This is what `tests/create_gate.rs` runs: the CHECK has to cover
    /// every leg on every `make ci`, and the legs themselves are sized
    /// for a bench rig rather than for a test suite.
    pub fn scaled(mut self, bytes: usize, members: usize) -> Shape {
        let factor = self.bytes as f64 / bytes as f64;
        if let Some(size) = self.volume_size {
            self.volume_size = Some(((size as f64 / factor) as u64).max(1024));
        }
        self.bytes = bytes;
        self.members = self.members.min(members);
        self
    }

    /// The password this leg reads and writes under, if any.
    pub fn password(&self) -> Option<&'static [u8]> {
        self.encrypted.then_some(GATE_PASSWORD)
    }

    fn write_format(&self) -> WriteFormat {
        match self.family {
            Family::Rar5 => WriteFormat::Rar5,
            Family::Rar29 => WriteFormat::Rar4(Rar4Version::V29),
            Family::Rar40 => WriteFormat::Rar4(Rar4Version::V40),
        }
    }

    /// The options rarkit's writer is given.
    pub fn rarkit_options(&self) -> WriteOptions {
        WriteOptions {
            format: self.write_format(),
            method: if self.level == 0 {
                WriteMethod::Stored
            } else {
                WriteMethod::Compressed {
                    level: self.level,
                    dictionary: self.dictionary,
                }
            },
            password: self.password().map(Password::new),
            encrypt_headers: self.encrypt_headers,
            solid: self.solid,
            volume_size: self.volume_size,
            recovery_percent: self.recovery_percent,
            checksum: ChecksumKind::Crc32,
            // Filters off, on both arms at once, except where a shape asks
            // for the shipped policy: see the module header.
            filters: if self.shipped_filters {
                WriteOptions::default().filters
            } else {
                FilterPolicy::Off
            },
            entropy: Entropy::Seeded(GATE_SEED),
            host_os: HostOs::Unix,
            ..WriteOptions::default()
        }
    }
}

// ---------------------------------------------------------------------
// The legs themselves: spec G section 7.4's list, plus the three shapes
// this change adds to it (encrypted, header encrypted, and a compressed
// volume set with a recovery record), plus spec H3 section 8.3 and 8.4's
// create legs in their ARCHIVE form.
//
// Sizes. The stored legs are spec G 7.2's own 128 MiB, because that is
// the size its RAR 4 RSS target is stated at. The compressed legs are
// 32 MiB of text, which is what the recorded absolute figures were
// taken at, so a ratio here sits beside a number already recorded. The
// encrypted and recovery legs are 64 MiB, which is enough for the cipher
// and the parity to be the leg rather than the framing and short enough
// that a rig can afford the rounds.
//
// Dictionary. Every compressed leg names 4 MiB on BOTH arms. The window
// is the search space the encoder pays for (spec G 7.3: 2 MiB against
// 32 MiB was 5.65 s against 111 s on one measured member), so two arms at
// two window sizes are two different pieces of work and their ratio is
// not a gate. 4 MiB is the window spec H3's own create legs use.
// ---------------------------------------------------------------------

const MIB: usize = 1 << 20;
const DICT: u64 = 4 << 20;

/// Every create leg, in the order the bench prints them.
pub const SHAPES: [Shape; 30] = [
    // Spec G 7.1's own list, stored half.
    Shape::new("g/create/rar5/m0", Family::Rar5, Corpus::Random, 128 * MIB),
    Shape::new("g/create/rar4/m0", Family::Rar29, Corpus::Random, 128 * MIB),
    // "a streamed -m0 leg from a reader payload, which is the shape
    // postfast drives and which no existing leg covers" (spec G 7.4).
    Shape::new(
        "g/create/rar5/m0/streamed",
        Family::Rar5,
        Corpus::Random,
        128 * MIB,
    )
    .streamed(),
    // 20,000 small members: the leg that measures the member table and
    // the header path rather than the copy.
    Shape::new(
        "g/create/rar5/m0/20k",
        Family::Rar5,
        Corpus::Random,
        20_000 * 64,
    )
    .members(20_000),
    // Spec G 7.1's own list, compressed half.
    Shape::new("g/create/rar5/m1", Family::Rar5, Corpus::Text, 32 * MIB).level(1, DICT),
    Shape::new("g/create/rar5/m3", Family::Rar5, Corpus::Text, 32 * MIB).level(3, DICT),
    Shape::new("g/create/rar5/m5", Family::Rar5, Corpus::Text, 32 * MIB).level(5, DICT),
    // The STRICTER reading of the level 5 leg. `create`'s level 5 is the
    // old engine's own, which encodes at levels 4 down to 1 as well and
    // keeps the smallest - five encodes, where rarkit's level 5 is one.
    // That is the arm the gate is against, because the buffered writers
    // are what the baseline profile measured, but it is a soft comparison
    // on wall. `create_streamed` is the same writer family doing ONE
    // encode at level 5's settings. Quote both, and say which.
    Shape::new(
        "g/create/rar5/m5/1pass",
        Family::Rar5,
        Corpus::Text,
        32 * MIB,
    )
    .level(5, DICT)
    .old_streamed(),
    Shape::new("g/create/rar4/m3", Family::Rar29, Corpus::Text, 32 * MIB).level(3, DICT),
    // The recovery record, on one archive and on a volume set.
    Shape::new(
        "g/create/rar5/m0/rr",
        Family::Rar5,
        Corpus::Random,
        64 * MIB,
    )
    .recovery(5),
    Shape::new(
        "g/create/rar5/m0/vol+rr",
        Family::Rar5,
        Corpus::Random,
        64 * MIB,
    )
    .volumes(15 << 20)
    .recovery(5),
    // Spec G 7.1's `-m3` volume set with a recovery record. The two `.rev`
    // volumes beside it are `rev5::create`'s and not `Writer`'s (spec G
    // 3.11), and the harness already times them as `rev/create`.
    Shape::new(
        "g/create/rar5/m3/vol+rr",
        Family::Rar5,
        Corpus::Text,
        32 * MIB,
    )
    .level(3, DICT)
    .volumes(2 << 20)
    .recovery(5),
    Shape::new("g/create/rar4/m3/rr", Family::Rar29, Corpus::Text, 32 * MIB)
        .level(3, DICT)
        .recovery(5),
    Shape::new(
        "g/create/rar4/m0/vol",
        Family::Rar29,
        Corpus::Random,
        64 * MIB,
    )
    .volumes(15 << 20),
    // Encryption, which spec G 3.12 builds in both families.
    Shape::new(
        "g/create/rar5/m0/pw",
        Family::Rar5,
        Corpus::Random,
        64 * MIB,
    )
    .encrypted(),
    Shape::new(
        "g/create/rar5/m0/hp",
        Family::Rar5,
        Corpus::Random,
        64 * MIB,
    )
    .headers_encrypted(),
    Shape::new(
        "g/create/rar4/m0/pw",
        Family::Rar29,
        Corpus::Random,
        64 * MIB,
    )
    .encrypted(),
    // RAR 4.0 rather than 2.9, and that is the old engine's boundary
    // rather than a preference: it refuses header encryption on a 2.9
    // target ("RAR 1.5 writer feature is not supported by Rar29"), so a
    // 2.9 header-encrypted leg would have one arm.
    Shape::new(
        "g/create/rar4/m0/hp",
        Family::Rar40,
        Corpus::Random,
        64 * MIB,
    )
    .headers_encrypted(),
    // A COMPRESSED member from a reader payload: spec G 3.7.3's windowed
    // encode against the old engine's streamed writer, which is the arm
    // doing the same work. It is the one create shape whose rarkit arm
    // never holds the member.
    Shape::new(
        "g/create/rar5/m3/streamed",
        Family::Rar5,
        Corpus::Text,
        32 * MIB,
    )
    .level(3, DICT)
    .streamed(),
    // SOLID sets, which spec H3's erratum of 19 Sep 2026 unblocked: one
    // encoder run across every member, each continuing the history of
    // the member before it. 64 members, because a solid set of one is a
    // plain archive with a bit set.
    Shape::new(
        "g/create/rar5/m3/solid",
        Family::Rar5,
        Corpus::Text,
        32 * MIB,
    )
    .level(3, DICT)
    .members(64)
    .solid(),
    Shape::new(
        "g/create/rar4/m3/solid",
        Family::Rar29,
        Corpus::Text,
        32 * MIB,
    )
    .level(3, DICT)
    .members(64)
    .solid(),
    // The same solid set as a VOLUME SET, which is the shape a poster
    // actually writes and the one this leg exists for. Until 19 Sep 2026
    // a volume set encoded a member at a time, because a volume boundary
    // ends a solid run (spec G 3.9) and where it falls is not known until
    // the packed bytes before it are written; the run is pipelined across
    // the members now and the boundary discards and re-encodes whatever
    // batch straddles it. The `old` arm here is the OLD ENGINE, so this
    // is the gate; the A/B of the pipeline's own depth is
    // `g/solid+vol/*/width` in the harness, both arms this engine.
    //
    // 2 MiB volumes over 32 MiB of text at `-m3`, which is the volume
    // size `g/create/rar5/m3/vol+rr` already uses, so a boundary falls
    // several times inside the run rather than once at the end.
    Shape::new(
        "g/create/rar5/m3/solid+vol",
        Family::Rar5,
        Corpus::Text,
        32 * MIB,
    )
    .level(3, DICT)
    .members(64)
    .solid()
    .volumes(2 << 20),
    Shape::new(
        "g/create/rar4/m3/solid+vol",
        Family::Rar29,
        Corpus::Text,
        32 * MIB,
    )
    .level(3, DICT)
    .members(64)
    .solid()
    .volumes(2 << 20),
    // The same set at level 5, which is the level whose finder is the
    // binary TREE: the index that carries across a solid member is a
    // different structure there, and its cost and its peak RSS are what
    // spec H3 section 8.3's structural requirements are about.
    Shape::new(
        "g/create/rar5/m5/solid",
        Family::Rar5,
        Corpus::Text,
        32 * MIB,
    )
    .level(5, DICT)
    .members(64)
    .solid(),
    // SPEC-H3 section 8.3's own legs, which every table in
    // the bench record until now has had to read across a scale
    // change: the targets there are set on a 128 MiB member, and the
    // create legs above are 32 MiB. One member, because 8.3's structural
    // requirement 1 is about a member longer than the working memory and
    // a set of small ones would not put it to the question.
    //
    // They are the heaviest legs in the harness by a wide margin (the
    // baseline profile has the old engine at 14.3 s and 2.0 GiB of RSS
    // for the level 5 one), so they are named apart from `g/create/*`
    // and a sweep that cannot afford them can pass `--only=g/`. They keep
    // `/create/` in the name, because that is what tells the harness's
    // `arms_must_agree` that these two arms are two ENGINES and their
    // archives are not expected to be the same bytes.
    Shape::new(
        "h3/create/rar5/m1/128m",
        Family::Rar5,
        Corpus::Text,
        128 * MIB,
    )
    .level(1, DICT),
    Shape::new(
        "h3/create/rar5/m3/128m",
        Family::Rar5,
        Corpus::Text,
        128 * MIB,
    )
    .level(3, DICT),
    Shape::new(
        "h3/create/rar5/m5/128m",
        Family::Rar5,
        Corpus::Text,
        128 * MIB,
    )
    .level(5, DICT),
    // The `code` legs: an EXECUTABLE at the three levels whose filter
    // policy differs (level 1 writes no filter, level 3
    // filters with the lazy parse on filtered blocks, level 5 at full
    // effort), rarkit at the policy it ships. Level 1 is the CONTROL: it
    // writes the same bytes as `Off`, which `g/detect/rar5/m1/code` holds
    // the harness to. 32 MiB, the compressed legs' own size, so each
    // reads beside the text leg of its level. The old arm is the buffered
    // writer at levels 1 and 3, as for every other gate leg, and the
    // STREAMED one at level 5: the buffered level 5 is five encodes (see
    // `g/create/rar5/m5/1pass`), about 29 s a round on this window
    // against rarkit's one, which no calibrator cap admits, so this leg
    // takes the stricter reading, one encode against one.
    Shape::new(
        "g/create/rar5/m1/code",
        Family::Rar5,
        Corpus::Code,
        32 * MIB,
    )
    .level(1, DICT)
    .shipped_filters(),
    Shape::new(
        "g/create/rar5/m3/code",
        Family::Rar5,
        Corpus::Code,
        32 * MIB,
    )
    .level(3, DICT)
    .shipped_filters(),
    Shape::new(
        "g/create/rar5/m5/code",
        Family::Rar5,
        Corpus::Code,
        32 * MIB,
    )
    .level(5, DICT)
    .old_streamed()
    .shipped_filters(),
];

/// The member names and bodies one shape asks for, cut out of `data`.
///
/// A leg's bytes are divided evenly and the last member takes the
/// remainder, so the members together are exactly `data` and an extracted
/// round trip can be compared against it whole.
pub fn members<'a>(shape: &Shape, data: &'a [u8]) -> Vec<(String, &'a [u8])> {
    let count = shape.members.max(1);
    let each = data.len() / count;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * each;
        let end = if index + 1 == count {
            data.len()
        } else {
            start + each
        };
        out.push((format!("m{index:05}.bin"), &data[start..end]));
    }
    out
}

/// Write one leg with rarkit, and hand back the volume bytes in set order.
pub fn rarkit_archive(shape: &Shape, data: &[u8]) -> rarkit::Result<Vec<Vec<u8>>> {
    let bodies = members(shape, data);
    let mut readers: Vec<std::io::Cursor<&[u8]>> = if shape.reader_payload {
        bodies
            .iter()
            .map(|(_, b)| std::io::Cursor::new(*b))
            .collect()
    } else {
        Vec::new()
    };
    let mut writer = Writer::new(shape.rarkit_options())?;
    // The payloads borrow `readers` for as long as the writer holds them,
    // so the whole member list is added from one iterator over it.
    let mut reader_slots = readers.iter_mut();
    for (name, body) in &bodies {
        let payload = if shape.reader_payload {
            let crc32 = rarkit::checksum::crc32(body);
            Payload::Reader {
                reader: reader_slots.next().expect("one reader per member"),
                // `<[u8]>::len`, spelled out: `RangeSource` is in scope
                // here and its own `len` answers `Option<u64>`.
                size: <[u8]>::len(body) as u64,
                crc32: Some(crc32),
            }
        } else {
            Payload::Bytes(body)
        };
        writer.add(MemberSpec {
            name: name.as_bytes(),
            payload,
            mtime: None,
            attributes: 0o100644,
            host_os: HostOs::Unix,
            is_directory: false,
        })?;
    }
    if shape.volume_size.is_some() {
        let mut volumes = Reserving {
            each: shape.volume_size.unwrap_or(1 << 20) as usize + SLACK,
            volumes: Vec::new(),
        };
        writer.finish_volumes(&mut volumes)?;
        Ok(volumes.volumes)
    } else {
        // `finish_seek` and NOT `finish_into`, because the OLD arm is a
        // buffered writer: `rarkit_oracle::create` builds the archive in
        // memory and can therefore fill a size or a checksum field after
        // the bytes have passed without holding anything or reading a
        // payload twice. `finish_into` takes a `Write` that cannot seek
        // and pays for both. Timing a pipe-shaped entry against a
        // buffered writer is not one ratio, it is two contracts; this is
        // the entry that means the same thing.
        let mut out = std::io::Cursor::new(Vec::with_capacity(one_archive_reserve(data.len())));
        writer.finish_seek(&mut out)?;
        Ok(vec![out.into_inner()])
    }
}

/// Room for the headers, the recovery record and the cipher padding on
/// top of an archive's payload.
const SLACK: usize = 1 << 21;

/// What the single-archive arm reserves for the whole archive, and why it
/// is a quarter over the payload and not `SLACK`.
///
/// This is a HARNESS figure and not the engine's. `SLACK` alone does not
/// cover a 5 per cent recovery record, so the `rr` legs' cursor
/// REALLOCATED once per round - and on macOS a heap buffer reallocated
/// while it is larger than about four megabytes leaves its whole dirty
/// length resident for the life of the process. Running
/// `g/create/rar5/m0/rr` for 25 rounds in one `two_arm` process therefore
/// climbed 67 MiB a round on a 64 MiB archive, half of it this line, and
/// the leg was measuring the harness. The old arm never paid it: the
/// oracle's `create` builds the archive in its own buffer and hands it
/// back.
fn one_archive_reserve(payload: usize) -> usize {
    payload + payload / 4 + SLACK
}

/// Collects each volume in memory with its capacity reserved up front.
///
/// The bundled `impl VolumeOut for Vec<Vec<u8>>` starts every volume at
/// zero capacity, so a leg using it would time 128 MiB of `Vec` growth
/// alongside the writer, and the old arm - whose adapter hands back
/// volumes it has already built - would not. Neither arm should be paying
/// for the harness's choice of container.
struct Reserving {
    each: usize,
    volumes: Vec<Vec<u8>>,
}

impl rarkit::VolumeOut for Reserving {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> rarkit::Result<Vec<u8>> {
        Ok(Vec::with_capacity(self.each))
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> rarkit::Result<()> {
        self.volumes.push(volume);
        Ok(())
    }
}

/// One member as an extraction gives it back: its name and its bytes.
pub type Extracted = (Vec<u8>, Vec<u8>);

/// Every member of a volume set, as rarkit's own reader gives them back.
pub fn extract_with_rarkit(
    volumes: &[Vec<u8>],
    password: Option<&[u8]>,
) -> rarkit::Result<Vec<Extracted>> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default().with_password(password.map(Password::new));
    let mut sink = Collect::default();
    rarkit::extract(sources, &options, &mut sink, &mut ())?;
    Ok(sink.members)
}

/// What [`check_agreement`] measured while it was checking.
#[derive(Clone, Copy, Debug)]
pub struct Agreement {
    /// Volumes rarkit wrote.
    pub rarkit_volumes: usize,
    /// Bytes rarkit wrote, over all volumes.
    pub rarkit_bytes: usize,
    /// Volumes the old engine wrote.
    pub old_volumes: usize,
    /// Bytes the old engine wrote, over all volumes.
    pub old_bytes: usize,
}

/// Collects every member's name and bytes, in archive order.
#[derive(Default)]
pub struct Collect {
    /// The members, in the order the reader produced them.
    pub members: Vec<Extracted>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.split_before {
            // A continued fragment appends to the member already open.
            return Ok(Disposition::Write(Vec::new()));
        }
        self.members.push((member.name.to_vec(), Vec::new()));
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if member.is_directory {
            return Ok(());
        }
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1.extend_from_slice(&bytes);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// The corpora. Both generators are seeded and allocate once.
// ---------------------------------------------------------------------

/// `bytes` bytes of the corpus a shape names.
///
/// EMPTY for [`Corpus::Code`] when its file is absent or is not the file
/// pinned; a caller that must say why calls [`code_corpus`] itself.
pub fn corpus(kind: Corpus, bytes: usize) -> Vec<u8> {
    match kind {
        Corpus::Random => pseudo_random(bytes),
        Corpus::Text => text_corpus(bytes),
        Corpus::Code => code_corpus(bytes).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------
// The executable corpus.
//
// The file is the x86-64 `libLLVM.so` of the Rust 1.98.0 toolchain
// (`libLLVM.so.22.1-rust-1.98.0-stable`, 199,596,928 bytes, sha256
// b2cc5bb9aafd2c8d1fd8ad0e99fd7de09e6831ff319ac99130d737261316596e),
// the one the filter detection work measured, copied to ONE fixed path
// on every box that takes these legs. It is the x86-64 library on
// every box, aarch64 ones included, so a row from each architecture is
// over the SAME bytes: the filter detected is a property of the corpus,
// not of the box measuring it. It carries both x86 transforms and delta
// regions, where the arm64 library fires deltas alone.
//
// The window is 32 MiB from 136 MiB in: the library's final `.text`,
// `.text.warm` and `.text.cold` (about 22 MiB of x86-64 machine code),
// then its unwind tables and the start of its symbol table. That is an
// executable's own mix, and it is chosen for what the filters DO on it
// (counted 28 Sep 2026, `FilterPolicy::Detect` over `Off`, 4 MiB
// dictionary, aarch64): the window writes 0.978 of Off's bytes at
// level 3 and 0.969 at level 5, beside the whole library's 0.974 and
// 0.967, where a window of the older `.bolt.org.text` alone (72 MiB in)
// wrote 0.9997 and 0.995 and so would time a create the filter barely
// touches. It is pinned by the WINDOW's sha256, so a different build of
// the library at the same path is refused rather than measured.
// ---------------------------------------------------------------------

/// Where the executable corpus is read from when
/// `RARKIT_BENCH_CODE_CORPUS` does not say.
pub const CODE_CORPUS_DEFAULT: &str = "rarkit-corpora/code/libLLVM-x86_64.so";
/// The file's length, checked before anything is read.
pub const CODE_CORPUS_FILE_BYTES: u64 = 199_596_928;
/// Where the window starts.
pub const CODE_CORPUS_OFFSET: u64 = 136 << 20;
/// The window's length: the most any `code` leg asks for.
pub const CODE_CORPUS_WINDOW: usize = 32 << 20;
/// The window's sha256.
pub const CODE_CORPUS_WINDOW_SHA256: &str =
    "93df31f6f346bc78f2572991ffa86f2e8a68a335fcab57eb680328b8cf3dbc33";

/// Where, inside the window, a MiB lies that a filter pays on at levels 3
/// and 5: the unwind index, a sorted table of fixed-width records, which
/// writes 0.55 of Off's bytes at level 3. A debug build can afford to
/// encode a MiB where it cannot afford the window, so this is the slice
/// `tests/create_gate.rs` proves detection fires on. The first MiB of
/// the window is code and fires nothing at that length.
pub const CODE_CORPUS_FIRE_SLICE: std::ops::Range<usize> = (30 << 20)..(31 << 20);

/// Why [`code_corpus`] has no bytes to give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeCorpusError {
    /// No file at the path: this box does not carry the corpus, and a leg
    /// over it is SKIPPED with this said.
    Absent(String),
    /// A file is there and it is not the one pinned: a FAILURE, because
    /// timing other bytes under this leg's name would be a wrong row.
    Wrong(String),
}

impl std::fmt::Display for CodeCorpusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeCorpusError::Absent(why) | CodeCorpusError::Wrong(why) => f.write_str(why),
        }
    }
}

/// The path the executable corpus is read from on this box.
pub fn code_corpus_path() -> PathBuf {
    match std::env::var_os("RARKIT_BENCH_CODE_CORPUS") {
        Some(path) => PathBuf::from(path),
        None => {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(CODE_CORPUS_DEFAULT)
        }
    }
}

/// The first `bytes` bytes of the executable corpus's pinned window.
///
/// The whole window is read and checked against its pin whatever `bytes`
/// is, so a scaled check reads a prefix of exactly the bytes a bench leg
/// times.
pub fn code_corpus(bytes: usize) -> Result<Vec<u8>, CodeCorpusError> {
    use sha2::Digest;
    use std::io::{Read, Seek, SeekFrom};

    assert!(
        bytes <= CODE_CORPUS_WINDOW,
        "a code leg asked for {bytes} bytes; the window is {CODE_CORPUS_WINDOW}"
    );
    let path = code_corpus_path();
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CodeCorpusError::Absent(format!(
                "executable corpus not on this box ({}; set RARKIT_BENCH_CODE_CORPUS)",
                path.display()
            )))
        }
        Err(e) => {
            return Err(CodeCorpusError::Wrong(format!(
                "executable corpus {}: {e}",
                path.display()
            )))
        }
    };
    let wrong = |why: String| CodeCorpusError::Wrong(format!("{}: {why}", path.display()));
    let length = file.metadata().map_err(|e| wrong(e.to_string()))?.len();
    if length != CODE_CORPUS_FILE_BYTES {
        return Err(wrong(format!(
            "{length} bytes, the pinned file is {CODE_CORPUS_FILE_BYTES}"
        )));
    }
    let mut window = vec![0u8; CODE_CORPUS_WINDOW];
    file.seek(SeekFrom::Start(CODE_CORPUS_OFFSET))
        .and_then(|_| file.read_exact(&mut window))
        .map_err(|e| wrong(e.to_string()))?;
    let digest: String = sha2::Sha256::digest(&window)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if digest != CODE_CORPUS_WINDOW_SHA256 {
        return Err(wrong(format!(
            "window sha256 {digest}, pinned {CODE_CORPUS_WINDOW_SHA256}"
        )));
    }
    window.truncate(bytes);
    Ok(window)
}

/// `len` bytes that are the same on every run and in both arms, and that
/// no writer can shrink.
///
/// A create leg wants the writer's COPY path timed, not its match finder,
/// so the filler has to be flat enough over any window the writer looks
/// back through that it finds nothing to point at. Each byte is the low
/// byte of its own index put through two odd multiplies with a shift
/// between them: the index decides the byte, so the stream is seekable and
/// reproducible without carrying state, and the mixing leaves no run, no
/// period a dictionary reaches and no bias a Huffman pass can spend.
pub fn pseudo_random(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let mut v = i.wrapping_mul(0xA24B_AED4_963E_E407).wrapping_add(1);
            v ^= v >> 31;
            v = v.wrapping_mul(0x9FB2_1C65_1E98_DF25);
            (v >> 40) as u8
        })
        .collect()
}

/// The seed of the gate's text.
pub const TEXT_SEED: u64 = 0x6761_7465;

/// `len` bytes of text, the same on every box and at every commit: the
/// shared test data crate's `source_text`, whole words in a seeded order,
/// wrapped into lines of drawn widths, from a list that crate keeps of
/// the commonest words of this engine's own source, proper names left out.
/// A shorter ask is a prefix of a longer one, so legs of 32, 64 and
/// 128 MiB read one stream.
///
/// A text member has real token statistics and no long range structure.
/// Text that repeats itself, or that runs on in long stretches of one
/// source, makes 64 MiB that is one enormous self reference: a writer
/// turns it into a handful of long matches and a timed leg then measures
/// `memcpy` rather than the codec. Sentences drawn word by word keep the
/// repeats short, which is the shape wanted here.
pub fn text_corpus(len: usize) -> Vec<u8> {
    rarkit_testdata::source_text(TEXT_SEED, len)
}
