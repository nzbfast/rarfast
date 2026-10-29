//! Spec G: the RAR 5 and RAR 4 writers over the section 5 vectors.
//!
//! The three oracles of spec G 6.1, in the order that section puts them:
//! reference `rar` 7.23's own bytes (the committed archives here, compared
//! byte for byte where the specification claims byte identity, and
//! reference `unrar` over everything this writer produces); rarkit's own
//! reader, for round trips; and the old engine through `rarkit-oracle`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use rarkit::{
    extract, Archive, ChecksumKind, Disposition, Layout, MemberInfo, MemberOutcome, MemberSpec,
    Password, Payload, RangeSource, Rar4Version, ReadOptions, Sink, Timestamp, VolumeNaming,
    WriteFormat, WriteOptions, Writer,
};

// The tests, one module a section of spec G.
#[path = "writers/comment_lock.rs"]
mod comment_lock;
#[path = "writers/compressed.rs"]
mod compressed;
#[path = "writers/finish_seek.rs"]
mod finish_seek;
#[path = "writers/identity.rs"]
mod identity;
#[path = "writers/naming_crypto.rs"]
mod naming_crypto;
#[path = "writers/progress.rs"]
mod progress;
#[path = "writers/properties.rs"]
mod properties;
#[path = "writers/pulled.rs"]
mod pulled;
#[path = "writers/recovery.rs"]
mod recovery;
#[path = "writers/refcheck.rs"]
mod refcheck;
#[path = "writers/refusals.rs"]
mod refusals;

fn vectors() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-G"
    ))
}

fn archive_bytes(name: &str) -> Vec<u8> {
    std::fs::read(vectors().join("archives").join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// One member as the reader gives it back: everything a writer needs to
/// put it back, and everything a round trip has to preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    name: Vec<u8>,
    is_directory: bool,
    data: Vec<u8>,
    mtime: Option<Timestamp>,
    attributes: u32,
    host_os: rarkit::HostOs,
}

#[derive(Default)]
struct Collect {
    members: Vec<Member>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.split_before {
            // A continued fragment joins the member already open.
            return Ok(Disposition::Write(Vec::new()));
        }
        self.members.push(Member {
            name: member.name.to_vec(),
            is_directory: member.is_directory,
            data: Vec::new(),
            mtime: member.mtime,
            attributes: member.attributes,
            host_os: member.host_os,
        });
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
        if let Some(bytes) = out {
            if let Some(last) = self.members.last_mut() {
                last.data.extend_from_slice(&bytes);
            }
        }
        Ok(())
    }
}

/// Every member of `names`, read back through rarkit's own reader.
fn read_back(names: &[&str]) -> Vec<Member> {
    let volumes: Vec<Arc<dyn RangeSource>> = names
        .iter()
        .map(|n| Arc::new(archive_bytes(n)) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let mut progress = NoProgress;
    extract(volumes, &ReadOptions::default(), &mut sink, &mut progress)
        .unwrap_or_else(|e| panic!("reading {names:?}: {e}"));
    sink.members
}

/// The members of an archive this test wrote.
fn read_back_bytes(volumes: Vec<Vec<u8>>) -> Vec<Member> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .into_iter()
        .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let mut progress = NoProgress;
    extract(sources, &ReadOptions::default(), &mut sink, &mut progress)
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

struct NoProgress;

impl rarkit::Progress for NoProgress {}

/// The filter policy a format will accept.
///
/// **A RAR 4 write has to say `FilterPolicy::Off` explicitly**, because
/// SPEC-J's erratum refuses a filter request for that family rather than
/// resolving it to `Off`, and `FilterPolicy::Detect` is the default. So
/// `WriteOptions::default()` with a RAR 4 format is an error, which is a
/// wart worth naming: spec G 3.14.7 says the option RESOLVES to `Off` for
/// every RAR 4 target and the erratum says it is refused, and the two
/// cannot both be followed. The erratum is later and is what this crate
/// does; this helper is what every RAR 4 caller then needs.
fn filters_for(format: WriteFormat) -> rarkit::FilterPolicy {
    if matches!(format, WriteFormat::Rar4(_)) {
        rarkit::FilterPolicy::Off
    } else {
        rarkit::FilterPolicy::default()
    }
}

/// Writes `members` with `options` into one archive.
fn write_one(options: WriteOptions, members: &[Member]) -> Vec<u8> {
    let mut writer = Writer::new(options).expect("options");
    for member in members {
        writer
            .add(MemberSpec {
                name: &member.name,
                payload: Payload::Bytes(&member.data),
                mtime: member.mtime,
                attributes: member.attributes,
                host_os: member.host_os,
                is_directory: member.is_directory,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn reference_options() -> WriteOptions {
    WriteOptions {
        layout: Layout::Reference { quick_open: true },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

// ---------------------------------------------------------------------
// Spec G 6.1 oracle 1: reference unrar
// ---------------------------------------------------------------------

/// Whether reference `unrar` is on PATH, so the test can say it SKIPPED
/// rather than silently passing.
fn unrar() -> Option<&'static str> {
    // `unrar` with no command prints its banner and exits non-zero, so
    // what is being tested here is that the binary RAN at all.
    Command::new("unrar").output().ok().map(|_| "unrar")
}

// ---------------------------------------------------------------------
// Spec G 6.3: properties, over deterministic pseudo-random inputs
// ---------------------------------------------------------------------

/// A seeded pseudo-random stream, so that a failing case is a fixed case.
fn pseudo(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

// ---------------------------------------------------------------------
// Spec G 5.1: the same comparison refcheck.py makes, from Rust
// ---------------------------------------------------------------------

/// Whether reference `rar` 7.23 is on PATH.
fn rar() -> Option<&'static str> {
    Command::new("rar").output().ok().map(|_| "rar")
}

// ---------------------------------------------------------------------
// Spec G 3.8 and 1.2: the compressed path, through spec H3's encoders
// ---------------------------------------------------------------------

/// `len` bytes of text, which every level compresses.
fn compressible(len: usize) -> Vec<u8> {
    rarkit_testdata::chatter(0x7772, len)
}
