//! A RAR 5 member whose solid bit is CLEAR starts a new chain (spec F 3.6),
//! on every read path that decodes a solid archive.
//!
//! **The defect this pins (fuzz, 27 Sep 2026).** The read path decided a
//! member's solidity with the RAR 1.5 rule ("the archive flag governs, the
//! member bit is not written") before it looked at the member's own bit,
//! and it chose that rule by `unpack_version < 20`. A RAR 5 member's
//! `unpack_version` is its COMPRESSION version, 0, so every RAR 5 member
//! after the first continued the chain whatever its bit said. On a valid
//! archive that changes no byte, because a chain's first member names no
//! distance before itself and carries its own tables; on a damaged one a
//! member whose match reaches before its own stream's start (SPEC-H2 3.7)
//! instead copied bytes out of the chain before it and reported OK.
//!
//! What 3.7 gives such a match changed on 11 Oct 2026 (its amendment): it was
//! `DistanceOutOfRange`, and it is ZERO bytes with nothing said, the
//! member's checksum deciding. Either way it is not the bytes of the
//! chain before, and that is what these cases hold.
//!
//! So two kinds of case: the damaged archive never copies across the
//! break on any path, and the
//! genuine ones reference `rar` writes with chain breaks mid archive
//! (`-s<N>`, `-se`) extract byte for byte what reference `unrar` extracts,
//! on every path.

use std::path::Path;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

/// Each member's name and bytes.
type Members = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Default)]
struct Keep {
    members: Members,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
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
    ) -> Result<()> {
        if !member.is_directory {
            self.members
                .push((member.name.to_vec(), out.unwrap_or_default()));
        }
        Ok(())
    }
}

/// Every read path a solid archive can take through `extract`: the walk at
/// one lane, the walk with the chain's decode-ahead at the default width,
/// and the solid path whose walk runs on a worker, which engages only for
/// a writer the caller calls a file.
fn paths() -> [(&'static str, ReadOptions); 3] {
    [
        ("one lane", ReadOptions::default().with_workers(Some(1))),
        ("default width", ReadOptions::default()),
        (
            "walk on a worker",
            ReadOptions::default().with_sink_is_file(Some(true)),
        ),
    ]
}

fn read(archive: &[u8], options: &ReadOptions) -> (Keep, Option<String>) {
    let source: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    let mut sink = Keep::default();
    let ended = extract(vec![source], options, &mut sink, &mut ());
    (sink, ended.err().map(|e| format!("{:?}", e.kind())))
}

/// The fuzz finding, on every path: `m1.bin` has its solid bit clear, so
/// its stream starts at its own first byte, and its only symbol, a match
/// at distance 2, reaches before it (SPEC-H2 3.7).
#[test]
fn a_bit_clear_member_restarts_on_every_path() {
    let archive = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/findings-27sep/solid-chain-break-continues.rar"),
    )
    .expect("the finding");
    for (path, options) in paths() {
        let (kept, ended) = read(&archive, &options);
        assert_eq!(
            kept.members.first().map(|m| m.1.len()),
            Some(11),
            "{path}: m0.bin"
        );
        assert!(ended.is_none(), "{path}: nothing is said, {ended:?}");
        let m1 = &kept.members.get(1).expect("m1.bin").1;
        assert!(
            !m1.is_empty() && m1.iter().all(|&byte| byte == 0),
            "{path}: m1.bin decoded against m0.bin's window: {m1:?}"
        );
    }
}

/// A solid archive reference `rar` writes from `files` with `switches`,
/// and what reference `unrar` extracts from it, in name order. `None`
/// without both tools on the path.
fn reference(
    tag: &str,
    files: &[(String, Vec<u8>)],
    switches: &[&str],
) -> Option<(Vec<u8>, Members)> {
    // The process id, because two runs of the suite on one box share
    // `temp_dir`.
    let dir = std::env::temp_dir().join(format!("rarkit-restart-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let input = dir.join("in");
    let output = dir.join("out");
    std::fs::create_dir_all(&input).ok()?;
    std::fs::create_dir_all(&output).ok()?;
    for (name, bytes) in files {
        std::fs::write(input.join(name), bytes).ok()?;
    }
    let archive = dir.join("set.rar");
    let wrote = std::process::Command::new("rar")
        .current_dir(&input)
        .args(["a", "-ma5", "-ep", "-idq", "-y"])
        .args(switches)
        .arg(&archive)
        .arg(".")
        .status()
        .is_ok_and(|s| s.success());
    let extracted = wrote
        && std::process::Command::new("unrar")
            .current_dir(&output)
            .args(["x", "-idq", "-y"])
            .arg(&archive)
            .status()
            .is_ok_and(|s| s.success());
    let result = if extracted {
        let bytes = std::fs::read(&archive).ok()?;
        let mut theirs = Vec::new();
        for entry in std::fs::read_dir(&output).ok()? {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            theirs.push((name.into_bytes(), std::fs::read(&path).ok()?));
        }
        theirs.sort();
        Some((bytes, theirs))
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Rarkit's members on one path, in name order.
fn ours(archive: &[u8], options: &ReadOptions) -> std::result::Result<Members, String> {
    let (kept, ended) = read(archive, options);
    if let Some(ended) = ended {
        return Err(ended);
    }
    let mut members = kept.members;
    members.sort();
    Ok(members)
}

/// How many members after the first start a chain of their own, which is
/// the shape these cases exist for: a case whose `rar` wrote none tests
/// nothing and says so.
fn breaks(archive: &[u8]) -> usize {
    rarkit::internals::rar5::members(archive)
        .iter()
        .filter(|m| !m.directory && m.unpacked > 0)
        .skip(1)
        .filter(|m| !m.solid)
        .count()
}

fn check(tag: &str, files: &[(String, Vec<u8>)], switches: &[&str], want_breaks: usize) {
    let Some((archive, theirs)) = reference(tag, files, switches) else {
        eprintln!("    reference `rar` or `unrar` is not on the path; skipped");
        return;
    };
    let found = breaks(&archive);
    assert!(
        found >= want_breaks,
        "{tag}: rar {switches:?} broke the chain {found} times, fewer than {want_breaks}"
    );
    assert_eq!(theirs.len(), files.len(), "{tag}: unrar's members");
    for (path, options) in paths() {
        let got = ours(&archive, &options).unwrap_or_else(|e| panic!("{tag}, {path}: {e}"));
        assert!(got == theirs, "{tag}, {path}: not unrar's bytes");
    }
}

/// `-s<N>`: a new chain every N members, the chain start's bit clear. Small
/// members, so a chain is many one-block members and the decode-ahead
/// walks across its breaks.
#[test]
fn a_reference_rar_set_of_small_solid_groups_extracts_as_unrar_does() {
    // Three EMPTY members among them, at a chain's start, middle and end:
    // spec F 3.6's erratum keeps the chain through a zero byte member
    // whatever its bit says.
    let files: Vec<(String, Vec<u8>)> = (0..96)
        .map(|i| {
            let len = if [16, 21, 31].contains(&i) {
                0
            } else {
                3_000 + i * 37
            };
            (
                format!("m{i:03}.txt"),
                rarkit_testdata::chatter(i as u64 + 1, len),
            )
        })
        .collect();
    check("s8", &files, &["-m3", "-s8"], 8);
}

/// `-s<N>` with members large enough to take the tape path, so a chain
/// start decodes in waves after the break.
#[test]
fn a_reference_rar_set_of_large_solid_groups_extracts_as_unrar_does() {
    let files: Vec<(String, Vec<u8>)> = (0..9)
        .map(|i| {
            (
                format!("big{i}.txt"),
                rarkit_testdata::chatter(i as u64 + 101, 700_000 + i * 1_001),
            )
        })
        .collect();
    check("s3", &files, &["-m3", "-s3"], 2);
}

/// `-se`: a new chain for each file extension.
#[test]
fn a_reference_rar_set_solid_by_extension_extracts_as_unrar_does() {
    let files: Vec<(String, Vec<u8>)> = (0..60)
        .map(|i| {
            let ext = ["txt", "log", "csv"][i % 3];
            (
                format!("f{i:03}.{ext}"),
                rarkit_testdata::chatter(i as u64 + 7, 2_500 + i * 53),
            )
        })
        .collect();
    check("se", &files, &["-m5", "-se"], 2);
}
