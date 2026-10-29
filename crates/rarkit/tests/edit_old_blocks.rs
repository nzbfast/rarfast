//! A rewrite and the two block types only RAR 2.x wrote: the protect
//! block (type 0x78), which is that version's recovery record, and the
//! old sub block (type 0x77), which carries something of the member
//! before it.
//!
//! The rule is the one the RAR 4 and RAR 5 records already have: a
//! rewrite keeps a thing truthfully or refuses the edit by name, and
//! never drops it or keeps it silently.
//!
//! Width and memory: the archives are under 100 KiB, a rewrite copies
//! bytes on the calling thread, and every read uses the default memory
//! policy. Nothing follows the machine's thread count.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    edit, extract, Archive, BlockKind, Disposition, ErrorKind, HostOs, MemberInfo, MemberSpec,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, ServiceKind, Sink, Unsupported,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

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
        if let (Some(b), Some(last)) = (out, self.members.last_mut()) {
            last.1 = b;
        }
        Ok(())
    }
}

fn read_back(archive: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading an archive back: {e}"));
    sink.members
}

fn open(archive: &[u8]) -> Archive {
    let src: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    Archive::open(src, &ReadOptions::default()).expect("open")
}

/// `d250_rr.rar` of `fixtures/legacy`: written by RAR 2.50 with `-rr`,
/// so it ends in a genuine protect block.
fn protected_archive() -> Vec<u8> {
    let dir = match std::env::var("RARKIT_LEGACY_FIXTURES") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/archives"),
    };
    let path = dir.join("d250_rr.rar");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn has_record_block(archive: &Archive) -> bool {
    archive
        .blocks()
        .any(|block| block.kind == BlockKind::Service(ServiceKind::RecoveryRecord))
}

/// An edit that says nothing about the recovery record does not lose a
/// RAR 2.x one: it is refused, and the refusal says why.
///
/// The record states a count of SECTORS and no percentage (`-rr` is one
/// sector, `-rr8` eight), and this crate writes no protect block, so
/// there is nothing truthful to rebuild it as. Before this the rewrite
/// returned Ok over an output with no record at all.
#[test]
fn an_edit_that_does_not_name_a_rar2_protect_record_is_refused() {
    let source = protected_archive();
    let src = open(&source);
    assert!(
        has_record_block(&src) && src.has_recovery_record(),
        "the fixture has no protect block"
    );

    type Rewrite = fn(&Archive, &mut Vec<u8>) -> Result<()>;
    let edits: [(&str, Rewrite); 3] = [
        ("lock", |src, out| edit::lock(src, out)),
        ("comment", |src, out| {
            edit::set_comment(src, Some(b"a comment"), out)
        }),
        ("rename", |src, out| {
            edit::rename(src, b"README.TXT", b"NEW.TXT", out).map(|_| ())
        }),
    ];
    for (what, rewrite) in edits {
        let mut out = Vec::new();
        match rewrite(&src, &mut out) {
            Ok(()) => panic!(
                "{what}: returned Ok over {} bytes, record kept: {}",
                out.len(),
                has_record_block(&open(&out))
            ),
            Err(error) => {
                let ErrorKind::Unsupported(Unsupported::WriteFeature(reason)) = error.kind() else {
                    panic!("{what}: refused, but not by name: {error}");
                };
                assert!(
                    reason.contains("RAR 2.x protect block"),
                    "{what}: the refusal does not name the record: {reason}"
                );
            }
        }
        assert!(out.is_empty(), "{what}: wrote before it refused");
    }
}

/// The caller who NAMES what becomes of the record is not refused: it is
/// dropped when they say so, and the members are all still there.
#[test]
fn a_rar2_protect_record_the_caller_drops_is_dropped() {
    let source = protected_archive();
    let src = open(&source);
    let mut out = Vec::new();
    let report = edit::set_recovery(&src, None, &mut out).expect("drop the record");
    assert!(!report.recovery);
    let after = open(&out);
    assert!(!has_record_block(&after) && !after.has_recovery_record());
    assert!(
        !out.windows(8).any(|window| window == b"Protect!"),
        "the protect block is still in the output"
    );
    assert_eq!(read_back(&out), read_back(&source));
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 7 + usize::from(seed) * 31 + 3) % 251) as u8)
        .collect()
}

fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b"a.txt".to_vec(), bytes(3_000, 1)),
        (b"b.txt".to_vec(), bytes(3_000, 2)),
        (b"c.txt".to_vec(), bytes(3_000, 3)),
    ]
}

fn rar4_archive() -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V29),
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        order: rarkit::MemberOrder::AsAdded,
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    let members = members();
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// An old sub block (type 0x77) carrying `data`: the seven common bytes,
/// the data size, a sub type and a level. Its checksum covers the data
/// area as well as the header, which is this type's own rule.
fn old_sub_block(data: &[u8]) -> Vec<u8> {
    let mut rest = vec![0x77];
    rest.extend_from_slice(&0x8000u16.to_le_bytes());
    rest.extend_from_slice(&14u16.to_le_bytes());
    rest.extend_from_slice(&(data.len() as u32).to_le_bytes());
    rest.extend_from_slice(&0x0101u16.to_le_bytes());
    rest.push(0);
    rest.extend_from_slice(data);
    let mut block = (rarkit::checksum::crc32(&rest) as u16)
        .to_le_bytes()
        .to_vec();
    block.extend_from_slice(&rest);
    block
}

/// The RAR 4 family archive of [`members`] with `block` straight after
/// the file block of member `after`.
fn with_block_after(after: usize, block: &[u8]) -> Vec<u8> {
    let source = rar4_archive();
    let at = open(&source)
        .blocks()
        .filter(|b| b.kind == BlockKind::File)
        .nth(after)
        .expect("the member")
        .range
        .end as usize;
    let mut out = source[..at].to_vec();
    out.extend_from_slice(block);
    out.extend_from_slice(&source[at..]);
    out
}

fn holds(archive: &[u8], needle: &[u8]) -> bool {
    archive.windows(needle.len()).any(|window| window == needle)
}

/// An old sub block goes with the member it follows and stays with a
/// member that stays. Before this it was copied whatever became of its
/// member, so the removed member's record came out behind another one.
#[test]
fn a_removal_takes_the_old_sub_block_of_the_removed_member() {
    let owner = b"owner of b.txt, in an old sub block";
    let source = with_block_after(1, &old_sub_block(owner));
    let src = open(&source);
    assert!(
        src.blocks().any(|b| b.kind == BlockKind::Other(0x77)),
        "the fixture's block is not read as an old sub block"
    );
    assert_eq!(read_back(&source), members(), "the fixture");

    let mut without_b = Vec::new();
    edit::remove(&src, &[b"b.txt"], &mut without_b).expect("remove b");
    assert!(
        !holds(&without_b, owner),
        "b.txt's old sub block stayed and now follows a.txt"
    );
    let mut kept = members();
    kept.remove(1);
    assert_eq!(read_back(&without_b), kept, "without b");

    for (index, other) in [(0usize, &b"a.txt"[..]), (2, &b"c.txt"[..])] {
        let mut out = Vec::new();
        edit::remove(&src, &[other], &mut out).expect("remove another");
        assert!(
            holds(&out, owner),
            "b.txt stayed and its old sub block did not"
        );
        let after = open(&out);
        let kinds: Vec<BlockKind> = after
            .blocks()
            .map(|b| b.kind)
            .filter(|kind| matches!(kind, BlockKind::File | BlockKind::Other(0x77)))
            .collect();
        // b.txt is the first member left when a.txt went and the second
        // when c.txt went, and the block is straight after it either way.
        let b_at = if index == 0 { 0 } else { 1 };
        assert_eq!(
            kinds.get(b_at + 1),
            Some(&BlockKind::Other(0x77)),
            "{kinds:?}"
        );
        let mut kept = members();
        kept.remove(index);
        assert_eq!(read_back(&out), kept);
    }
}
