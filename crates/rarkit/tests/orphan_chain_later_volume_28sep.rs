//! An orphan chain start is told from a missing head by the VOLUME it sits
//! in, never by the member's contents (spec F 3.6,
//! decided 28 Sep 2026).
//!
//! The first member of a solid archive with its solid bit set is read from
//! a fresh stream in a single archive and in the FIRST volume of a set
//! (spec F 3.5.3's test: RAR 5's volume flag with no number or number 0,
//! the RAR 4 family's main flag 0x0100). The same member at the head of a
//! LATER volume opened alone is the missing head, and stays refused
//! `Corrupt(Stream)`, with every member of its chain.
//!
//! Built by rewriting headers only (their CRCs recomputed): the RAR 5 case
//! from the fuzz find `orphan-chain-start-compressed.rar`, whose main
//! header is rewritten to name a volume; the RAR 4 case from the genuine
//! rar 4.20 fixture `r420_solid.rar`, `DATA.BIN`'s file flag 0x0010 set.
//!
//! A DIFFERENCE PINNED, NOT COPIED. Reference `unrar` 7.23 (homebrew's,
//! aarch64 macOS, 28 Sep 2026) tests EVERY archive below OK, exit 0,
//! including the two rarkit refuses: it decodes whatever a volume opened
//! alone starts with from an empty window, and these members lean on
//! nothing before them. Spec F 3.6 decides by the volume's identity, so
//! on a real later volume a member that leans on the missing head is
//! refused up front here where the reference fails its checksum.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

fn read(parts: &[&str]) -> Vec<u8> {
    let mut path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect();
    path.extend(parts);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[derive(Default)]
struct Keep {
    members: Vec<(String, Vec<u8>, Option<bool>)>,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            String::from_utf8_lossy(member.name).into_owned(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

fn ours(archive: Vec<u8>) -> (Keep, Option<String>) {
    let source: Arc<dyn RangeSource> = Arc::new(archive);
    let mut sink = Keep::default();
    let ended = extract(vec![source], &ReadOptions::default(), &mut sink, &mut ());
    (sink, ended.err().map(|e| format!("{:?}", e.kind())))
}

/// The fuzz find with its main header replaced by one naming a volume:
/// `number` `None` is the first volume's form (the number field left out),
/// `Some(n)` a volume numbered `n`, zero-based (spec F 3.2.5).
fn rar5_as_volume(number: Option<u8>) -> Vec<u8> {
    let archive = read(&[
        "fuzz",
        "findings-27sep",
        "orphan-chain-start-compressed.rar",
    ]);
    // Signature, then the main header: CRC32, size, type 1, header flags
    // 0x0005 (an extra area of 7 bytes, the locator), archive flags 0x0004
    // (solid). The locator is dropped: nothing here reads it.
    assert_eq!(
        &archive[12..16],
        &[0x0b, 0x01, 0x05, 0x07],
        "the find as taken"
    );
    let end = 16 + 11 - 3;
    let mut body = vec![0x01, 0x00];
    match number {
        None => body.push(0x05),
        Some(n) => body.extend_from_slice(&[0x07, n]),
    }
    let mut head = vec![body.len() as u8];
    head.extend_from_slice(&body);
    let mut out = archive[..8].to_vec();
    out.extend_from_slice(&crc32fast::hash(&head).to_le_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(&archive[end..]);
    out
}

/// The single archive and the first volume, in both of its forms, read the
/// member from a fresh stream with its CRC32 verified.
#[test]
fn a_rar5_first_volume_reads_its_orphan_chain_start() {
    for number in [None, Some(0)] {
        let (kept, ended) = ours(rar5_as_volume(number));
        assert_eq!(ended, None, "{number:?}");
        assert_eq!(kept.members.len(), 1, "{number:?}");
        assert_eq!(kept.members[0].2, Some(true), "{number:?}");
        assert_eq!(
            crc32fast::hash(&kept.members[0].1),
            0x527a_6e2c,
            "{number:?}"
        );
    }
}

/// Volume number 1 opened alone: the chain's head is in volume 0, which
/// the caller did not supply, so the member is refused whatever its bytes
/// hold. `unrar t` passes it (the module's note).
#[test]
fn a_rar5_later_volume_keeps_its_missing_head_refused() {
    let (kept, ended) = ours(rar5_as_volume(Some(1)));
    assert_eq!(ended, Some("Corrupt(Stream)".to_owned()));
    assert_eq!(kept.members.len(), 1);
    assert!(kept.members[0].1.is_empty());
    assert_eq!(kept.members[0].2, Some(false));
}

/// Rewrite the RAR 1.5 to 4.x block at `at` (CRC16, type, flags, size),
/// OR-ing `set` into its flags and clearing `clear`, and fix its CRC.
fn rar4_flags(archive: &mut [u8], at: usize, set: u16, clear: u16) {
    let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
    archive[at + 3..at + 5].copy_from_slice(&((flags | set) & !clear).to_le_bytes());
    let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
    let crc = crc32fast::hash(&archive[at + 2..at + size]) as u16;
    archive[at..at + 2].copy_from_slice(&crc.to_le_bytes());
}

/// `r420_solid.rar` with its first member's solid flag set, its host byte
/// set to `host`, and its main header's flags changed by `set` and `clear`.
fn rar4_orphan(set: u16, clear: u16, host: u8) -> Vec<u8> {
    let mut archive = read(&["fixtures", "legacy", "archives", "r420_solid.rar"]);
    // The marker is 7 bytes and the main header 13; the first file header
    // follows it (spec F 3.3), its host byte at 15 and its name at 32.
    assert_eq!(archive[7 + 2], 0x73, "the main header");
    let first = 7 + 13;
    assert_eq!(archive[first + 2], 0x74, "the first file header");
    assert_eq!(&archive[first + 32..first + 40], b"DATA.BIN");
    archive[first + 15] = host;
    rar4_flags(&mut archive, first, 0x0010, 0);
    rar4_flags(&mut archive, 7, set, clear);
    archive
}

/// A single RAR 4 archive, and a first volume by its main flag 0x0100:
/// every member reads, each checksum verified, as `unrar t` reports.
#[test]
fn a_rar4_first_volume_reads_its_orphan_chain_start() {
    for (set, what) in [(0, "single"), (0x0101, "first volume")] {
        let (kept, ended) = ours(rar4_orphan(set, 0, 3));
        assert_eq!(ended, None, "{what}");
        assert_eq!(kept.members.len(), 12, "{what}");
        assert!(
            kept.members.iter().all(|m| m.2 != Some(false)),
            "{what}: {:?}",
            kept.members.iter().map(|m| (&m.0, m.2)).collect::<Vec<_>>()
        );
        assert_eq!(kept.members[0].0, "DATA.BIN");
    }
}

/// A volume WITHOUT 0x0100: not taken for the first, so the chain its
/// first member continues has its head elsewhere and every member of that
/// chain is refused (the chain here runs through the whole archive).
/// Spec F 3.6 (28 Sep 2026): on the EXTRACT path a RAR 4 volume is first
/// for this decision only when its main header carries 0x0100 or it is not
/// a volume; 3.5.3's end block test needs a record 3.7.2 forbids reading
/// before the members in front of it. The HOST BYTE decides nothing
/// (3.5.3): refused at Unix (3) and at MS-DOS (0) alike. A difference the
/// spec backs: `d250_vol.rar` rebuilt solid with its first file's bit set,
/// beside its real `.r00` to `.r02`, is read by unrar 7.23 (All OK) and
/// refused here, DOS RAR 2.50 setting no 0x0100.
#[test]
fn a_rar4_volume_without_the_first_volume_flag_keeps_its_missing_head_refused() {
    for host in [3u8, 0] {
        let (kept, ended) = ours(rar4_orphan(0x0001, 0x0100, host));
        assert_eq!(ended, Some("Corrupt(Stream)".to_owned()), "host {host}");
        assert_eq!(kept.members[0].0, "DATA.BIN");
        assert_eq!(kept.members[0].2, Some(false), "host {host}");
        assert!(kept.members[0].1.is_empty(), "host {host}");
    }
}
