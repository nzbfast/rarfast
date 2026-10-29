//! Compression version 1 and the RAR 7 dictionary (spec F 3.2.6.3, SPEC-H2
//! 3.3), on archives reference `rar` 7.23 wrote.
//!
//! `tests/rar7/` holds four one-member archives rar wrote over standard
//! input with `-qo-` (`tests/rar7/make.sh` is their provenance): `-md4g`
//! is version 0 and the other three version 1, one of them (`-md8g`) with
//! the power's fifth bit, bit 14, and one (`-md4608m`) with a fraction.
//! Each member is the same 108,894 bytes.
//!
//! And the DIFFERENTIAL vectors 3.2.6.3 owes this package: the genuine
//! archives with their compression information rewritten to each of the
//! consequences' fields (the header's size and CRC32 recomputed, which a
//! `-qo-` archive allows), with rarkit's verdict held to reference `unrar
//! t -md64g`'s wherever `unrar` is on the path.

use std::path::Path;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, ErrorKind, MemberInfo, MemberOutcome, MemoryPolicy, RangeSource,
    ReadOptions, Resource, Result, Sink, Unsupported,
};

const LEN: u64 = 108_894;
const G: u64 = 1 << 30;
const M: u64 = 1 << 20;

fn genuine(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/rar7")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One member's dictionary, algorithm version, byte count and verdict.
#[derive(Default)]
struct Seen {
    members: Vec<(Option<u64>, u32, u64, Option<bool>)>,
}

impl Sink for Seen {
    type Out = std::io::Sink;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            member.dictionary,
            member.algorithm_version,
            outcome.bytes,
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// A policy that admits every dictionary the format can name, which is
/// what `unrar -md64g` is.
fn roomy() -> ReadOptions {
    ReadOptions::default().with_memory(MemoryPolicy {
        max_window: 64 * G,
        ..MemoryPolicy::default()
    })
}

fn read(archive: &[u8], options: &ReadOptions) -> (Seen, Option<rarkit::Error>) {
    let source: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    let mut seen = Seen::default();
    let ended = extract(vec![source], options, &mut seen, &mut ());
    (seen, ended.err())
}

/// Whether rarkit extracts the one member whole with its checksum right.
fn decodes(archive: &[u8]) -> bool {
    let (seen, ended) = read(archive, &roomy());
    ended.is_none()
        && seen.members.len() == 1
        && seen.members[0].2 == LEN
        && seen.members[0].3 == Some(true)
}

/// Each genuine archive lists the dictionary and the algorithm its field
/// names, and decodes to its 108,894 bytes with its checksum right under a
/// policy that admits the dictionary.
#[test]
fn the_genuine_archives_list_and_decode() {
    for (name, dictionary, algorithm) in [
        ("md4g.rar", 4 * G, 0u32),
        ("md4608m.rar", 4_608 * M, 1),
        ("md5g.rar", 5 * G, 1),
        ("md8g.rar", 8 * G, 1),
    ] {
        let (seen, ended) = read(&genuine(name), &roomy());
        assert!(ended.is_none(), "{name}: {ended:?}");
        assert_eq!(
            seen.members,
            vec![(Some(dictionary), algorithm, LEN, Some(true))],
            "{name}"
        );
    }
}

/// The default policy is asked for what a member NEEDS (SPEC-API 8.1
/// term 1, the member-sized window).
///
/// md5g.rar's one member is 108,894 bytes outside a solid stream, so it
/// needs its REACH, not the 5 GiB dictionary its field names: it decodes
/// under the default policy with its checksum right. Before the
/// member-sized window it was refused as `LimitExceeded` naming 5 GiB. A
/// window ceiling below the reach still refuses it, naming the reach.
///
/// The same archive marked SOLID is asked for the full computed
/// dictionary, since a later member may continue the window, and the
/// default policy refuses it as `LimitExceeded` naming 5 GiB exactly (the
/// reference's own answer is its memory prompt, 3.2.6.3).
#[test]
fn the_default_policy_is_asked_for_the_computed_dictionary() {
    let (seen, ended) = read(&genuine("md5g.rar"), &ReadOptions::default());
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(seen.members, vec![(Some(5 * G), 1, LEN, Some(true))]);

    let tight = ReadOptions::default().with_memory(MemoryPolicy {
        max_window: 64 * 1024,
        ..MemoryPolicy::default()
    });
    let (_, ended) = read(&genuine("md5g.rar"), &tight);
    let ended = ended.expect("a window ceiling under the member's reach");
    assert!(
        matches!(
            ended.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::Window,
                needed,
                ..
            } if *needed == LEN
        ),
        "{ended:?}"
    );

    let (_, ended) = read(&solid(&genuine("md5g.rar")), &ReadOptions::default());
    let ended = ended.expect("a 5 GiB window for a solid member under the default policy");
    assert!(
        matches!(
            ended.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::Window,
                needed,
                ..
            } if *needed == 5 * G
        ),
        "{ended:?}"
    );
}

/// `archive` with its main header's SOLID flag set (archive flag 0x0004,
/// SPEC-F 3.2.2) and that header's CRC32 recomputed. The genuine archives
/// are single-volume, so the archive flags are one byte either way.
fn solid(archive: &[u8]) -> Vec<u8> {
    let mut out = archive.to_vec();
    let start = 8usize;
    let mut p = start + 4;
    let size = read_vint(archive, &mut p) as usize;
    let end = p + size;
    let btype = read_vint(archive, &mut p);
    assert_eq!(btype, 1, "the first block is the main header");
    let flags = read_vint(archive, &mut p);
    if flags & 1 != 0 {
        read_vint(archive, &mut p);
    }
    if flags & 2 != 0 {
        read_vint(archive, &mut p);
    }
    assert!(archive[p] < 0x80, "one byte of archive flags");
    out[p] |= 0x04;
    let crc = crc32fast::hash(&out[start + 4..end]);
    out[start..start + 4].copy_from_slice(&crc.to_le_bytes());
    out
}

fn vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_vint(bytes: &[u8], at: &mut usize) -> u64 {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte < 0x80 {
            return value;
        }
    }
}

/// `archive` with its one file header's compression information replaced
/// by `comp`: the field's vint re-encoded, the header's size re-encoded
/// and its CRC32 recomputed. Nothing in a `-qo-` archive records an offset
/// past the header, so the rest of the archive stands (spec F 3.2.6.3).
fn rewritten(archive: &[u8], comp: u64) -> Vec<u8> {
    let mut at = 8usize;
    loop {
        let start = at;
        let mut p = start + 4;
        let size = read_vint(archive, &mut p) as usize;
        let fields = p;
        let end = fields + size;
        let btype = read_vint(archive, &mut p);
        let flags = read_vint(archive, &mut p);
        if flags & 1 != 0 {
            read_vint(archive, &mut p);
        }
        let data = if flags & 2 != 0 {
            read_vint(archive, &mut p)
        } else {
            0
        };
        if btype == 2 {
            let file_flags = read_vint(archive, &mut p);
            read_vint(archive, &mut p); // unpacked size
            read_vint(archive, &mut p); // attributes
            if file_flags & 2 != 0 {
                p += 4;
            }
            if file_flags & 4 != 0 {
                p += 4;
            }
            let field = p;
            read_vint(archive, &mut p);
            let mut body = archive[fields..field].to_vec();
            vint(&mut body, comp);
            body.extend_from_slice(&archive[p..end]);
            let mut sized = Vec::new();
            vint(&mut sized, body.len() as u64);
            sized.extend_from_slice(&body);
            let mut out = archive[..start].to_vec();
            out.extend_from_slice(&crc32fast::hash(&sized).to_le_bytes());
            out.extend_from_slice(&sized);
            out.extend_from_slice(&archive[end..]);
            return out;
        }
        at = end + data as usize;
    }
}

/// Reference `unrar t -md64g` on `archive`: `Some(true)` for a clean test,
/// `None` without `unrar`.
fn unrar_tests_ok(tag: &str, archive: &[u8]) -> Option<bool> {
    let path = std::env::temp_dir().join(format!("rarkit-rar7-{tag}-{}.rar", std::process::id()));
    std::fs::write(&path, archive).ok()?;
    let status = std::process::Command::new("unrar")
        .args(["t", "-idq", "-md64g"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::fs::remove_file(&path);
    status.ok().map(|s| s.success())
}

/// Spec F 3.2.6.3's consequences as differential vectors. Each row is a
/// genuine archive, the field it is rewritten to, and whether the member
/// then decodes: which the specification says and reference `unrar`
/// confirms where it is present.
#[test]
fn the_consequences_hold_on_rewritten_genuine_archives() {
    let v0 = genuine("md4g.rar");
    let v1 = genuine("md5g.rar");
    for (tag, base, comp, want) in [
        // 1 and 3: a version 0 field with bit 14 set reads bits 10 to 13.
        ("v0-bit14", &v0, 0x7c80u64, true),
        ("v0-high-bits", &v0, 0xfbc80, true),
        // 5: bit 20 of a version 1 field is version 0 data.
        ("v1-bit20-v0-data", &v0, 0x14_3c81, true),
        ("v1-v0-data", &v0, 0x4_3c81, false),
        // 6: the version, not the size, chooses the algorithm.
        ("v1-at-4g", &v1, 0x3c81, true),
        ("v0-v1-data", &v1, 0x3c80, false),
        // 5 again, from the other side.
        ("v1-bit20-v1-data", &v1, 0x14_3c81, false),
        // Bits 21 and up are ignored.
        ("v1-bit27", &v1, 0x804_3c81, true),
    ] {
        let archive = rewritten(base, comp);
        assert_eq!(decodes(&archive), want, "{tag} ({comp:#x}): rarkit");
        match unrar_tests_ok(tag, &archive) {
            Some(theirs) => assert_eq!(theirs, want, "{tag} ({comp:#x}): unrar t -md64g"),
            None => eprintln!("    {tag}: reference `unrar` is not on the path; rarkit alone"),
        }
    }

    // 4: a version 1 field above 64 GiB is an unknown version, whatever
    // the policy, and the reference fails it too. Both fields are method
    // 1: an unknown version refuses only where a codec
    // runs (spec F 5.3's `0x5001` has method 0, a stored member).
    for (tag, comp) in [("66g", 0xcc81u64), ("128g", 0x5081)] {
        let archive = rewritten(&v1, comp);
        let (_, ended) = read(&archive, &roomy());
        assert!(
            matches!(
                ended.as_ref().map(rarkit::Error::kind),
                Some(ErrorKind::Unsupported(Unsupported::Version(1)))
            ),
            "{tag}: {ended:?}"
        );
        if let Some(theirs) = unrar_tests_ok(tag, &archive) {
            assert!(!theirs, "{tag}: unrar t -md64g passed it");
        }
    }
}
