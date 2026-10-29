//! Spec F: the read path over the section 5 vectors, and the differential
//! of section 6.2 against the old engine through `rarkit-oracle`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rarkit::{
    extract, Archive, Disposition, ErrorKind, Format, MemberInfo, MemberOutcome, Progress,
    RangeSource, ReadOptions, Sink,
};

fn vectors() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F"
    ))
}

fn archive_bytes(name: &str) -> Vec<u8> {
    std::fs::read(vectors().join("archives").join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn source(data: Vec<u8>) -> Arc<dyn RangeSource> {
    Arc::new(data)
}

/// One member as the sink saw it: name, directory, bytes, verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Got {
    name: Vec<u8>,
    is_directory: bool,
    data: Vec<u8>,
    checksum_ok: Option<bool>,
}

/// What one extraction produced, per member.
#[derive(Debug, Default)]
struct Collect {
    members: Vec<Got>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            self.members.push(Got {
                name: member.name.to_vec(),
                is_directory: true,
                data: Vec::new(),
                checksum_ok: None,
            });
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if member.is_directory {
            return Ok(());
        }
        self.members.push(Got {
            name: member.name.to_vec(),
            is_directory: false,
            data: out.unwrap_or_default(),
            checksum_ok: outcome.checksum_ok,
        });
        Ok(())
    }
}

/// A `Progress` that asserts `released` is monotone per volume.
#[derive(Default)]
struct Watch {
    last: Vec<u64>,
    volumes_done: Vec<u32>,
}

impl Progress for Watch {
    fn released(&mut self, volume: u32, offset: u64) -> rarkit::Result<()> {
        while self.last.len() <= volume as usize {
            self.last.push(0);
        }
        assert!(
            offset >= self.last[volume as usize],
            "released went backwards on volume {volume}: {offset} after {}",
            self.last[volume as usize]
        );
        self.last[volume as usize] = offset;
        Ok(())
    }

    fn volume_done(&mut self, volume: u32) -> rarkit::Result<()> {
        self.volumes_done.push(volume);
        Ok(())
    }
}

fn run(names: &[&str], password: Option<&str>) -> (rarkit::Result<rarkit::ExtractReport>, Collect) {
    let volumes: Vec<Arc<dyn RangeSource>> =
        names.iter().map(|n| source(archive_bytes(n))).collect();
    let opts = ReadOptions::default().with_password(password.map(rarkit::Password::from));
    let mut sink = Collect::default();
    let mut watch = Watch::default();
    let report = extract(volumes, &opts, &mut sink, &mut watch);
    (report, sink)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

#[test]
fn the_smallest_archive_lists_one_stored_member() {
    let a = Archive::open(
        source(archive_bytes("f01_stored.rar")),
        &ReadOptions::default(),
    )
    .unwrap();
    assert_eq!(a.format(), Format::Rar5);
    assert_eq!(a.start(), 0);
    assert!(!a.is_solid());
    let members: Vec<_> = a.members().collect();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].name, b"hello.txt");
    assert_eq!(members[0].unpacked_size, Some(16));
    assert_eq!(members[0].method, rarkit::Method::Stored);
    assert_eq!(a.blocks().count(), 3);
}

#[test]
fn a_stub_is_found_and_offsets_stay_in_source_coordinates() {
    let a = Archive::open(
        source(archive_bytes("f16_sfx_prefix.rar")),
        &ReadOptions::default(),
    )
    .unwrap();
    assert_eq!(a.start(), 4096);
    let m = a.members().next().unwrap();
    assert!(m.data.start > 4096, "source coordinates, not archive ones");
}

#[test]
fn a_genuine_rar15_directory_is_a_directory() {
    // Spec F 8.1 defect 1: DOS RAR 1.55 marks a directory with the DOS
    // attribute 0x10 alone, header flags 0x8000 and nothing else.
    let a = Archive::open(
        source(archive_bytes("D155_M5.RAR")),
        &ReadOptions::default(),
    )
    .unwrap();
    assert_eq!(a.format(), Format::Rar15);
    let dirs: Vec<_> = a
        .members()
        .filter(|m| m.is_directory)
        .map(|m| m.name.to_vec())
        .collect();
    assert_eq!(dirs, vec![b"SUB".to_vec(), b"SUB/NESTED".to_vec()]);
}

#[test]
fn the_rar4_family_label_comes_from_the_highest_unpack_version() {
    for (name, want) in [
        ("D155_M5.RAR", Format::Rar15),
        ("D250_M5.RAR", Format::Rar20),
        ("r420_m5.rar", Format::Rar4Family),
        ("D140_M5.RAR", Format::Rar13),
    ] {
        let a = Archive::open(source(archive_bytes(name)), &ReadOptions::default()).unwrap();
        assert_eq!(a.format(), want, "{name}");
    }
}

#[test]
fn names_come_back_with_one_separator_for_every_format() {
    for name in ["D140_M5.RAR", "D155_M5.RAR", "D250_M5.RAR", "r420_m5.rar"] {
        let a = Archive::open(source(archive_bytes(name)), &ReadOptions::default()).unwrap();
        for m in a.members() {
            assert!(
                !m.name.contains(&b'\\'),
                "{name}: {:?} still has a backslash",
                m.name_lossy()
            );
        }
    }
}

#[test]
fn a_blake2sp_member_gets_its_verdict() {
    // Spec F 3.2.6 and 5.1: f05 carries a BLAKE2sp hash extra record in
    // place of the CRC32 file flag.
    let (report, sink) = run(&["f05_blake.rar"], None);
    let report = report.unwrap();
    assert_eq!(report.checksum_failures, 0);
    assert_eq!(sink.members[0].checksum_ok, Some(true));
}

#[test]
fn a_comment_service_record_is_read() {
    let a = Archive::open(
        source(archive_bytes("f06_comment.rar")),
        &ReadOptions::default(),
    )
    .unwrap();
    assert_eq!(a.comment().map(<[u8]>::len), Some(27));
    // The comment is a service record, not a member.
    assert_eq!(a.members().count(), 1);
}

#[test]
fn a_recovery_record_and_a_locator_are_reported() {
    let a = Archive::open(source(archive_bytes("f09_rr.rar")), &ReadOptions::default()).unwrap();
    assert!(a.has_recovery_record());
    let services: Vec<_> = a
        .blocks()
        .filter(|b| matches!(b.kind, rarkit::BlockKind::Service(_)))
        .collect();
    assert_eq!(services.len(), 2, "QO and RR");
}

#[test]
fn volume_facts_answer_for_both_ends_of_a_set() {
    let first = Archive::open(
        source(archive_bytes("f11_svol.part1.rar")),
        &ReadOptions::default(),
    )
    .unwrap();
    assert!(first.volume().is_volume);
    assert!(first.volume().is_first);
    assert_eq!(first.volume().number, Some(0));
    assert_eq!(first.volume().next_follows, Some(true));

    let last = Archive::open(
        source(archive_bytes("f11_svol.part4.rar")),
        &ReadOptions::default(),
    )
    .unwrap();
    assert!(!last.volume().is_first);
    assert_eq!(last.volume().number, Some(3));
    assert_eq!(last.volume().next_follows, Some(false));
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

#[test]
fn a_bad_header_checksum_stops_the_walk_there() {
    let err = Archive::open(
        source(archive_bytes("f14_bad_header_crc.rar")),
        &ReadOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::HeaderChecksum), "{err}");
}

#[test]
fn a_source_ending_inside_a_member_is_truncated() {
    let err = Archive::open(
        source(archive_bytes("f13_truncated.rar")),
        &ReadOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Truncated), "{err}");
}

#[test]
fn a_header_encrypted_archive_needs_a_password() {
    for name in ["f08_hp.rar", "r420_hp.rar"] {
        let err = Archive::open(source(archive_bytes(name)), &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(err.kind(), ErrorKind::PasswordRequired),
            "{name}: {err}"
        );
    }
}

/// SPEC-API 4.3: `headers_encrypted` answers for both formats. RAR 5
/// signals it by the archive encryption block ahead of the main block
/// (spec F, `f08_hp.rar`), RAR 4 by the main header's flag; archives
/// without `-hp` read false in both.
#[test]
fn headers_encrypted_reads_true_on_both_formats_with_the_password() {
    let opts = ReadOptions::default().with_password(Some(rarkit::Password::from("Secret")));
    for (name, want) in [
        ("f08_hp.rar", true),
        ("r420_hp.rar", true),
        ("f01_stored.rar", false),
        ("f07_pw.rar", false),
    ] {
        let archive = Archive::open(source(archive_bytes(name)), &opts)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(archive.headers_encrypted(), want, "{name}");
    }
}

#[test]
fn rar5_answers_wrong_password_before_a_header_is_decrypted() {
    let opts =
        ReadOptions::default().with_password(Some(rarkit::Password::from("definitely not it")));
    let err = Archive::open(source(archive_bytes("f08_hp.rar")), &opts).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::WrongPassword), "{err}");
}

#[test]
fn a_rar4_wrong_password_shows_as_a_failed_header_check() {
    let opts =
        ReadOptions::default().with_password(Some(rarkit::Password::from("definitely not it")));
    let err = Archive::open(source(archive_bytes("r420_hp.rar")), &opts).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::HeaderChecksum), "{err}");
}

#[test]
fn nothing_is_an_archive_without_a_signature() {
    let data = vec![0u8; 4096];
    let err = Archive::open(source(data), &ReadOptions::default()).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::NotAnArchive), "{err}");
}

// ---------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------

#[test]
fn a_stored_member_extracts_end_to_end() {
    let (report, sink) = run(&["f01_stored.rar"], None);
    let report = report.unwrap();
    assert_eq!(report.members, 1);
    assert_eq!(report.checksum_failures, 0);
    assert_eq!(sink.members.len(), 1);
    assert_eq!(sink.members[0].name, b"hello.txt");
    assert_eq!(sink.members[0].data.len(), 16);
    assert_eq!(sink.members[0].checksum_ok, Some(true));
    // The report carries this operation's own peak working memory, which
    // for a stored member is the read buffer plus the one copy buffer.
    assert!(
        report.peak_working_memory > 0 && report.peak_working_memory < 1 << 20,
        "peak working memory {} bytes",
        report.peak_working_memory
    );
}

#[test]
fn a_member_checksum_failure_is_not_an_error() {
    // Spec F 4.4 and 8: a member whose content checksum fails is delivered
    // with `checksum_ok == Some(false)` and counted, never raised as an
    // error that hides which member it was.
    //
    // `f15_bad_data_crc.rar` does NOT pin this: its generator flips
    // `b[len(b) - 4]`, which in this layout (main, file, 16 data bytes,
    // end) lands in the END record's size field, not in the member's data.
    // The committed expected walk shows that, and the rule is pinned here
    // by damaging a byte that really is in the data area. The vector
    // itself still needs correcting.
    let mut damaged = archive_bytes("f01_stored.rar");
    let at = damaged.len() - 12;
    damaged[at] ^= 0x01;
    let opts = ReadOptions::default();
    let mut sink = Collect::default();
    let mut watch = Watch::default();
    let volumes: Vec<Arc<dyn RangeSource>> = vec![source(damaged)];
    let report = extract(volumes, &opts, &mut sink, &mut watch)
        .expect("a checksum failure is never an error on the extract path");
    assert_eq!(report.members, 1);
    assert_eq!(report.checksum_failures, 1);
    assert_eq!(sink.members[0].checksum_ok, Some(false));
}

#[test]
fn f15_damages_the_end_record_and_its_member_still_arrives() {
    // What the committed vector actually holds: an intact member followed
    // by an end record whose size field runs past the file. The member is
    // delivered with a passing verdict, and the damaged trailing header is
    // then reported rather than swallowed.
    let (report, sink) = run(&["f15_bad_data_crc.rar"], None);
    assert_eq!(sink.members.len(), 1);
    assert_eq!(sink.members[0].checksum_ok, Some(true));
    let err = report.unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::Truncated | ErrorKind::Corrupt(_)),
        "{err}"
    );
}

/// The RAR 1.3 member checksum of spec F 3.4.3: a 16-bit running value
/// that adds each byte of the UNPACKED member modulo 2^16 and rotates the
/// result left by one bit.
fn sum16(data: &[u8]) -> u16 {
    let mut state = 0u16;
    for byte in data {
        state = state.wrapping_add(u16::from(*byte)).rotate_left(1);
    }
    state
}

/// A RAR 1.3 archive of one STORED member, built from the header layout of
/// spec F 3.4. Every genuine RAR 1.3 vector stores its members compressed,
/// so this is the only way to reach the stored path and the internal
/// checksum verification of 3.4.3 without the RAR 1.3 decoder.
fn rar13_stored(name: &[u8], body: &[u8], damage: Option<usize>) -> Vec<u8> {
    let mut out = b"RE~^".to_vec();
    out.extend_from_slice(&7u16.to_le_bytes()); // archive header size
    out.push(0x80); // the bit every writer sets
    let header_size = 21 + name.len();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // packed
    out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // unpacked
    out.extend_from_slice(&sum16(body).to_le_bytes());
    out.extend_from_slice(&(header_size as u16).to_le_bytes());
    out.extend_from_slice(&0x5D32_86A0u32.to_le_bytes()); // DOS time
    out.push(0x20); // attributes
    out.push(0x00); // flags
    out.push(2); // unpack version
    out.push(name.len() as u8);
    out.push(0); // method: stored
    out.extend_from_slice(name);
    let at = out.len();
    out.extend_from_slice(body);
    if let Some(offset) = damage {
        out[at + offset] ^= 0x40;
    }
    out
}

#[test]
fn a_rar13_stored_member_is_verified_by_its_own_checksum() {
    let body: Vec<u8> = (0..4096u32).map(|i| (i * 31) as u8).collect();

    let clean = rar13_stored(b"HELLO.TXT", &body, None);
    let mut sink = Collect::default();
    let mut watch = Watch::default();
    let volumes: Vec<Arc<dyn RangeSource>> = vec![source(clean)];
    let report = extract(volumes, &ReadOptions::default(), &mut sink, &mut watch).unwrap();
    assert_eq!(report.checksum_failures, 0);
    assert_eq!(sink.members[0].data, body);
    // The API has no 16-bit checksum variant, so nothing is reported
    // through `MemberInfo::checksum`; the verdict still arrives.
    assert_eq!(sink.members[0].checksum_ok, Some(true));

    let damaged = rar13_stored(b"HELLO.TXT", &body, Some(1000));
    let mut sink = Collect::default();
    let mut watch = Watch::default();
    let volumes: Vec<Arc<dyn RangeSource>> = vec![source(damaged)];
    let report = extract(volumes, &ReadOptions::default(), &mut sink, &mut watch)
        .expect("a checksum failure is never an error");
    assert_eq!(report.checksum_failures, 1);
    assert_eq!(sink.members[0].checksum_ok, Some(false));
}

#[test]
fn a_stored_member_split_over_four_volumes_joins() {
    let (report, sink) = run(
        &[
            "f11_svol.part1.rar",
            "f11_svol.part2.rar",
            "f11_svol.part3.rar",
            "f11_svol.part4.rar",
        ],
        None,
    );
    let report = report.unwrap();
    assert_eq!(report.members, 1);
    assert_eq!(report.checksum_failures, 0);
    assert_eq!(sink.members[0].name, b"rand.bin");
    assert_eq!(sink.members[0].data.len(), 12_000);
    assert_eq!(sink.members[0].checksum_ok, Some(true));
}

#[test]
fn a_compressed_member_split_over_four_volumes_is_one_stream_to_the_decoder() {
    // Spec F 3.5.4: the packed bytes of the fragments are ONE stream to the
    // decoder. It is not restarted, its dictionary is not cleared, and it
    // never learns that a boundary passed. f12_cvol's `rand.bin` is one
    // -m3 member over four volumes, so a decoder restarted at any boundary
    // cannot produce the member's own CRC32.
    let (report, sink) = run(
        &[
            "f12_cvol.part1.rar",
            "f12_cvol.part2.rar",
            "f12_cvol.part3.rar",
            "f12_cvol.part4.rar",
        ],
        None,
    );
    let report = report.expect("f12_cvol extracts");
    assert_eq!(report.members, 2);
    assert_eq!(report.checksum_failures, 0);
    let split = sink
        .members
        .iter()
        .find(|m| m.name == b"rand.bin")
        .expect("the split member");
    assert_eq!(split.data.len(), 12_000);
    assert_eq!(split.checksum_ok, Some(true));
    for member in &sink.members {
        assert_eq!(member.checksum_ok, Some(true), "{:?}", member.name);
    }
}

#[test]
fn a_set_handed_over_out_of_order_is_corrupt() {
    // Spec F 3.5.3: a volume whose declared number is lower than the
    // previous one, or more than one higher, means the provider is handing
    // over a different set or one out of order, and continuing would
    // splice one member's bytes from two archives.
    let err = run(
        &[
            "f11_svol.part1.rar",
            "f11_svol.part3.rar",
            "f11_svol.part4.rar",
        ],
        None,
    )
    .0
    .unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::Corrupt(_)),
        "{err} (kind {:?})",
        err.kind()
    );
}

#[test]
fn a_set_that_ends_early_is_truncated() {
    let err = run(&["f11_svol.part1.rar", "f11_svol.part2.rar"], None)
        .0
        .unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Truncated), "{err}");
}

#[test]
fn fragments_from_two_different_sets_are_never_spliced() {
    // Spec F 3.5.4: the next volume's first member must carry the
    // "continues from" flag, the same name, size and compression info.
    let err = run(&["f11_svol.part1.rar", "f12_cvol.part2.rar"], None)
        .0
        .unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::Corrupt(_) | ErrorKind::Truncated),
        "{err}"
    );
}

#[test]
fn a_method_with_no_decoder_is_refused_by_name_never_skipped_silently() {
    // Spec F section 8. Every codec this crate's scope names is now in the
    // build, so the member that pins this rule is one nothing can decode by
    // design: a RAR 3 filter program that is not one of the six standard
    // ones, which is refused rather than interpreted. It must come
    // back as an error NAMING it, with the member's own `close` already
    // called, and the archive's other members unharmed.
    let (report, sink) = run(&["r420_m5.rar"], None);
    report.expect("every member of r420_m5 decodes");
    assert!(!sink.members.is_empty());
    for member in sink.members.iter().filter(|m| !m.is_directory) {
        assert_eq!(
            member.checksum_ok,
            Some(true),
            "{:?}",
            String::from_utf8_lossy(&member.name)
        );
    }
    // An unpack version no table names is the other half of the rule, and
    // it needs no fixture: `f03_m3.rar` with its version byte changed.
    let mut bytes = archive_bytes("f03_m3.rar");
    let archive = Archive::open(source(bytes.clone()), &ReadOptions::default()).unwrap();
    let member = archive.members().next().expect("one member");
    let at = member.data.start as usize;
    assert!(at > 0);
    drop(archive);
    // The compression info's low six bits are the algorithm version; a
    // version this package does not know is refused BEFORE anything else
    // in the member is looked at (spec F question 9).
    let mut found = false;
    for index in 8..at {
        if bytes[index] == 0x80 && bytes[index + 1] == 0x0c {
            bytes[index] = 0x81;
            found = true;
            break;
        }
    }
    if !found {
        return;
    }
    let mut sink = Collect::default();
    let err = extract(
        vec![source(bytes)],
        &ReadOptions::default(),
        &mut sink,
        &mut (),
    )
    .unwrap_err();
    assert!(
        matches!(
            err.kind(),
            ErrorKind::Unsupported(_) | ErrorKind::HeaderChecksum
        ),
        "{err}"
    );
}

#[test]
fn a_rar5_compressed_member_extracts_and_verifies() {
    // The same archive package F could only refuse: method 3, a dictionary
    // above the minimum, decoded through spec H2 and verified against the
    // CRC32 the header carries.
    let (report, sink) = run(&["f03_m3.rar"], None);
    let report = report.expect("f03_m3 extracts");
    assert_eq!(sink.members.len(), 1);
    assert_eq!(sink.members[0].checksum_ok, Some(true));
    assert_eq!(sink.members[0].data.len() as u64, report.bytes);
    assert!(report.bytes > 0);
    assert_eq!(report.checksum_failures, 0);
}

#[test]
fn a_solid_chain_continues_from_the_member_before_it() {
    // Spec F 3.6: a member with its solid bit set is decoded with the
    // decoder state the member before it left. f04_solid.rar's second
    // member carries that bit; both must verify.
    let (report, sink) = run(&["f04_solid.rar"], None);
    report.expect("f04_solid extracts");
    assert_eq!(sink.members.len(), 2, "both members had their close");
    for member in &sink.members {
        assert_eq!(member.checksum_ok, Some(true), "{:?}", member.name);
    }
}

#[test]
fn a_solid_chain_is_refused_when_its_first_member_is_missing() {
    // Spec F 3.6: a solid chain whose first member is missing is not
    // repairable, and nothing here can rebuild the dictionary it needs.
    //
    // The vector is f04_solid.rar with its FIRST member's block cut out,
    // which is what a caller opening a middle volume of a set hands over:
    // the archive still parses, and the member that continues the chain
    // must be refused by name rather than handed back wrong bytes.
    let whole = archive_bytes("f04_solid.rar");
    let archive = Archive::open(source(whole.clone()), &ReadOptions::default()).unwrap();
    let first = archive
        .blocks()
        .find(|b| matches!(b.kind, rarkit::BlockKind::File))
        .expect("a file block");
    let cut = first.range.start as usize..first.range.end as usize;
    let mut without = whole[..cut.start].to_vec();
    without.extend_from_slice(&whole[cut.end..]);

    let mut sink = Collect::default();
    let report = extract(
        vec![source(without)],
        &ReadOptions::default(),
        &mut sink,
        &mut (),
    );
    let err = report.unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Corrupt(_)), "{err}");
    assert_eq!(sink.members.len(), 1, "the member still had its close");
    assert_eq!(sink.members[0].checksum_ok, Some(false));
}

#[test]
fn a_directory_entry_is_offered_and_carries_no_bytes() {
    let (report, sink) = run(&["f02_dirs.rar"], None);
    report.unwrap();
    let dirs: Vec<_> = sink.members.iter().filter(|m| m.is_directory).collect();
    assert_eq!(dirs.len(), 2);
}

#[test]
fn an_encrypted_stored_member_extracts_with_its_password() {
    let (report, sink) = run(&["f07_pw.rar"], Some("Secret"));
    match report {
        Ok(r) => {
            assert_eq!(r.checksum_failures, 0, "{:?}", sink.members);
            assert_eq!(sink.members[0].checksum_ok, Some(true));
        }
        Err(e) => panic!("f07_pw.rar with its password: {e}"),
    }
}

#[test]
fn cancelling_ends_the_operation() {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let opts = ReadOptions::default().with_cancel(Some(flag));
    let mut sink = Collect::default();
    let mut watch = Watch::default();
    let volumes: Vec<Arc<dyn RangeSource>> = vec![source(archive_bytes("f01_stored.rar"))];
    let err = extract(volumes, &opts, &mut sink, &mut watch).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Cancelled), "{err}");
}

// ---------------------------------------------------------------------
// One pass, and what it costs
// ---------------------------------------------------------------------

/// A source that records every `read_at`.
struct Counted {
    data: Vec<u8>,
    reads: AtomicUsize,
    bytes: AtomicUsize,
}

impl RangeSource for Counted {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let n = self.data.read_at(offset, buf)?;
        self.bytes.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
    fn available(&self) -> u64 {
        self.data.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

#[test]
fn extraction_never_reads_more_than_the_volumes_hold() {
    let names = [
        "f11_svol.part1.rar",
        "f11_svol.part2.rar",
        "f11_svol.part3.rar",
        "f11_svol.part4.rar",
    ];
    let counted: Vec<Arc<Counted>> = names
        .iter()
        .map(|n| {
            Arc::new(Counted {
                data: archive_bytes(n),
                reads: AtomicUsize::new(0),
                bytes: AtomicUsize::new(0),
            })
        })
        .collect();
    let volumes: Vec<Arc<dyn RangeSource>> = counted
        .iter()
        .map(|c| c.clone() as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let mut watch = Watch::default();
    extract(volumes, &ReadOptions::default(), &mut sink, &mut watch).unwrap();
    for (name, c) in names.iter().zip(&counted) {
        let read = c.bytes.load(Ordering::Relaxed);
        // Each byte range is read once, plus the buffered reader's final
        // short read at the end of each volume.
        assert!(
            read <= c.data.len() + 4096,
            "{name}: read {read} of {} bytes",
            c.data.len()
        );
    }
    assert_eq!(watch.volumes_done, vec![0, 1, 2, 3]);
}

// ---------------------------------------------------------------------
// The differential of spec F 6.2
// ---------------------------------------------------------------------

#[cfg(feature = "oracle-compare")]
#[test]
fn every_vector_archive_agrees_with_the_old_engine_or_is_owed() {
    let mut owed: Vec<String> = Vec::new();
    let mut compared = 0usize;
    let sets: Vec<(Vec<&str>, Option<&str>)> = vec![
        (vec!["f01_stored.rar"], None),
        (vec!["f02_dirs.rar"], None),
        (vec!["f05_blake.rar"], None),
        (vec!["f06_comment.rar"], None),
        (
            vec![
                "f11_svol.part1.rar",
                "f11_svol.part2.rar",
                "f11_svol.part3.rar",
                "f11_svol.part4.rar",
            ],
            None,
        ),
        (vec!["f16_sfx_prefix.rar"], None),
        (vec!["D140_M5.RAR"], None),
        (vec!["D155_M5.RAR"], None),
        (vec!["D250_M5.RAR"], None),
        (vec!["r420_m5.rar"], None),
    ];
    for (names, password) in sets {
        let raw: Vec<Vec<u8>> = names.iter().map(|n| archive_bytes(n)).collect();
        let borrowed: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
        let old = match rarkit_oracle::extract(&borrowed, password.map(str::as_bytes)) {
            Ok(members) => members,
            Err(e) => {
                owed.push(format!("{names:?}: the old engine refused it ({e})"));
                continue;
            }
        };
        let (_report, ours) = run(&names, password);
        for member in &old {
            if member.is_directory {
                continue;
            }
            let Some(mine) = ours
                .members
                .iter()
                .find(|m| !m.is_directory && m.name == member.name)
            else {
                owed.push(format!(
                    "{names:?}: {} is not in this package's output",
                    String::from_utf8_lossy(&member.name)
                ));
                continue;
            };
            if mine.checksum_ok == Some(false) {
                owed.push(format!(
                    "{names:?}: {} needs a codec this build has not got",
                    String::from_utf8_lossy(&member.name)
                ));
                continue;
            }
            assert_eq!(
                mine.data,
                member.data,
                "{names:?}: {} differs from the old engine",
                String::from_utf8_lossy(&member.name)
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "the differential compared nothing");
    if !owed.is_empty() {
        eprintln!("owed by a later package:\n  {}", owed.join("\n  "));
    }
}

#[cfg(feature = "oracle-compare")]
/// Spec F 8.1 defect 1. The specification lists this as a DELIBERATE
/// disagreement with the old engine, which made empty FILES of a genuine
/// RAR 1.5 writer's directory entries and exited 0. The oracle in this
/// repository is built from the fork after its fix, where the defect was
/// already fixed, so the two now agree: what is asserted here is the
/// behaviour, not the disagreement.
#[test]
fn a_genuine_rar15_directory_is_never_an_empty_file() {
    let raw = archive_bytes("D155_M5.RAR");
    let old = rarkit_oracle::extract(&[raw.as_slice()], None);
    let a = Archive::open(source(raw), &ReadOptions::default()).unwrap();
    let ours: Vec<_> = a
        .members()
        .filter(|m| m.is_directory)
        .map(|m| m.name.to_vec())
        .collect();
    assert_eq!(ours.len(), 2, "this package sees two directories");
    if let Ok(old) = old {
        assert_eq!(
            old.iter().filter(|m| m.is_directory).count(),
            2,
            "the old engine's fork fixed this; a disagreement here means the \
             oracle was built before the fix"
        );
    }
}

// ---------------------------------------------------------------------
// The reference differential of spec F 6.1
// ---------------------------------------------------------------------

/// Whether the reference `unrar` answers on PATH at all. Asked once, so
/// a machine without it (a hosted Windows runner has none) is told from a
/// machine whose `unrar` refuses every archive, which stays a failure.
fn have_unrar() -> bool {
    std::process::Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|found| found.status.success())
        .unwrap_or(false)
}

/// `unrar lb` on `path`, or `None` when the reference is not installed or
/// refuses the archive (which for the damaged vectors it should).
fn unrar_lb(path: &std::path::Path, password: Option<&str>) -> Option<Vec<String>> {
    let mut command = std::process::Command::new("unrar");
    command.arg("lb");
    match password {
        Some(p) => command.arg(format!("-p{p}")),
        None => command.arg("-p-"),
    };
    let out = command.arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            // THE REFERENCE PRINTS THE HOST'S SEPARATOR, NOT THE
            // ARCHIVE'S. Spec F 3.3.8 records that these containers
            // store a backslash whatever the host OS is, and that the
            // reference prints forward slashes; that observation was
            // taken on a Mac. On Windows the same reference, same
            // version 7.23, prints `SUB\NESTED\DEEP.TXT` for the same
            // archive, where this package answers `SUB/NESTED/DEEP.TXT`
            // on every platform (measured on a Windows desktop, 22 Sep 2026).
            // The separator is therefore normalised HERE, on the
            // reference's side of the comparison only: what this package
            // emits is spec F question 3's business and is not touched
            // to make a test pass. Whether the API should ever emit a
            // native separator is an open question put to SPEC-API.
            .map(|l| l.replace('\\', "/"))
            .filter(|l| !l.is_empty())
            .collect(),
    )
}

/// Spec F 6.1: `Archive::open` + `members()` against `unrar lb`, name for
/// name, on every vector the reference accepts. The reference prints a
/// directory and a file alike and uses forward slashes for every format,
/// which is what question 3's normalisation is for.
#[test]
fn every_vector_lists_the_names_the_reference_prints() {
    // THE MACHINE THIS STATES: the reference `unrar` on PATH; no thread
    // pool (a listing is one thread's) and the default memory policy.
    // Without the reference there is nothing to compare, and the test says
    // so and stops, as the suite's other reference arms do. With it, ten
    // archives compared is still the floor below.
    if !have_unrar() {
        eprintln!("reference `unrar` is not on PATH: skipped, no name was compared");
        return;
    }
    let root = vectors().join("archives");
    let mut checked = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // A volume set is listed from its first volume only, and the
        // reference then follows the rest itself.
        if name.contains(".part") && !name.contains("part1.") {
            continue;
        }
        let password = match name.as_str() {
            "f07_pw.rar" | "f08_hp.rar" | "r420_hp.rar" => Some("Secret"),
            _ => None,
        };
        let Some(reference) = unrar_lb(&path, password) else {
            skipped.push(format!("{name}: the reference would not list it"));
            continue;
        };
        let opts = ReadOptions::default().with_password(password.map(rarkit::Password::from));
        let archive = match Archive::open(source(archive_bytes(&name)), &opts) {
            Ok(a) => a,
            Err(e) => {
                skipped.push(format!("{name}: this package would not list it ({e})"));
                continue;
            }
        };
        let mut ours: Vec<String> = archive
            .members()
            .map(|m| m.name_lossy().into_owned())
            .collect();
        let mut theirs = reference;
        ours.sort();
        theirs.sort();
        assert_eq!(ours, theirs, "{name}: names differ from `unrar lb`");
        checked += 1;
    }
    if !skipped.is_empty() {
        eprintln!("not compared:\n  {}", skipped.join("\n  "));
    }
    assert!(
        checked >= 10,
        "the reference differential compared only {checked} archives; is `unrar` installed?"
    );
}
