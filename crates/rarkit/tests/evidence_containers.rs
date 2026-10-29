//! The container facts the evidence pass of 6 Oct 2026 established, each
//! on the specification's own probe archive
//! (`specs/vectors-F/evidence-06oct`, with the reference's recorded
//! answer beside it) and named by its section of spec F.
//!
//! One thread throughout; every archive is under 1 KiB unless a test says
//! otherwise.

use std::sync::Arc;

use rarkit::{
    extract, Archive, Disposition, ErrorKind, MemberInfo, MemberOutcome, RangeSource, ReadOptions,
    Sink,
};

fn arm(path: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-F/evidence-06oct/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// What one member came to: its name, its bytes, its checksum verdict and
/// how many of its leading fragments disagreed with their field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Came {
    name: String,
    data: Vec<u8>,
    checksum_ok: Option<bool>,
    fragment_mismatches: u32,
}

#[derive(Default)]
struct Keep(Vec<Came>);

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.0.push(Came {
            name: member.name_lossy().into_owned(),
            data: out.unwrap_or_default(),
            checksum_ok: outcome.checksum_ok,
            fragment_mismatches: outcome.fragment_mismatches,
        });
        Ok(())
    }
}

/// Every member of the set, and how the operation ended.
fn read(volumes: &[Vec<u8>], opts: &ReadOptions) -> (Vec<Came>, rarkit::Result<()>) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Keep::default();
    let ended = extract(sources, opts, &mut sink, &mut ()).map(|_| ());
    (sink.0, ended)
}

/// The names of the members that came out with a good checksum, the
/// operation having ended without an error.
fn good(volumes: &[Vec<u8>]) -> Vec<String> {
    let (came, ended) = read(volumes, &ReadOptions::default());
    ended.unwrap_or_else(|e| panic!("the archive was refused: {e}"));
    for member in &came {
        assert_eq!(member.checksum_ok, Some(true), "{}", member.name);
    }
    came.into_iter().map(|m| m.name).collect()
}

/// The members the reference tested "OK", in order, from the answer
/// recorded beside an arm (`<arm>.txt`, its `unrar t` section).
fn reference_ok(arm_path: &str) -> Vec<String> {
    let text = String::from_utf8(arm(&format!("{arm_path}.txt"))).expect("the record is text");
    let section = text
        .split("\n$ ")
        .find(|part| part.starts_with("unrar t "))
        .expect("an unrar t section");
    section
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(" OK"))
        .filter(|line| line.starts_with("Testing ") || line.starts_with("... "))
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(str::to_owned)
        .collect()
}

fn open(bytes: Vec<u8>) -> rarkit::Result<Archive> {
    let src: Arc<dyn RangeSource> = Arc::new(bytes);
    Archive::open(src, &ReadOptions::default())
}

// ---------------------------------------------------------------------
// 3.2.10 U1 and 3.3.3 B1: a block of a type the reader does not use
// ---------------------------------------------------------------------

/// U1: a RAR 5 block of an unknown type is skipped by its header size and
/// data size whatever its flags, and reported as `BlockKind::Other`. The
/// reference lists and tests the members on both sides, exit 0.
#[test]
fn a_rar5_block_of_an_unknown_type_is_skipped_whatever_its_flags() {
    for (name, kind) in [
        ("type-9-skip", 9),
        ("type-9-noskip", 9),
        ("type-300-skip", 300),
        ("type-0-skip", 0),
        ("type-6-noskip", 6),
    ] {
        let bytes = arm(&format!("rar5-container/{name}/x.rar"));
        let tested = reference_ok(&format!("rar5-container/{name}"));
        assert_eq!(tested, ["a.txt", "b.txt", "c.txt"], "{name}: the record");
        assert_eq!(good(std::slice::from_ref(&bytes)), tested, "{name}");
        let archive = open(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let others = archive
            .blocks()
            .filter(|b| b.kind == rarkit::BlockKind::Other(kind))
            .count();
        assert_eq!(others, 1, "{name}: the block is reported by its type");
    }
}

/// B1: the same in the older container, with flag 0x4000 and without it,
/// with a data area and without. Type 0x75 standing alone is the
/// exception: it is refused (B2, `tests/comment_block_outside_header.rs`).
#[test]
fn an_older_container_block_the_reader_does_not_use_is_skipped() {
    for kind in ["76", "77", "78", "79", "7c", "7f", "20"] {
        for form in ["skip", "noskip", "data"] {
            let name = format!("type-{kind}-{form}");
            let bytes = arm(&format!("old-container/{name}/x.rar"));
            let tested = reference_ok(&format!("old-container/{name}"));
            assert!(tested.len() >= 2, "{name}: the record");
            assert_eq!(good(&[bytes]), tested, "{name}");
        }
    }
}

/// The blocks now skipped were refused before, so the skip is put to
/// hostile input: every prefix of an archive that carries one, and every
/// single byte of it changed. Each case opens or ends in a named error;
/// none panics, and none can allocate for the skipped block, whose data
/// area is stepped over by its size and never read (a size past the end
/// of the source is `Truncated`).
#[test]
fn a_skipped_block_cut_or_damaged_anywhere_is_an_error_and_never_a_panic() {
    for path in [
        "rar5-container/type-9-noskip/x.rar",
        "old-container/type-7c-data/x.rar",
        "old-container/type-20-noskip/x.rar",
    ] {
        let whole = arm(path);
        assert!(whole.len() < 1024, "{path}");
        for cut in 0..whole.len() {
            let (_, ended) = read(&[whole[..cut].to_vec()], &ReadOptions::default());
            if let Err(e) = ended {
                assert!(
                    !matches!(
                        e.kind(),
                        ErrorKind::Unsupported(rarkit::Unsupported::Version(_))
                    ),
                    "{path} cut at {cut}: {e}"
                );
            }
        }
        for at in 0..whole.len() {
            let mut damaged = whole.clone();
            damaged[at] ^= 0xA5;
            let _ = read(&[damaged], &ReadOptions::default());
        }
    }
}
// ---------------------------------------------------------------------
// 3.3.8 X2: the fraction bytes of an extended time
// ---------------------------------------------------------------------

fn nanos_of_b(name: &str) -> u32 {
    let archive = open(arm(&format!("old-container/{name}/x.rar"))).expect(name);
    let member = archive
        .members()
        .find(|m| m.mtime.is_some_and(|t| t.nanos != 0))
        .unwrap_or_else(|| panic!("{name}: no member has a fraction"));
    member.mtime.unwrap().nanos
}

/// X2: the fraction is a count of 100 ns units in three bytes, least
/// significant first, and when fewer than three are present they are the
/// HIGH order ones. Each figure is the one the reference prints.
#[test]
fn an_extended_time_fraction_of_one_or_two_bytes_is_the_high_order_bytes() {
    for (name, nanos) in [
        ("xtime-frac-3-010000", 100),
        ("xtime-frac-2-0100", 25_600),
        ("xtime-frac-1-01", 6_553_600),
        ("xtime-frac-1-6b", 701_235_200),
        ("xtime-frac-2-6f6b", 704_076_800),
        ("xtime-m3", 704_088_300),
    ] {
        assert_eq!(nanos_of_b(name), nanos, "{name}");
    }
}
// ---------------------------------------------------------------------
// 3.5.6 C3 and C4: a leading fragment's checksum field of FFFFFFFF
// ---------------------------------------------------------------------

/// The two volumes of a set, under whichever naming its writer used.
fn set(name: &str) -> Vec<Vec<u8>> {
    let old_style = name.ends_with("-v15");
    let (first, second) = if old_style {
        ("x.rar", "x.r00")
    } else {
        ("x.part1.rar", "x.part2.rar")
    };
    vec![
        arm(&format!("volume-sets/{name}/{first}")),
        arm(&format!("volume-sets/{name}/{second}")),
    ]
}

fn mismatches(name: &str) -> u32 {
    let (came, ended) = read(&set(name), &ReadOptions::default());
    ended.unwrap_or_else(|e| panic!("{name}: {e}"));
    for member in &came {
        assert_eq!(member.checksum_ok, Some(true), "{name}: {}", member.name);
    }
    came.iter().map(|m| m.fragment_mismatches).sum()
}

/// A leading field is not judged when the member's unpack version is 15,
/// or when the field is FFFFFFFF in the older container, at version 20 as
/// at 15: the reference prints nothing for those and prints its "packed
/// data checksum error in volume" line for a wrong field at version 29.
#[test]
fn a_leading_fragment_field_of_ffffffff_is_no_checksum() {
    assert_eq!(mismatches("v4-lead-crc-ffffffff-v20"), 0, "FFFFFFFF, v20");
    assert_eq!(mismatches("v4-lead-crc-ffffffff-v15"), 0, "FFFFFFFF, v15");
    assert_eq!(mismatches("v4-lead-crc-wrong-v15"), 0, "any field, v15");
    assert_eq!(mismatches("v4-lead-crc-wrong"), 1, "a wrong field, v29");
    assert_eq!(mismatches("v5-lead-crc-wrong"), 1, "a wrong field, RAR 5");
}
// ---------------------------------------------------------------------
// 3.1.1, 3.2.3, 3.2.6, 3.2.6.1 T5, 3.2.9 S3: RAR 5 facts a sound reader
// already holds
// ---------------------------------------------------------------------

/// 3.1.1: the eighth signature byte must be 0, and a seventh byte other
/// than 0 and 1 names no archive this package reads.
#[test]
fn the_rar5_signature_is_matched_on_all_eight_bytes() {
    for name in ["sig-byte7-01", "sig-byte6-02", "sig-byte6-05"] {
        let bytes = arm(&format!("rar5-container/{name}/x.rar"));
        let found = rarkit::detect(&bytes, rarkit::DEFAULT_SFX_SCAN).expect(name);
        assert!(
            !found.is_some_and(|f| f.format == rarkit::Format::Rar5),
            "{name}: read as RAR 5"
        );
    }
}

/// 3.2.3: the first block after the signature is the main header or the
/// archive encryption header; anything else there is `Corrupt`.
#[test]
fn the_first_rar5_block_must_be_the_main_or_the_encryption_header() {
    let err = open(arm("rar5-container/main-absent/x.rar")).expect_err("no main header");
    assert!(matches!(err.kind(), ErrorKind::Corrupt(_)), "{err}");
}

/// 3.2.6, as restated on 8 Oct 2026: method values 6 and 7 are
/// COMPRESSED, like 1 to 5, and no RAR 5 method value is
/// `Unsupported(Method)`. These two arms put the value on a member whose
/// data is plain bytes, which no decoder reads under any method: the
/// member fails as its data fails, never by its method, and the other
/// members are read, as the reference's record beside each arm says.
#[test]
fn rar5_methods_6_and_7_are_decoded_and_fail_only_by_their_data() {
    for name in ["method-6", "method-7"] {
        let (came, ended) = read(
            &[arm(&format!("rar5-container/{name}/x.rar"))],
            &ReadOptions::default(),
        );
        let err = ended.expect_err(name);
        assert!(
            !matches!(err.kind(), ErrorKind::Unsupported(_)),
            "{name}: {err}"
        );
        let fine: Vec<String> = came
            .iter()
            .filter(|m| m.checksum_ok == Some(true))
            .map(|m| m.name.clone())
            .collect();
        assert_eq!(
            fine,
            reference_ok(&format!("rar5-container/{name}")),
            "{name}"
        );
        assert_eq!(fine, ["a.txt", "c.txt"], "{name}");
    }
}

/// One archive of `specs/vectors-F/method-code`, the probe behind 3.2.6's
/// "Method values 6 and 7 are COMPRESSED".
fn method_code_arm(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-F/method-code/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// 3.2.6 (bug sweep item SWEEP2-08OCT-50): on a genuine `-m3 -s` archive
/// of twenty members, the method of any one member set to 6 or to 7
/// changes nothing a reader does. Every member is good and has the bytes
/// it has in the untouched archive: a text member, an empty member that
/// carries a block of tables for the member after it, and an empty
/// member with no packed bytes, 40 archives in all, as the reference
/// answers every one of them. Before the rule was restated a reader
/// refused the member, and in this solid chain lost every member after
/// it.
///
/// Read at the default width, at one worker, and by `extract_parallel` at
/// two. Each archive is under 3 KiB and its members come to 23,840 bytes.
#[test]
fn rar5_methods_6_and_7_are_compressed_members_in_a_solid_chain() {
    let (base, ended) = read(&[method_code_arm("base.rar")], &ReadOptions::default());
    ended.expect("the untouched archive");
    assert_eq!(base.len(), 20);
    let cases = String::from_utf8(method_code_arm("cases.tsv")).expect("the cases are text");
    let mut arms = 0;
    for line in cases.lines().skip(2) {
        let name = line.split('\t').next().expect("an archive name");
        if name.ends_with(".method-0.rar") {
            continue;
        }
        arms += 1;
        let bytes = method_code_arm(name);
        for workers in [None, Some(1)] {
            let options = ReadOptions::default().with_workers(workers);
            let (came, ended) = read(std::slice::from_ref(&bytes), &options);
            ended.unwrap_or_else(|e| panic!("{name}, workers {workers:?}: {e}"));
            assert_eq!(came, base, "{name}, workers {workers:?}");
        }
        let wide = WideKeep::default();
        let source: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes)];
        rarkit::extract_parallel(source, &ReadOptions::default(), &wide, 2)
            .unwrap_or_else(|e| panic!("{name}, extract_parallel: {e}"));
        let mut came = wide.0.into_inner().expect("lock");
        came.sort_by_key(|member| base.iter().position(|b| b.name == member.name));
        assert_eq!(came, base, "{name}, extract_parallel");
    }
    assert_eq!(arms, 40);
}

/// [`Keep`] for `extract_parallel`, whose members close in any order.
#[derive(Default)]
struct WideKeep(std::sync::Mutex<Vec<Came>>);

impl rarkit::ParallelSink for WideKeep {
    type Out = Vec<u8>;

    fn open(&self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.0.lock().expect("lock").push(Came {
            name: member.name_lossy().into_owned(),
            data: out.unwrap_or_default(),
            checksum_ok: outcome.checksum_ok,
            fragment_mismatches: outcome.fragment_mismatches,
        });
        Ok(())
    }
}

/// 3.2.6.1 T5: a nanosecond field of 1,000,000,000 or more is not
/// refused. The reference prints 1,500,000,000 as `,426258176`, which is
/// the value modulo 2^30; the seconds stand.
#[test]
fn a_rar5_nanosecond_field_is_read_modulo_two_to_the_thirty() {
    let archive = open(arm("rar5-container/time-ns-over/x.rar")).expect("opens");
    let nanos: Vec<u32> = archive
        .members()
        .filter_map(|m| m.mtime)
        .map(|t| t.nanos)
        .filter(|&n| n != 0)
        .collect();
    assert_eq!(nanos, [426_258_176]);
}

/// 3.2.9 S3: the comment is the first `CMT` block met before any file
/// header, less one final zero byte; one after the members is not the
/// comment; one whose checksum fails is `None` and never fails the open.
#[test]
fn the_rar5_comment_is_the_first_cmt_block_before_any_file_header() {
    let comment = |name: &str| {
        open(arm(&format!("rar5-container/{name}/x.rar")))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .comment()
            .map(<[u8]>::to_vec)
    };
    let first = comment("service-cmt-first").expect("a comment");
    assert!(!first.is_empty() && first.last() != Some(&0));
    assert_eq!(comment("service-cmt-last"), None);
    assert_eq!(first, b"the comment\n");
    let two = comment("service-cmt-two").expect("the first of two");
    assert_eq!(two, b"first comment\n", "the first of two is shown");
    let trimmed = comment("service-cmt-zero-end").expect("a comment");
    assert_ne!(trimmed.last(), Some(&0), "a final zero byte is not text");
    assert!(comment("service-cmt-no-crc").is_some());
    assert_eq!(comment("service-cmt-bad-crc"), None);
    assert_eq!(
        comment("service-cmt-lower"),
        None,
        "the name is matched exactly"
    );
}

/// 3.3.3 B4: the same in the older container, whose first block after the
/// signature is the main header (type 0x73).
#[test]
fn the_first_older_container_block_must_be_the_main_header() {
    let err = open(arm("old-container/main-absent/x.rar")).expect_err("no main header");
    assert!(matches!(err.kind(), ErrorKind::Corrupt(_)), "{err}");
}

// ---------------------------------------------------------------------
// 3.1.2 and question 2: finding the signature
// ---------------------------------------------------------------------

/// The last offset at which the reference finds a `Rar!` signature.
const REFERENCE_REACH: usize = 4_194_282;

/// `prefix` zero bytes and then a genuine archive.
fn behind(prefix: usize, archive: &[u8]) -> Vec<u8> {
    let mut file = vec![0u8; prefix];
    file.extend_from_slice(archive);
    file
}

/// Question 2: with the default search a signature that starts at any
/// offset up to 4,194,282 is found, as the reference finds it, in both
/// `Rar!` containers; the archive behind it opens and its members read.
///
/// About 4 MiB a file, one at a time.
#[test]
fn the_default_search_reaches_as_far_as_the_reference() {
    assert!(rarkit::DEFAULT_SFX_SCAN >= REFERENCE_REACH as u64);
    for (path, format) in [
        ("rar5-container/base/x.rar", rarkit::Format::Rar5),
        ("old-container/base/x.rar", rarkit::Format::Rar4Family),
    ] {
        let archive = arm(path);
        let names = good(std::slice::from_ref(&archive));
        assert!(!names.is_empty(), "{path}");
        for prefix in [1_001, (1 << 20) + 8, REFERENCE_REACH] {
            let file = behind(prefix, &archive);
            let found = rarkit::detect(&file, rarkit::DEFAULT_SFX_SCAN)
                .unwrap()
                .unwrap_or_else(|| panic!("{path} behind {prefix} bytes was not found"));
            assert_eq!((found.format, found.start), (format, prefix as u64));
            assert_eq!(good(&[file]), names, "{path} behind {prefix} bytes");
        }
        // A caller may ask for less, and `0` means "at byte 0".
        let near = behind(1_001, &archive);
        assert_eq!(rarkit::detect(&near, 1_000).unwrap(), None);
        assert_eq!(rarkit::detect(&near, 0).unwrap(), None);
    }
}

/// A source that counts what is asked of it.
struct Counted {
    bytes: Vec<u8>,
    reads: std::sync::atomic::AtomicU64,
    read: std::sync::atomic::AtomicU64,
    furthest: std::sync::atomic::AtomicU64,
}

impl RangeSource for Counted {
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }

    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::sync::atomic::Ordering::Relaxed;
        let got = self.bytes.as_slice().read_at(offset, buf)?;
        self.reads.fetch_add(1, Relaxed);
        self.read.fetch_add(got as u64, Relaxed);
        self.furthest.fetch_max(offset + got as u64, Relaxed);
        Ok(got)
    }
}

/// What the wider default costs on a file that holds no signature: the
/// search reads each byte once, in reads of 4 KiB or more, no further
/// than the reach plus one signature and one read, and holds one fixed
/// buffer on the stack whatever the file's size (it allocates nothing).
///
/// 16 MiB of zeros, one thread.
#[test]
fn a_file_with_no_signature_costs_one_pass_over_the_reach() {
    use std::sync::atomic::Ordering::Relaxed;
    let source = Counted {
        bytes: vec![0u8; 16 << 20],
        reads: Default::default(),
        read: Default::default(),
        furthest: Default::default(),
    };
    assert_eq!(
        rarkit::detect(&source, rarkit::DEFAULT_SFX_SCAN).unwrap(),
        None
    );
    let reach = rarkit::DEFAULT_SFX_SCAN;
    let slack = 8 + 2 * 4096;
    assert!(source.furthest.load(Relaxed) <= reach + slack);
    assert!(source.read.load(Relaxed) <= reach + slack);
    assert!(source.reads.load(Relaxed) <= reach / 4096 + 2);
}

/// 3.1.2: the RAR 1.3 signature is four bytes of text, and is a mark only
/// at offset 0 and at offset 1; it is never searched for further in. The
/// reference reads `rar13-sfx-1` and calls the others no archive.
#[test]
fn the_rar13_signature_is_recognised_at_offsets_0_and_1_only() {
    let at = |name: &str| {
        let bytes = arm(&format!("rar5-container/{name}/{}", {
            if name == "rar13-sfx-exe" {
                "x.exe"
            } else {
                "x.rar"
            }
        }));
        rarkit::detect(&bytes, rarkit::DEFAULT_SFX_SCAN).unwrap()
    };
    let rar13 = |start| {
        Some(rarkit::Found {
            format: rarkit::Format::Rar13,
            start,
        })
    };
    assert_eq!(at("rar13-base"), rar13(0));
    assert_eq!(at("rar13-sfx-1"), rar13(1));
    for name in [
        "rar13-sfx-2",
        "rar13-sfx-28",
        "rar13-sfx-1001",
        "rar13-sfx-exe",
    ] {
        assert_eq!(at(name), None, "{name}");
    }
    // `RE~^` further in is passed by, and the RAR 5 archive behind it is
    // the one found; at offset 0 it wins, whatever follows (3.1.3).
    let inside = at("decoy-rar13-inside").expect("the archive behind the decoy");
    assert_eq!((inside.format, inside.start), (rarkit::Format::Rar5, 164));
    assert_eq!(at("decoy-rar13"), rar13(0));

    // One byte ahead of the signature, the archive reads as the reference
    // lists it.
    let names = good(&[arm("rar5-container/rar13-sfx-1/x.rar")]);
    assert_eq!(names, ["A.TXT", "B.TXT"]);
}
