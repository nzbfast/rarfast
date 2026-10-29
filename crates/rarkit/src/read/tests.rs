//! The acceptance test of spec F section 5: the block walk of every vector
//! archive, printed in the format of 5.2 and compared with the committed
//! `vectors-F/expected/` file byte for byte.

use std::path::PathBuf;

fn vectors() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F"
    ))
}

#[cfg(feature = "repo-tests")]
#[test]
fn every_vector_archive_walks_to_its_expected_blocks() {
    let root = vectors();
    let mut names: Vec<String> = std::fs::read_dir(root.join("archives"))
        .expect("vectors-F/archives")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 30, "spec F 5: 30 archives");

    let mut wrong = Vec::new();
    for name in &names {
        let data = std::fs::read(root.join("archives").join(name)).unwrap();
        let expected = std::fs::read_to_string(root.join("expected").join(format!("{name}.txt")))
            .unwrap_or_else(|e| panic!("expected walk for {name}: {e}"));
        let got = super::dump::walk(name, &data);
        if got != expected {
            wrong.push(format!(
                "--- {name} expected\n{expected}--- {name} got\n{got}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Spec F 3.2.8: both locator offsets are measured from the first byte
/// AFTER the signature, and `f09_rr.rar` states 11,757 and 11,822 while
/// the QO and RR service headers sit at file offsets 11,765 and 11,830,
/// which is 8 more. A locator is a HINT: it is usable only once the block
/// at it parses, its checksum passes and its name matches.
#[cfg(feature = "repo-tests")]
#[test]
fn the_locator_offsets_land_on_their_service_headers() {
    use crate::read::block::{Fields, ServiceName};
    use crate::read::reader::{BlockReader, ReadCtx};
    use crate::read::{Format, ReadOptions};

    let data = std::fs::read(vectors().join("archives/f09_rr.rar")).unwrap();
    let mut ctx = ReadCtx::new(ReadOptions::default());
    let mut reader = BlockReader::new(&data, &mut ctx, Format::Rar5, 0);

    let mut locator = None;
    let mut services = Vec::new();
    while let Some(block) = reader.next().unwrap() {
        match &block.fields {
            Fields::Main(main) => locator = main.locator,
            Fields::File(file) => {
                if let Some(name) = file.service {
                    services.push((block.header.start, name));
                }
            }
            _ => {}
        }
    }
    let locator = locator.expect("f09_rr.rar carries a locator");
    assert_eq!(locator.raw_quick_open, Some(11_757));
    assert_eq!(locator.raw_recovery, Some(11_822));
    assert_eq!(locator.quick_open, Some(11_765));
    assert_eq!(locator.recovery, Some(11_830));
    assert!(services.contains(&(11_765, ServiceName::QuickOpen)));
    assert!(services.contains(&(11_830, ServiceName::Recovery)));
}

/// Spec F 3.2.9.1: each quick open entry's stored CRC32 covers its size
/// field and everything after it, and its "distance back", subtracted from
/// the QO header's own offset, lands exactly on a file header.
#[cfg(feature = "repo-tests")]
#[test]
fn every_quick_open_entry_checks_out_and_points_at_a_real_header() {
    use crate::read::block::{Fields, ServiceName};
    use crate::read::cursor::read_exact_at;
    use crate::read::reader::{BlockReader, ReadCtx};
    use crate::read::{rar5, Format, ReadOptions};

    let data = std::fs::read(vectors().join("archives/f10_qo.rar")).unwrap();
    let mut ctx = ReadCtx::new(ReadOptions::default());
    let mut reader = BlockReader::new(&data, &mut ctx, Format::Rar5, 0);

    let mut headers = Vec::new();
    let mut quick_open = None;
    while let Some(block) = reader.next().unwrap() {
        if let Fields::File(file) = &block.fields {
            match file.service {
                Some(ServiceName::QuickOpen) => {
                    quick_open = Some((block.header.start, block.data.clone()));
                }
                None => headers.push(block.header.start),
                _ => {}
            }
        }
    }
    let (qo_at, data_range) = quick_open.expect("f10_qo.rar carries a QO record");
    let mut record = vec![0u8; (data_range.end - data_range.start) as usize];
    read_exact_at(&data, data_range.start, &mut record).unwrap();

    let mut landed = Vec::new();
    rar5::walk_quick_open(&record, |entry| {
        assert!(entry.checksum_ok, "a QO entry's own CRC32 must match");
        assert!(entry.cached_size > 0);
        landed.push(qo_at - entry.distance_back);
    })
    .unwrap();
    assert_eq!(landed.len(), headers.len(), "one entry per file header");
    for at in landed {
        assert!(
            headers.contains(&at),
            "a QO entry pointed at {at}, which is not a file header"
        );
    }
}

/// A plain stored RAR 1.5 to 4.x archive of `count` small members, built
/// from the header layout of spec F 3.3 so the allocation test below has
/// an archive with a lot of members and no dependency on a writer.
fn many_members(count: usize) -> Vec<u8> {
    fn stamp(mut block: Vec<u8>) -> Vec<u8> {
        let size = block.len() as u16;
        block[5..7].copy_from_slice(&size.to_le_bytes());
        let crc = crate::checksum::crc32(&block[2..]) as u16;
        block[0..2].copy_from_slice(&crc.to_le_bytes());
        block
    }
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    out.extend_from_slice(&stamp(vec![0, 0, 0x73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    for i in 0..count {
        let name = format!("member{i:06}.txt");
        let body = format!("body {i}\n").into_bytes();
        let mut h = vec![0, 0, 0x74];
        h.extend_from_slice(&0x8000u16.to_le_bytes());
        h.extend_from_slice(&[0; 2]);
        h.extend_from_slice(&(body.len() as u32).to_le_bytes());
        h.extend_from_slice(&(body.len() as u32).to_le_bytes());
        h.push(2); // host OS
        h.extend_from_slice(&crate::checksum::crc32(&body).to_le_bytes());
        h.extend_from_slice(&0x5D32_86A0u32.to_le_bytes());
        h.push(20); // unpack version
        h.push(0x30); // stored
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0x20u32.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&stamp(h));
        out.extend_from_slice(&body);
    }
    out.extend_from_slice(&stamp(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0]));
    out
}

/// Spec F 7.3.2 and API promise 2.4: listing an archive of N members makes
/// O(log N) allocations, because the name arena and the member table both
/// grow geometrically and nothing else allocates per header, per member or
/// per name.
///
/// This reuses the crate's ONE counting global allocator, which spec J's
/// tests install: a binary may have only one.
#[test]
fn listing_allocates_o_log_n_for_n_members() {
    use crate::rar3_filters::tests::counting;
    use crate::read::{Archive, ReadOptions};
    use std::sync::Arc;

    let mut counts = Vec::new();
    for count in [1_000usize, 4_000, 16_000] {
        let data = many_members(count);
        let src: Arc<dyn crate::source::RangeSource> = Arc::new(data);
        let before = counting::count();
        let archive = Archive::open(src, &ReadOptions::default()).unwrap();
        let allocations = counting::count() - before;
        assert_eq!(archive.members().len(), count);
        counts.push((count, allocations));
    }
    eprintln!("    allocations per listing: {counts:?}");

    // Sixteen times the members must not cost sixteen times the
    // allocations: geometric growth adds four doublings, not 15,000
    // allocations.
    let (_, small) = counts[0];
    let (_, large) = counts[2];
    assert!(
        large <= small + 16,
        "allocations per listing: {counts:?}; 16x the members cost {} more",
        large - small
    );
    for (count, allocations) in &counts {
        assert!(
            *allocations < 128,
            "listing {count} members made {allocations} allocations"
        );
    }
}

/// Spec F 3.1: the four signatures, a signature at any byte offset, and
/// the scan window. The RAR 4 signature is a PREFIX of the RAR 5 one, so a
/// reader that tests the shorter form first reads every RAR 5 archive as a
/// corrupt RAR 4 archive.
#[test]
fn detection_tests_the_longer_signature_first_and_honours_the_window() {
    use crate::read::{detect, Format};

    let rar5 = b"Rar!\x1a\x07\x01\x00".to_vec();
    let rar4 = b"Rar!\x1a\x07\x00".to_vec();
    let rar13 = b"RE~^".to_vec();

    for (bytes, want) in [
        (&rar5, Format::Rar5),
        (&rar4, Format::Rar4Family),
        (&rar13, Format::Rar13),
    ] {
        let found = detect(&bytes.as_slice(), 0).unwrap().unwrap();
        assert_eq!(found.format, want);
        assert_eq!(found.start, 0);
    }

    // A signature at an ODD offset, behind a stub, is found.
    for stub in [1usize, 7, 511, 4096, 100_003] {
        let mut data = vec![0x90u8; stub];
        data.extend_from_slice(&rar5);
        let found = detect(&data.as_slice(), data.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(found.start, stub as u64, "stub of {stub} bytes");
        assert_eq!(found.format, Format::Rar5);
    }

    // `sfx_scan == 0` means the archive starts at byte 0 and no search is
    // made, so a signature one byte in is not found.
    let mut late = vec![0x90u8];
    late.extend_from_slice(&rar5);
    assert!(detect(&late.as_slice(), 0).unwrap().is_none());
    assert!(detect(&late.as_slice(), 1).unwrap().is_some());

    // The window is a bound: a signature past it is not found, and that is
    // `Ok(None)`, not an error.
    let mut far = vec![0x90u8; 5000];
    far.extend_from_slice(&rar5);
    assert!(detect(&far.as_slice(), 4999).unwrap().is_none());
    assert!(detect(&far.as_slice(), 5000).unwrap().is_some());

    // Nothing at all, and a source too short to hold any signature.
    assert!(detect(&[0x90u8; 4096].as_slice(), 4096).unwrap().is_none());
    assert!(detect(&b"Rar".as_slice(), 64).unwrap().is_none());
    assert!(detect(&[].as_slice(), 64).unwrap().is_none());
}

/// Spec F 3.1.3: the FIRST signature wins, even when the archive behind it
/// is junk. A reader that rescans on a parse failure finds a different
/// archive from the reference in exactly the cases where a producer is
/// trying to make two readers disagree.
#[cfg(feature = "repo-tests")]
#[test]
fn the_first_signature_wins_even_when_it_is_a_decoy() {
    use crate::read::{detect, Archive, Format, ReadOptions};
    use crate::ErrorKind;
    use std::sync::Arc;

    let real = std::fs::read(vectors().join("archives/f01_stored.rar")).unwrap();
    let mut data = vec![0u8; 100];
    data.extend_from_slice(b"Rar!\x1a\x07\x01\x00"); // the decoy
    data.extend_from_slice(&[0xFF; 64]); // junk behind it
    data.extend_from_slice(&real);

    let found = detect(&data.as_slice(), data.len() as u64)
        .unwrap()
        .unwrap();
    assert_eq!(found.start, 100, "the decoy, not the archive behind it");
    assert_eq!(found.format, Format::Rar5);

    let opts = ReadOptions {
        sfx_scan: data.len() as u64,
        ..ReadOptions::default()
    };
    let err = Archive::open(Arc::new(data), &opts).unwrap_err();
    assert!(
        !matches!(err.kind(), ErrorKind::NotAnArchive),
        "the decoy was found; opening it fails on ITS headers: {err}"
    );
}

/// Spec F 7.3.2, 7.3.5 and 7.3.9, and API promise 2.4: EXTRACTING an
/// archive of N members allocates no more per member than listing it does.
///
/// The listing test above covers `Archive::open`; this one covers the
/// walk, which is a different path (`extract` parses headers as it goes and
/// never calls `Archive::open`) and the one the 20,000-member test leg
/// runs. It is counted per member rather than per archive, which is the
/// only way a cost of one allocation each shows up at all: at 20,000
/// members it is 0.3% of a leg's wall time and invisible beside the copy.
#[test]
fn extraction_allocates_no_more_per_member_than_listing() {
    use crate::rar3_filters::tests::counting;
    use crate::read::{extract, Disposition, MemberInfo, MemberOutcome, ReadOptions, Sink};
    use std::sync::Arc;

    /// A sink that verifies and keeps nothing, so every allocation counted
    /// is the engine's.
    struct Verify;

    impl Sink for Verify {
        type Out = Vec<u8>;

        fn open(&mut self, _member: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Verify)
        }

        fn close(
            &mut self,
            _member: &MemberInfo<'_>,
            _out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> crate::Result<()> {
            assert_eq!(outcome.checksum_ok, Some(true));
            Ok(())
        }
    }

    // ORDER-INDEPENDENCE (traced 22 Sep 2026): the very
    // FIRST `extract` call any test in this binary makes pays a one-time
    // warm-up of about 170 allocations, on top of whatever a member costs.
    // Measured directly: two back-to-back single-member calls on the same
    // thread cost 177 then 7; the same probe run on a FRESH thread after
    // the first call still cost only 7, so the cost is not per-thread, it
    // is paid once per PROCESS regardless of which thread touches it
    // first. That rules out a thread-local cache and points at some
    // lazily-initialised process-global state on the extraction path
    // (a `OnceLock`-style table, or a one-time cost inside a dependency
    // this crate calls into, such as a cipher backend's CPU-feature
    // detection reached through `ReadCtx::new`'s key cache) rather than
    // anything that scales with member count. No such site was pinned
    // down inside `crates/rarkit` itself; if it is worth removing from the
    // read path, that is not done yet. Until then, one
    // extraction is spent here and its count discarded, so whichever test
    // in the binary happens to run first no longer changes this test's
    // verdict: `cargo test read::` (full module) and a single filtered
    // `--exact` run must agree, and did not before this call was added.
    let warm_up = many_members(1);
    let warm_up_sources = vec![Arc::new(warm_up) as Arc<dyn crate::source::RangeSource>];
    extract(
        warm_up_sources,
        &ReadOptions::default(),
        &mut Verify,
        &mut (),
    )
    .unwrap();

    let mut counts = Vec::new();
    for count in [1_000usize, 4_000, 16_000] {
        let data = many_members(count);
        let sources = vec![Arc::new(data) as Arc<dyn crate::source::RangeSource>];
        let before = counting::count();
        let report = extract(sources, &ReadOptions::default(), &mut Verify, &mut ()).unwrap();
        let allocations = counting::count() - before;
        assert_eq!(report.members, count as u64);
        assert_eq!(report.checksum_failures, 0);
        counts.push((count, allocations));
    }
    eprintln!("    allocations per extraction: {counts:?}");

    // NON-VACUITY: the counts above must actually have been taken (not all
    // zero, which a broken counter or a short-circuited walk could give
    // for free) and the three sizes must actually differ, or the slope
    // check below proves nothing.
    assert!(
        counts.iter().any(|&(_, a)| a > 0),
        "no allocation was counted at all: {counts:?}"
    );
    assert_eq!(
        counts.iter().map(|&(n, _)| n).collect::<Vec<_>>(),
        vec![1_000, 4_000, 16_000],
        "the three sizes must differ for a slope to mean anything"
    );

    let (small_n, small) = counts[0];
    let (large_n, large) = counts[2];
    // Sixteen times the members must not cost sixteen times the
    // allocations. One allocation per member would put 15,000 between
    // these two figures.
    assert!(
        large <= small + 24,
        "allocations per extraction: {counts:?}; {}x the members cost {} more",
        large_n / small_n,
        large - small
    );
    for (count, allocations) in &counts {
        assert!(
            *allocations < 160,
            "extracting {count} members made {allocations} allocations"
        );
    }
}

/// The read path holds ONE BLAKE2sp for a whole operation and starts it
/// again per member, because a hasher owns a heap stage and building one
/// per member is an allocation per member (API promise 2.4).
///
/// Two things have to be true for that to be safe, and neither is visible
/// in any output: a reset hasher must give what a fresh one gives, and
/// finishing in place must give what finishing by value gives.
#[test]
fn a_reset_hasher_gives_what_a_fresh_one_gives() {
    use crate::checksum::blake2sp::Blake2sp;

    // Sizes either side of the stage, so the reset is exercised with and
    // without buffered bytes behind it.
    for len in [0usize, 1, 64, 1000, 200 << 10, 600 << 10] {
        let first: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let second: Vec<u8> = (0..len).map(|i| (i * 17 + 3) as u8).collect();

        let mut fresh = Blake2sp::new();
        fresh.update(&second);
        let want = fresh.finalize();

        let mut reused = Blake2sp::new();
        reused.update(&first);
        let _ = reused.finalize_reset();
        reused.update(&second);
        assert_eq!(
            reused.finalize_reset(),
            want,
            "{len}: a hasher used again does not give a fresh hasher's digest"
        );

        let mut once = Blake2sp::new();
        once.update(&second);
        assert_eq!(
            once.finalize_reset(),
            want,
            "{len}: finishing in place disagrees with finishing by value"
        );

        let mut cleared = Blake2sp::new();
        cleared.update(&first);
        cleared.reset();
        cleared.update(&second);
        assert_eq!(
            cleared.finalize(),
            want,
            "{len}: an explicitly reset hasher does not give a fresh one's digest"
        );
    }
}

/// **The BLAKE2sp leaf team is REACHABLE through the read path.** Spec L
/// gates it on "the caller's `max_workers`" and API 8.2's table names it a
/// stage that `max_workers` bounds; until this was wired, every shipped
/// read and write path built its hasher at ONE worker, so the parallel
/// form existed, was tested, was correct, and could not be reached by any
/// caller at any policy.
///
/// Read from where the allowance lands rather than from a wall clock: the
/// hasher records the allowance it was built with and this asserts the
/// policy's figure arrived. What the hasher then DOES with it is the
/// hasher's own gate - a team engages only on a batch worth one - and
/// `checksum::blake2sp`'s tests hold that.
#[test]
fn the_read_path_gives_its_hasher_the_policy_worker_ceiling() {
    use crate::checksum::blake2sp;
    use crate::read::{extract, Disposition, MemberInfo, MemberOutcome, ReadOptions, Sink};
    use std::sync::Arc;

    struct Verify;

    impl Sink for Verify {
        type Out = Vec<u8>;

        fn open(&mut self, _member: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Verify)
        }

        fn close(
            &mut self,
            _member: &MemberInfo<'_>,
            _out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> crate::Result<()> {
            assert_eq!(outcome.checksum_ok, Some(true));
            Ok(())
        }
    }

    // A RAR 5 archive carrying a BLAKE2sp member hash, so the read path
    // builds a hasher for it at all. Written HERE by this crate's own
    // writer rather than read from `specs/vectors-F`, because `make ci`'s
    // `mirror-check` runs `--lib` over a copy of the crate with the
    // repository's vectors excluded: a test that reads one is gated
    // behind `repo-tests` and would not run there, and this property is
    // worth holding in every build.
    let payload = vec![0x5Au8; 3 << 20];
    let data = {
        use crate::write::{ChecksumKind, MemberSpec, Payload, WriteOptions, Writer};
        let mut writer = Writer::new(WriteOptions {
            checksum: ChecksumKind::Blake2sp,
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"m.bin",
                payload: Payload::Bytes(&payload),
                mtime: None,
                attributes: 0,
                host_os: crate::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish");
        out
    };
    for workers in [1usize, 2, 8] {
        let options = ReadOptions {
            memory: crate::MemoryPolicy {
                max_workers: workers,
                ..Default::default()
            },
            ..Default::default()
        };
        blake2sp::forget_allowance();
        let sources = vec![Arc::new(data.clone()) as Arc<dyn crate::source::RangeSource>];
        let report = extract(sources, &options, &mut Verify, &mut ()).unwrap();
        assert_eq!(report.checksum_failures, 0, "workers {workers}");
        let allowance = blake2sp::last_allowance();
        assert_eq!(
            allowance, workers,
            "a read at max_workers {workers} built its BLAKE2sp at {allowance}"
        );
    }
}

/// One RAR 5 file header built from its fields, so a test can put the
/// modification time in the header's own field (spec F 3.2.6 flag 0x0002),
/// in an extra TIME record (3.2.6.1), in BOTH, or in neither. Every value
/// here is small enough for a one-byte vint, which is asserted rather than
/// assumed.
fn rar5_file_header(mtime_field: Option<u32>, time_record: Option<&[u8]>) -> Vec<u8> {
    fn vint(out: &mut Vec<u8>, v: u64) {
        assert!(v < 0x80, "this builder writes one-byte vints only");
        out.push(v as u8);
    }
    let name = b"hello.txt";
    let mut extra = Vec::new();
    if let Some(body) = time_record {
        vint(&mut extra, 1 + body.len() as u64);
        vint(&mut extra, 3); // the TIME record's type
        extra.extend_from_slice(body);
    }

    let mut fields = Vec::new();
    vint(&mut fields, 2); // header type: FILE
    vint(
        &mut fields,
        u64::from(!extra.is_empty()) | 2, // EXTRA when there is one, DATA always
    );
    if !extra.is_empty() {
        vint(&mut fields, extra.len() as u64);
    }
    vint(&mut fields, 16); // data area size
                           // File flags: CRC32 always, and 0x0002 only when the header's own
                           // modification time field is there (spec F 3.2.6).
    vint(&mut fields, if mtime_field.is_some() { 0x06 } else { 0x04 });
    vint(&mut fields, 16); // unpacked size
    vint(&mut fields, 0); // attributes
    if let Some(raw) = mtime_field {
        fields.extend_from_slice(&raw.to_le_bytes());
    }
    fields.extend_from_slice(&0xCDFD_0CC2u32.to_le_bytes()); // data CRC32
    vint(&mut fields, 0); // compression info: version 0, stored, 128 KiB
    vint(&mut fields, 1); // host OS: Unix
    vint(&mut fields, name.len() as u64);
    fields.extend_from_slice(name);
    fields.extend_from_slice(&extra);

    let mut head = vec![0u8; 4]; // the CRC32, which nothing here checks
    vint(&mut head, fields.len() as u64);
    head.extend_from_slice(&fields);
    head
}

/// The modification time a header reports, however it carries it.
fn rar5_header_times(head: &[u8]) -> (Option<crate::Timestamp>, Option<crate::Timestamp>) {
    let common = super::rar5::parse_common(head).expect("a built header parses");
    let parsed = super::rar5::parse_file(head, &common, 0).expect("a built header parses");
    (parsed.fields.mtime, parsed.fields.header_mtime)
}

/// Spec F 3.2.6.1: the record WINS over the header field where both are
/// present and disagree, which is what reference unrar 7.23 prints. The
/// header field is still reported as what it is, so the block walk can
/// print the bytes rather than the resolution.
#[test]
fn spec_f_3_2_6_1_the_time_record_wins_over_the_header_field() {
    let record = [0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07];
    let (mtime, field) = rar5_header_times(&rar5_file_header(Some(1_000_000_000), Some(&record)));
    assert_eq!(mtime.unwrap().unix_seconds, 1_789_704_000);
    assert_eq!(mtime.unwrap().nanos, 123_456_789);
    assert_eq!(field.unwrap().unix_seconds, 1_000_000_000);
}

/// Spec F 3.2.6.1: a header with the record and NO field - which is what
/// `rar` 7.23 writes from a file with a sub-second mtime, and what
/// `f17_htime_ns.rar` pins - reports the record's time. This is the defect
/// the record caused: a reader that knows only the field shows no date.
#[test]
fn spec_f_3_2_6_1_a_header_with_only_the_record_reports_its_time() {
    let record = [0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07];
    let (mtime, field) = rar5_header_times(&rar5_file_header(None, Some(&record)));
    assert_eq!(mtime.unwrap().unix_seconds, 1_789_704_000);
    assert_eq!(field, None);
}

/// Spec F 3.2.6.1: a member with NO modification time at all - neither the
/// field nor a record carrying one - reports it as ABSENT. Not the epoch,
/// not a zero, not a blank: the reference prints `????-??-?? ??:??` for
/// one of these, and a caller can only do that if the engine can say so.
#[test]
fn spec_f_3_2_6_1_a_member_with_no_modification_time_reports_none() {
    // Nothing at all.
    assert_eq!(rar5_header_times(&rar5_file_header(None, None)).0, None);
    // A record carrying a creation time and no modification time, which is
    // what `rar -tsm- -tsc` writes.
    let ctime_only = [0x15, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07];
    assert_eq!(
        rar5_header_times(&rar5_file_header(None, Some(&ctime_only))).0,
        None
    );
}

/// Spec F 3.2.6.1: a record too short for the times its flags declare, an
/// unknown flag bit and trailing bytes are all accepted, and the member
/// keeps whatever the record really carried. None of the three may cost
/// the member its header.
#[test]
fn spec_f_3_2_6_1_a_damaged_record_never_costs_the_member_its_header() {
    for (what, body) in [
        ("short", &[0x1f, 0x40, 0xb7, 0xac, 0x6a][..]),
        (
            "unknown flag",
            &[0x33, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07][..],
        ),
        (
            "trailing bytes",
            &[
                0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07, 0xff, 0xff,
            ][..],
        ),
        ("no flags word", &[][..]),
        ("flags only", &[0x1f][..]),
    ] {
        let head = rar5_file_header(None, Some(body));
        let common = super::rar5::parse_common(&head).expect("{what}: the header parses");
        let parsed = super::rar5::parse_file(&head, &common, 0)
            .unwrap_or_else(|e| panic!("{what}: a header with that record failed with {e:?}"));
        let want = match what {
            "no flags word" | "flags only" => None,
            _ => Some(1_789_704_000),
        };
        assert_eq!(parsed.fields.mtime.map(|t| t.unix_seconds), want, "{what}");
    }
}

/// Spec F 5.1: `f17` to `f19` carry their modification times in an extra
/// TIME record with the header field absent, and every one of them lists
/// with the time the record holds. The walk test above compares the whole
/// block dump; this one asserts what a CALLER sees through the API, which
/// is the half that was showing no date at all.
#[cfg(feature = "repo-tests")]
#[test]
fn the_time_record_vectors_list_with_their_times() {
    use crate::read::{Archive, ReadOptions};
    use std::sync::Arc;

    for (name, seconds, nanos) in [
        ("f17_htime_ns.rar", 1_789_704_000i64, 123_456_789u32),
        ("f18_htime_ma.rar", 1_789_704_000, 123_456_789),
        // The windows form: FILETIME 132224078450000001 is
        // 2020-01-02 03:04:05 plus one 100 ns tick.
        ("f19_htime_win.rar", 1_577_934_245, 100),
    ] {
        let data = std::fs::read(vectors().join("archives").join(name)).unwrap();
        let src: Arc<dyn crate::source::RangeSource> = Arc::new(data);
        let archive = Archive::open(src, &ReadOptions::default()).unwrap();
        let members: Vec<_> = archive.members().collect();
        assert_eq!(members.len(), 1, "{name}");
        let mtime = members[0]
            .mtime
            .unwrap_or_else(|| panic!("{name}: no modification time at all"));
        assert_eq!(
            (mtime.unix_seconds, mtime.nanos),
            (seconds, nanos),
            "{name}"
        );
    }
}

/// One RAR 5 archive of one member whose compression information is
/// `comp`, with every header's CRC32 right, so the walk takes it.
fn rar5_one_member(comp: u64, unpacked: &[u8], packed: &[u8]) -> Vec<u8> {
    rar5_one_entry(0x04, comp, unpacked, packed)
}

/// [`rar5_one_member`] with these file flags (0x0001 a directory, 0x0004
/// the CRC32 present).
fn rar5_one_entry(file_flags: u64, comp: u64, unpacked: &[u8], packed: &[u8]) -> Vec<u8> {
    fn vint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    fn block(fields: &[u8]) -> Vec<u8> {
        let mut sized = Vec::new();
        vint(&mut sized, fields.len() as u64);
        sized.extend_from_slice(fields);
        let mut out = crate::checksum::crc32(&sized).to_le_bytes().to_vec();
        out.extend_from_slice(&sized);
        out
    }
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    out.extend_from_slice(&block(&[1, 0, 0])); // main header, not solid
    let mut file = Vec::new();
    vint(&mut file, 2); // FILE
    vint(&mut file, 2); // a data area follows
    vint(&mut file, packed.len() as u64);
    vint(&mut file, file_flags);
    vint(&mut file, unpacked.len() as u64);
    vint(&mut file, 0); // attributes
    if file_flags & 0x04 != 0 {
        file.extend_from_slice(&crate::checksum::crc32(unpacked).to_le_bytes());
    }
    vint(&mut file, comp);
    vint(&mut file, 1); // host OS: Unix
    vint(&mut file, 5);
    file.extend_from_slice(b"m.bin");
    out.extend_from_slice(&block(&file));
    out.extend_from_slice(packed);
    out.extend_from_slice(&block(&[5, 0, 0])); // end of archive
    out
}

/// Each member's bytes, dictionary and algorithm version.
type Kept = Vec<(Vec<u8>, Option<u64>, u32)>;

/// Each member's bytes, dictionary and algorithm version, and the error
/// the extraction ended with.
fn rar5_extract_one(archive: Vec<u8>) -> (Kept, Option<crate::Error>) {
    rar5_extract_with(archive, &crate::ReadOptions::default())
}

/// [`rar5_extract_one`] under `options`.
fn rar5_extract_with(
    archive: Vec<u8>,
    options: &crate::ReadOptions,
) -> (Kept, Option<crate::Error>) {
    use crate::{Disposition, MemberInfo, MemberOutcome, Sink};
    use std::sync::Arc;

    #[derive(Default)]
    struct Keep(Kept);
    impl Sink for Keep {
        type Out = Vec<u8>;
        fn open(&mut self, _: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Write(Vec::new()))
        }
        fn close(
            &mut self,
            member: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            _: &MemberOutcome,
        ) -> crate::Result<()> {
            self.0.push((
                out.unwrap_or_default(),
                member.dictionary,
                member.algorithm_version,
            ));
            Ok(())
        }
    }
    let source: Arc<dyn crate::source::RangeSource> = Arc::new(archive);
    let mut sink = Keep::default();
    let ended = crate::extract(vec![source], options, &mut sink, &mut ());
    (sink.0, ended.err())
}

/// SPEC-H2 3.3, through the READER: compression version 1 (RAR 7,
/// "v70") is read, not refused, and a compressed member of it decodes its
/// 446 lengths (decided 27 Sep 2026). Version
/// 2 is still unknown and still refused (spec F question 9).
#[test]
fn a_compressed_version_one_member_extracts() {
    use crate::rar5_lz::vectors::BlockBuilder;

    let mut block = BlockBuilder::default();
    block.distance = vec![7; 80];
    block.literals(b"abcdefgh");
    // Distance 4 is slot 3 with no extra bits; length slot 1 is three.
    block.fresh(1, 0, 3, 0);
    block.literals(b"!");
    let packed = block.finish(true, true);
    let want = b"abcdefghefg!";

    // Version 1, method 3, dictionary field 0 (128 KiB).
    let (members, ended) = rar5_extract_one(rar5_one_member(1 | 3 << 7, want, &packed));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, want);
    assert_eq!(members[0].1, Some(128 * 1024));
    assert_eq!(members[0].2, 1);

    let (_, ended) = rar5_extract_one(rar5_one_member(2 | 3 << 7, want, &packed));
    assert!(
        matches!(
            ended.as_ref().map(crate::Error::kind),
            Some(crate::ErrorKind::Unsupported(crate::Unsupported::Version(
                2
            )))
        ),
        "{ended:?}"
    );
}

/// Spec F 5.3's rows for the RAR 5 compression information (3.2.6.3): the
/// algorithm and the dictionary each field names, or the version it is
/// refused as.
#[test]
fn spec_f_5_3_the_compression_information_rows() {
    use super::rar5::dictionary_of;
    const G: u64 = 1 << 30;
    const M: u64 = 1 << 20;
    for (comp, algorithm, dictionary) in [
        (0x3c80u64, 0u32, 4 * G),
        (0x7c00, 0, 4 * G),
        (0x4000, 0, 128 * 1024),
        (0x43c81, 1, 5 * G),
        (0x4bc81, 1, 5_248 * M),
        (0xbc81, 1, 4_224 * M),
        (0x4081, 1, 8 * G),
        (0x3c081, 1, 9_984 * M),
        (0x4c81, 1, 64 * G),
        (0xfc881, 1, 63 * G),
        (0x8001, 1, 135_168),
        (0x3c81, 1, 4 * G),
        (0x143c81, 0, 5 * G),
        (0x8043c81, 1, 5 * G),
    ] {
        let got = dictionary_of(comp).unwrap_or_else(|e| panic!("{comp:#x}: {e}"));
        assert_eq!(got, (algorithm, dictionary), "{comp:#x}");
    }
    assert_eq!(5_248 * M, 5_502_926_848);
    assert_eq!(4_224 * M, 4_429_185_024);
    for (comp, version) in [(0xcc81u64, 1u32), (0x5001, 1), (0x3c82, 2)] {
        let refused = dictionary_of(comp).expect_err("refused");
        assert!(
            matches!(
                refused.kind(),
                crate::ErrorKind::Unsupported(crate::Unsupported::Version(v)) if *v == version
            ),
            "{comp:#x}: {refused:?}"
        );
    }
}

/// Spec F 3.2.6.3 through the READER. A stored version 1 member at 5 GiB
/// extracts and lists its dictionary; a compressed one outside a solid
/// stream NEEDS only its unpacked size (SPEC-API 8.1, the
/// member-sized window), so it decodes under the default
/// policy and under one that allows the whole dictionary alike; a version
/// 1 field above 64 GiB is `Unsupported(Version(1))` whatever the policy. The fields are the ones rar 7.23 wrote for `-md5g`
/// (`0x43c01` stored, `0x43c81` compressed).
#[test]
fn a_version_one_dictionary_sizes_the_member() {
    use crate::rar5_lz::vectors::BlockBuilder;
    let (members, ended) = rar5_extract_one(rar5_one_member(0x43c01, b"four", b"four"));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, b"four");
    assert_eq!(members[0].1, Some(5 << 30));
    assert_eq!(members[0].2, 1);

    let mut block = BlockBuilder::default();
    block.distance = vec![7; 80];
    block.literals(b"four");
    let packed = block.finish(true, true);
    let archive = rar5_one_member(0x43c81, b"four", &packed);
    // Four bytes of output need four bytes of window, not 5 GiB: the
    // default policy decodes it. Before the
    // member-sized window it was refused as `LimitExceeded` for a
    // dictionary it could not use.
    let (members, ended) = rar5_extract_one(archive.clone());
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members[0].0, b"four");
    assert_eq!(members[0].1, Some(5 << 30));
    let roomy = crate::ReadOptions::default().with_memory(crate::MemoryPolicy {
        max_window: 64 << 30,
        ..crate::MemoryPolicy::default()
    });
    let (members, ended) = rar5_extract_with(archive, &roomy);
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members[0].0, b"four");
    assert_eq!(members[0].1, Some(5 << 30));

    let (_, ended) = rar5_extract_with(rar5_one_member(0xcc81, b"four", &packed), &roomy);
    assert!(
        matches!(
            ended.as_ref().map(crate::Error::kind),
            Some(crate::ErrorKind::Unsupported(crate::Unsupported::Version(
                1
            )))
        ),
        "{ended:?}"
    );
}

/// Spec F 3.2.6.3 consequences 5 and 6, at small dictionaries so the test
/// allocates nothing large: the VERSION chooses the algorithm, and bit 20
/// of a version 1 field chooses version 0's. Version 0 data under a
/// version 1 field with bit 20 (`0x100001`, 128 KiB) decodes and lists as
/// algorithm 0; version 1 data under a version 1 field with a fraction
/// (`0x8001`, 132 KiB) decodes; each under the other's field does not.
#[test]
fn the_version_and_bit_twenty_choose_the_algorithm() {
    use crate::rar5_lz::vectors::BlockBuilder;
    let text = b"algorithm";
    let mut v0 = BlockBuilder::default();
    v0.literals(text);
    let v0 = v0.finish(true, true);
    let mut v1 = BlockBuilder::default();
    v1.distance = vec![7; 80];
    v1.literals(text);
    let v1 = v1.finish(true, true);
    let method = 3 << 7;

    let (members, ended) = rar5_extract_one(rar5_one_member(0x10_0001 | method, text, &v0));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members[0].0, text);
    assert_eq!(members[0].2, 0);
    let (members, ended) = rar5_extract_one(rar5_one_member(0x8001 | method, text, &v1));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members[0].0, text);
    assert_eq!(members[0].1, Some(135_168));
    assert_eq!(members[0].2, 1);

    for (comp, packed) in [(0x10_0001 | method, &v1), (0x8001 | method, &v0)] {
        let (members, ended) = rar5_extract_one(rar5_one_member(comp, text, packed));
        assert!(
            ended.is_some() || members.first().is_none_or(|m| m.0 != text),
            "{comp:#x}: the other algorithm's data decoded"
        );
    }
}

/// Version 0 reads bits 10 to 13 of the dictionary field and IGNORES any
/// above them (spec F 3.2.6.3, consequences 1 and 3). Bit 14 set on a
/// version 0 member with a 128 KiB field still decodes in 128 KiB.
#[test]
fn a_version_zero_member_ignores_dictionary_bits_past_thirteen() {
    use crate::rar5_lz::vectors::BlockBuilder;
    let mut block = BlockBuilder::default();
    block.literals(b"zero");
    let packed = block.finish(true, true);
    let (members, ended) = rar5_extract_one(rar5_one_member(3 << 7 | 1 << 14, b"zero", &packed));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, b"zero");
    assert_eq!(members[0].1, Some(128 * 1024));
    assert_eq!(members[0].2, 0);
}

/// An unknown compression version matters only where a codec runs
/// (decided 27 Sep 2026): a DIRECTORY entry
/// declaring version 3 (found by fuzzing) and a STORED member
/// declaring version 2, or a version 1 field above 64 GiB, open with the
/// version ignored and no dictionary named, as reference unrar opens them;
/// a COMPRESSED member declaring version 2 is still refused.
#[test]
fn an_unknown_version_is_refused_only_where_a_codec_runs() {
    let (members, ended) = rar5_extract_one(rar5_one_entry(0x01, 3, b"", b""));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].1, None);

    for comp in [2u64, 0x3f, 0xcc01] {
        let (members, ended) = rar5_extract_one(rar5_one_member(comp, b"kept", b"kept"));
        assert!(ended.is_none(), "{comp:#x}: {ended:?}");
        assert_eq!(members.len(), 1, "{comp:#x}");
        assert_eq!(members[0].0, b"kept", "{comp:#x}");
        assert_eq!(members[0].1, None, "{comp:#x}");
    }

    let (members, ended) = rar5_extract_one(rar5_one_member(2 | 3 << 7, b"kept", b"kept"));
    assert!(
        matches!(
            ended.as_ref().map(crate::Error::kind),
            Some(crate::ErrorKind::Unsupported(crate::Unsupported::Version(
                2
            )))
        ),
        "{ended:?}"
    );
    assert!(members.iter().all(|m| m.0.is_empty()));
}

/// A COMPRESSED member of an unknown version refuses THAT member only
/// (spec F 3.2.6, decided 28 Sep 2026):
/// its header is read, the members around it extract, and the walk ends
/// with its `Unsupported(Version(v))`. Until then the header walk refused
/// it, and with it the whole archive. unrar 7.23 on a `-m3 -qo-` archive
/// with its second member rewritten to version 2: "Unknown method in
/// b.txt", the first and third OK, exit 2.
#[test]
fn an_unknown_version_refuses_that_member_only() {
    use crate::rar5_lz::vectors::BlockBuilder;
    let packed = |text: &[u8]| {
        let mut block = BlockBuilder::default();
        block.literals(text);
        block.finish(true, true)
    };
    let (first, third) = (packed(b"first"), packed(b"third"));
    let method = 3 << 7;
    for (comp, version) in [(2 | method, 2), (0x3f | method, 0x3f), (0xcc81, 1)] {
        let archive = rar5_members(
            false,
            &[
                (method, b"first", &first),
                (comp, b"kept", b"kept"),
                (method, b"third", &third),
            ],
        );
        let (members, ended) = rar5_extract_one(archive);
        let bytes: Vec<&[u8]> = members.iter().map(|m| &m.0[..]).collect();
        assert_eq!(bytes, [&b"first"[..], b"", b"third"], "{comp:#x}");
        assert!(
            matches!(
                ended.as_ref().map(crate::Error::kind),
                Some(crate::ErrorKind::Unsupported(crate::Unsupported::Version(v))) if *v == version
            ),
            "{comp:#x}: {ended:?}"
        );
    }
}

/// A member of an unknown version that the sink SKIPS, in an archive that
/// is not solid, is neither taken nor needed, and is not the operation's
/// error: the members taken come out whole and `extract` answers `Ok`,
/// as it does for a skipped member whose encryption record it cannot use
/// (unrar 7.23 on a `-m3` archive with its second member's version set
/// to 9, asked for the other members: exit 0). Before, the skipped
/// member's `Unsupported(Version(v))` ended the operation. In a SOLID
/// archive the same skip still ends in that error: a member taken behind
/// it needs the one refused.
#[test]
fn a_skipped_member_of_an_unknown_version_is_not_the_operation_s_error() {
    use crate::rar5_lz::vectors::BlockBuilder;
    use crate::{Disposition, MemberInfo, MemberOutcome, Sink};
    use std::sync::Arc;

    /// Takes every member but the second, in archive order.
    #[derive(Default)]
    struct SkipSecond {
        opened: usize,
        took: Vec<(Vec<u8>, Option<bool>)>,
    }
    impl Sink for SkipSecond {
        type Out = Vec<u8>;
        fn open(&mut self, _: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
            self.opened += 1;
            Ok(if self.opened == 2 {
                Disposition::Skip
            } else {
                Disposition::Write(Vec::new())
            })
        }
        fn close(
            &mut self,
            _: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> crate::Result<()> {
            if let Some(bytes) = out {
                self.took.push((bytes, outcome.checksum_ok));
            }
            Ok(())
        }
    }
    let packed = |text: &[u8]| {
        let mut block = BlockBuilder::default();
        block.literals(text);
        block.finish(true, true)
    };
    let (first, third) = (packed(b"first"), packed(b"third"));
    let method = 3 << 7;
    let read = |solid: bool, comp: u64| {
        let archive = rar5_members(
            solid,
            &[
                (method, b"first", &first),
                (comp, b"kept", b"kept"),
                (method, b"third", &third),
            ],
        );
        let source: Arc<dyn crate::source::RangeSource> = Arc::new(archive);
        let mut sink = SkipSecond::default();
        let ended = crate::extract(
            vec![source],
            &crate::ReadOptions::default(),
            &mut sink,
            &mut (),
        );
        (sink.took, ended.err())
    };
    for (comp, version) in [(2 | method, 2), (9 | method, 9), (0x3f | method, 0x3f)] {
        let (took, ended) = read(false, comp);
        assert!(ended.is_none(), "{comp:#x}, not solid: {ended:?}");
        assert_eq!(
            took,
            [
                (b"first".to_vec(), Some(true)),
                (b"third".to_vec(), Some(true))
            ],
            "{comp:#x}, not solid"
        );
        // Solid: the third member's solid bit is clear in this archive's
        // headers or not, the refused member's error stands either way.
        let (_, ended) = read(true, comp);
        assert!(
            matches!(
                ended.as_ref().map(crate::Error::kind),
                Some(crate::ErrorKind::Unsupported(crate::Unsupported::Version(v))) if *v == version
            ),
            "{comp:#x}, solid: {ended:?}"
        );
    }
}

/// In a SOLID archive the member of an unknown version is never decoded,
/// so the member after it that continues the chain cannot be: it fails,
/// and the next member with its bit clear starts a chain that extracts
/// (spec F 3.2.6). The member after it here copies from four bytes back,
/// which the FIRST member's window can serve, so without the chain broken
/// it came out as the first member's bytes and passed; this pins that it
/// is refused instead. unrar 7.23 stops at the refused member and tests
/// nothing after it, exit 2: a difference spec F 3.2.6 pins.
#[test]
fn an_unknown_version_breaks_its_solid_chain_and_the_next_chain_extracts() {
    use crate::rar5_lz::vectors::BlockBuilder;
    let mut first = BlockBuilder::default();
    first.literals(b"abcdefgh");
    let first = first.finish(true, true);
    let mut after = BlockBuilder::default();
    // Distance 4 is slot 3 with no extra bits; length slot 1 is three.
    after.fresh(1, 0, 3, 0);
    let after = after.finish(false, true);
    let mut next = BlockBuilder::default();
    next.literals(b"next");
    let next = next.finish(true, true);
    let method = 3 << 7;
    let solid_bit = 1 << 6;

    let archive = rar5_members(
        true,
        &[
            (method, b"abcdefgh", &first),
            (2 | method | solid_bit, b"lost", b"lost"),
            (method | solid_bit, b"efg", &after),
            (method, b"next", &next),
        ],
    );
    let (members, ended) = rar5_extract_one(archive);
    let bytes: Vec<&[u8]> = members.iter().map(|m| &m.0[..]).collect();
    assert_eq!(bytes, [&b"abcdefgh"[..], b"", b"", b"next"]);
    assert!(
        matches!(
            ended.as_ref().map(crate::Error::kind),
            Some(crate::ErrorKind::Unsupported(crate::Unsupported::Version(
                2
            )))
        ),
        "{ended:?}"
    );
}

/// A DIRECTORY opens whatever version and method bits it declares, since
/// nothing decodes its data area (spec F 3.2.6.3's last row, `0x3c83`,
/// by design; the reference refuses it, a pinned difference).
#[test]
fn a_compressed_directory_of_an_unknown_version_opens() {
    let (members, ended) = rar5_extract_one(rar5_one_entry(0x01, 0x3c83, b"", b""));
    assert!(ended.is_none(), "{ended:?}");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].1, None);
}

/// Spec F 3.3.5's table, as decided 28 Sep 2026: 29 alone is the RAR 2.9
/// decoder, where the row had read "29 and above". unrar 7.23 gives every
/// higher version "Unknown method", exit 2 (`r393_m3.rar`'s `BIG.TXT` at 36
/// and 99). 16, 21 and 28 the reference decodes and fails on its checksum,
/// exit 3; the table names them not, and they refuse here (a pinned
/// difference; the member fails either way).
#[test]
fn spec_f_3_3_5_the_unpack_version_table() {
    use super::rar4::{codec_for, Rar4Codec};
    for version in 13..=15 {
        assert!(
            matches!(codec_for(version), Some(Rar4Codec::Rar15)),
            "{version}"
        );
    }
    for version in [20, 26] {
        assert!(
            matches!(codec_for(version), Some(Rar4Codec::Rar20)),
            "{version}"
        );
    }
    assert!(matches!(codec_for(29), Some(Rar4Codec::Rar29)));
    for version in [
        0, 10, 12, 16, 19, 21, 25, 27, 28, 30, 36, 50, 99, 200, 255, 256,
    ] {
        assert!(codec_for(version).is_none(), "{version}");
    }
}

/// A RAR 5 archive of `members`, each `(compression information, unpacked
/// bytes, packed bytes)`, with the archive's solid flag as `solid`.
fn rar5_members(solid: bool, members: &[(u64, &[u8], &[u8])]) -> Vec<u8> {
    let one: Vec<Vec<u8>> = members
        .iter()
        .map(|(comp, unpacked, packed)| rar5_one_member(*comp, unpacked, packed))
        .collect();
    // Each one-member archive is the signature (8 bytes), the main header
    // (8: CRC32, size, three fields), the file header and data, and the
    // end record (8); splice the members' middles behind one main header.
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = vec![1u8, 0, if solid { 0x04 } else { 0 }];
    let mut sized = vec![main.len() as u8];
    sized.append(&mut main);
    out.extend_from_slice(&crate::checksum::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    for archive in &one {
        out.extend_from_slice(&archive[8 + 8..archive.len() - 8]);
    }
    out.extend_from_slice(&one[0][one[0].len() - 8..]);
    out
}

/// Spec F 3.6's erratum: a member of ZERO unpacked length does not break
/// the chain and does not reset the decoder, even with its solid bit clear
/// (genuine solid archives carry such members, `d250_sol.rar`'s
/// `EMPTY.DAT`). The RAR 5 restart of 27 Sep 2026 reads each member's own
/// bit, and this is the one case the bit does not decide: the member after
/// the empty one carries NO tables and copies from before it, so reset
/// tables would fail it (`EmptyTable`) and a reset window would give it
/// zero bytes where it copies (SPEC-H2 3.7: a distance before the
/// stream's start is no fault since 11 Oct 2026, and the member's
/// checksum is what says so).
#[test]
fn a_zero_byte_member_with_its_bit_clear_keeps_the_chain() {
    use crate::rar5_lz::vectors::BlockBuilder;
    let mut first = BlockBuilder::default();
    first.literals(b"abcdefgh");
    let first = first.finish(true, true);
    let mut after = BlockBuilder::default();
    // Distance 4 is slot 3 with no extra bits; length slot 1 is three.
    after.fresh(1, 0, 3, 0);
    let after = after.finish(false, true);
    let method = 3 << 7;
    let solid_bit = 1 << 6;

    let archive = rar5_members(
        true,
        &[
            (method, b"abcdefgh", &first),
            (method, b"", b""),
            (method | solid_bit, b"efg", &after),
        ],
    );
    let (members, ended) = rar5_extract_one(archive);
    assert!(ended.is_none(), "{ended:?}");
    let bytes: Vec<&[u8]> = members.iter().map(|m| &m.0[..]).collect();
    assert_eq!(bytes, [&b"abcdefgh"[..], b"", b"efg"]);

    // The control: the same middle member declaring ONE byte (a literal)
    // with its bit clear does restart, so the member after it copies from
    // before the start of a stream that holds one byte: zeros, which its
    // checksum does not agree with.
    let mut one = BlockBuilder::default();
    one.literals(b"z");
    let one = one.finish(true, true);
    let archive = rar5_members(
        true,
        &[
            (method, b"abcdefgh", &first),
            (method, b"z", &one),
            (method | solid_bit, b"efg", &after),
        ],
    );
    let (members, ended) = rar5_extract_one(archive);
    assert!(ended.is_none(), "nothing is said: {ended:?}");
    assert_eq!(
        members[2].0,
        [0, 0, 0],
        "a one byte bit-clear member did not restart"
    );
}
