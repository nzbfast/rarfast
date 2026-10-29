//! `-mm<size>` as the dictionary's cap and the working limit at once.

use super::*;

fn opts_with_cap(cap: Option<u64>) -> Options {
    Options {
        memory_cap: cap,
        ..Options::default()
    }
}

/// Options whose named `-mm` gives the engine exactly `limit` as its
/// `working_limit` (`mm_for_engine_limit`): the rows below pin the ENGINE
/// at spec G 3.5's figures, and a named `-mm` is the whole process's.
fn opts_with_engine_limit(limit: u64) -> Options {
    let opts = Options::default();
    opts_with_cap(Some(mm_for_engine_limit(limit, &opts)))
}

/// Acceptance test 3: `-mm` still caps the dictionary exactly as it
/// did before this change.
#[test]
fn mm_still_caps_the_dictionary() {
    let default_dictionary = rarkit::MemoryPolicy::default().max_dictionary;

    let policy = memory_policy(&opts_with_cap(Some(4 << 20)), &[]);
    assert_eq!(
        policy.max_dictionary,
        4 << 20,
        "-mm4m did not cap the dictionary to 4 MiB"
    );

    // A cap above the default ceiling changes nothing: `-mm` only
    // ever lowers the dictionary, exactly as before.
    let policy = memory_policy(&opts_with_cap(Some(1 << 30)), &[]);
    assert_eq!(
        policy.max_dictionary, default_dictionary,
        "-mm1g raised the dictionary past its default ceiling"
    );

    // The 128 KiB floor still holds for a cap smaller than it.
    let policy = memory_policy(&opts_with_cap(Some(1)), &[]);
    assert_eq!(
        policy.max_dictionary,
        1 << 17,
        "-mm1 did not floor at 128 KiB"
    );
}

/// `-mm<size>` sets `working_limit` from the figure (spec G 3.5's
/// erratum, reading (a)), and since 24 Oct 2026 at EVERY figure as the
/// whole process's: the figure less the process headroom and `mm_room`,
/// so a figure that cannot hold even those leaves the engine nothing. The
/// figure is floored at 128 KiB as the dictionary cap is. Until then this
/// row pinned `-mm8m` to an 8 MiB engine and `-mm1` to 128 KiB, and the
/// process passed a named figure by up to 71 MiB.
#[test]
fn mm_sets_the_working_limit_from_the_figure_in_process_terms() {
    let opts = opts_with_cap(Some(8 << 20));
    let policy = memory_policy(&opts, &[]);
    let process = rarkit::MemoryPolicy::for_process(8 << 20, mm_room(&[], &opts));
    assert_eq!(
        (policy.working_limit, policy.process_overhead),
        (process.working_limit, process.process_overhead),
        "-mm8m is the process's budget"
    );
    assert!(policy.limit_named, "-mm8m reached the engine as no ceiling");

    let roomy = opts_with_engine_limit(8 << 20);
    assert_eq!(
        memory_policy(&roomy, &[]).working_limit,
        8 << 20,
        "the figure that leaves the engine 8 MiB does not"
    );

    let opts = opts_with_cap(Some(1));
    let policy = memory_policy(&opts, &[]);
    assert_eq!(
        policy.working_limit,
        rarkit::MemoryPolicy::for_process(1 << 17, mm_room(&[], &opts)).working_limit,
        "-mm1 is not floored at 128 KiB"
    );
}

/// `-mm512m` names exactly `MemoryPolicy::DEFAULT_LIMIT`, and a named
/// ceiling must still reach the engine as one: before
/// `MemoryPolicy::limit_named` it was read as no ceiling at all, so a
/// create under `-mm512m` never took spec G 3.5 case (b)'s streaming
/// mode. Every figure around the default is named.
///
/// And at every figure, either side of 512 MiB, the engine's limit is the
/// figure less the process headroom and `mm_room`, `for_process`'s
/// arithmetic, so the budget is the figure (since 24 Oct 2026; until
/// then a figure under 512 MiB was the engine's own).
#[test]
fn mm_naming_the_default_limit_is_still_a_ceiling() {
    let default = rarkit::MemoryPolicy::DEFAULT_LIMIT;
    for cap in [default - 1, default, default + 1, 2 << 30] {
        let opts = opts_with_cap(Some(cap));
        let policy = memory_policy(&opts, &[]);
        assert!(
            policy.limit_named,
            "-mm of {cap} bytes reached the engine as no ceiling"
        );
        let process = rarkit::MemoryPolicy::for_process(cap, mm_room(&[], &opts));
        assert_eq!(
            (policy.working_limit, policy.process_overhead),
            (process.working_limit, process.process_overhead),
            "-mm of {cap} bytes is the process's budget"
        );
        assert_eq!(
            policy.working_limit + policy.process_overhead,
            cap,
            "the budget is the figure"
        );
        assert_eq!(
            policy.max_dictionary,
            rarkit::MemoryPolicy::default().max_dictionary.min(cap)
        );
    }
}

/// With no `-mm` at all the policy is `process_default`'s:
/// not named, its `working_limit` the machine's default process budget
/// (the larger of 512 MiB and a quarter of physical memory)
/// less the process headroom and what the binary holds (at least the
/// read-ahead's floor), and the dictionary cap `default()`'s.
#[test]
fn no_mm_takes_the_process_default() {
    let opts = opts_with_cap(None);
    let policy = memory_policy(&opts, &[]);
    assert!(!policy.limit_named, "no -mm at all named a ceiling");
    let process = rarkit::MemoryPolicy::process_default(create_resident(&[], &opts));
    assert_eq!(policy.working_limit, process.working_limit);
    assert_eq!(policy.process_overhead, process.process_overhead);
    assert!(
        policy.process_overhead
            >= rarkit::MemoryPolicy::PROCESS_HEADROOM + super::super::ahead::held_bytes_most(1),
        "the process terms {} leave no room for the read-ahead",
        policy.process_overhead
    );
    assert_eq!(
        policy.max_dictionary,
        rarkit::MemoryPolicy::default().max_dictionary
    );
}

/// Bytes that do not compress, so a member's packed output is close
/// to its input size and the held-whole write's cost actually follows
/// the member, the way `crates/rarkit/tests/streamed_packed_member.rs`
/// (`noise`) uses to the same end for the engine's own budgeted
/// streaming rows.
///
/// Since 28 Sep 2026 a non-solid member of 1 MiB and more whose
/// samples all fail to compress is written STORED (spec G 3.8.3), which
/// has no packed output to follow the member, so this plants a run of
/// 512 zero bytes in the middle of the samples of the first five of the
/// sixteen segments, which outvotes the rule at every size (two do
/// under 128 MiB; from 128 MiB four may compress); the engine's
/// `lz_noise` does the same, and its `plain_noise_is_now_stored_and_so_
/// reaches_no_encoder` pins the plain stream the other way.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut out = rarkit_testdata::scramble(seed, len);
    for segment in 0..5 {
        let middle = (2 * segment + 1) * len / 32;
        out[middle - 256..middle + 256].fill(0);
    }
    out
}

/// Writes one incompressible member of `length` bytes over a non-solid
/// volume set, through `write_options` with `opts` as given, and
/// answers the volumes and the write report.
fn write_one_long_member(
    opts: &Options,
    length: usize,
    seed: u64,
) -> (Vec<Vec<u8>>, rarkit::WriteReport) {
    let options = write_options(opts, &[], None);
    let head = vec![b'h'; 4_000];
    let long = incompressible(length, seed);
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"head.txt",
            payload: Payload::Bytes(&head),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add head.txt");
    writer
        .add(MemberSpec {
            name: b"long.bin",
            payload: Payload::Bytes(&long),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add long.bin");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
    (volumes, report)
}

/// The dictionary this row asks for with `-md`, matching
/// `crates/rarkit/tests/streamed_packed_member.rs`'s own `DICTIONARY`
/// so the working-memory figures below are the ones that file's own
/// comments already measured. Small, so the held-whole cost of a
/// multi-mebibyte member is dominated by the member and not by the
/// dictionary the writer would otherwise keep for its own default
/// (2 MiB), which the DEFAULT `-mm` figures used elsewhere in this
/// module never come near.
const SMALL_DICTIONARY: u64 = 128 << 10;

/// A ceiling the streamed walk fits inside and the held-whole write of
/// a member from 2 to 8 MiB does not, computed from spec G 3.5's
/// terms exactly as `streamed_packed_member.rs`'s `roomy` computes it
/// for the same dictionary: the dictionary, one window, the chains'
/// finder over the window and the history it carries (4 MiB of fixed
/// heads and 1 Mi links, 8 MiB), and a 3 MiB margin, about 11.4 MiB.
///
/// It was `-mm3m`, which spec G 3.5 (restated 28 Sep 2026) withdrew:
/// the chains' heads alone are 4 MiB, so no walk at levels 1 to 3 fits
/// once the report counts the lead encoder's finder (held, the walk here
/// stated 8,519,907 bytes). Each member's held-whole write, the finder
/// over the member's own length, is still above it: 14.4 MiB for 2 MiB.
const ROOMY_CAP: u64 = {
    let window = 256 << 10;
    let span = SMALL_DICTIONARY * 5 + window;
    let links = if span.next_power_of_two() < 16 << 20 {
        span.next_power_of_two()
    } else {
        16 << 20
    };
    SMALL_DICTIONARY + window + 4 * (1 << 20) + 4 * links + (3 << 20)
};

/// Acceptance test 1: `-mm<size>` on a create whose member exceeds the
/// size takes the budgeted path.
///
/// Built through `write_options`, the exact function a real `-mm`
/// command line resolves to, over a non-solid volume set - SPEC-G
/// 3.5's case (b). The observable property of the budgeted
/// walk is that its peak working memory does not grow with the
/// member's size (`crates/rarkit/tests/streamed_packed_member.rs`'s
/// `ceiling_rule_a_budgeted_write_is_bounded_and_accepted`), where the
/// default (no ceiling) mode's does - so this compares a 2 MiB and an
/// 8 MiB member under `-mm` at `ROOMY_CAP` and `-md128k` against the same two members
/// with no `-mm` at all.
#[test]
fn mm_takes_the_budgeted_path_when_a_member_would_exceed_it() {
    // One parse block, the grain rarkit's own working-memory buffers
    // grow in (the same margin `streamed_packed_member.rs` uses).
    const SAME: u64 = 256 << 10;

    let mut budgeted = opts_with_engine_limit(ROOMY_CAP); // the engine at about 11.4 MiB
    budgeted.dictionary = Some(SMALL_DICTIONARY); // -md128k
    budgeted.volume_size = Some(200_000);
    let mut unbudgeted = opts_with_cap(None);
    unbudgeted.dictionary = Some(SMALL_DICTIONARY);
    unbudgeted.volume_size = Some(200_000);

    // Both lengths must exceed the write's own WINDOW (the dictionary
    // clamped up to one parse block, 256 KiB here) or neither is
    // eligible to stream at all (spec G 3.5's size condition,
    // `Run::streams_packed`), and a member held whole for THAT reason
    // alone is not what this row measures.
    let (small_volumes, small_report) = write_one_long_member(&budgeted, 2 << 20, 1);
    let (large_volumes, large_report) = write_one_long_member(&budgeted, 8 << 20, 2);
    assert!(
        small_volumes.len() > 1 && large_volumes.len() > 1,
        "a member over a 200,000 byte volume budget did not split into a set"
    );
    assert!(
        small_report.peak_working_memory <= ROOMY_CAP,
        "-mm held {} bytes for a 2 MiB member against a {ROOMY_CAP} byte ceiling",
        small_report.peak_working_memory
    );
    assert!(
        large_report.peak_working_memory <= ROOMY_CAP,
        "-mm held {} bytes for an 8 MiB member against a {ROOMY_CAP} byte ceiling",
        large_report.peak_working_memory
    );
    assert_eq!(small_report.ceiling_exceeded_by, None);
    assert_eq!(large_report.ceiling_exceeded_by, None);
    assert!(
        large_report.peak_working_memory <= small_report.peak_working_memory + SAME,
        "-mm held {} bytes for a 2 MiB member and {} for an 8 MiB one, so the budgeted \
             walk is not following the member",
        small_report.peak_working_memory,
        large_report.peak_working_memory
    );

    let (_, small_held) = write_one_long_member(&unbudgeted, 2 << 20, 1);
    let (_, large_held) = write_one_long_member(&unbudgeted, 8 << 20, 2);
    assert!(
        large_held.peak_working_memory > small_held.peak_working_memory + SAME,
        "the held-whole write did not grow with the member's size, so this row is not \
             measuring the difference it names"
    );
    assert!(
        large_report.peak_working_memory + SAME < large_held.peak_working_memory,
        "-mm held {} bytes for an 8 MiB member against {} held whole, which is not the \
             saving the budgeted path exists for",
        large_report.peak_working_memory,
        large_held.peak_working_memory
    );
}

/// A volume provider that CANNOT patch, collecting in memory: the
/// walk every `rarfast` volume set took before its own `Volumes`
/// learned to patch, kept here as the control the rows below compare
/// against.
struct Unpatched(Vec<Vec<u8>>);

impl VolumeOut for Unpatched {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> rarkit::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> rarkit::Result<()> {
        self.0.push(volume);
        Ok(())
    }
}

/// One member of `body` as a `Payload::Reader` stating no CRC32, which
/// is how `write_archive` hands every file over, written by `opts`
/// into `out`.
fn write_reader<O: VolumeOut>(opts: &Options, body: &[u8], out: &mut O) -> rarkit::WriteReport {
    let mut reader = std::io::Cursor::new(body);
    let mut writer = Writer::new(write_options(opts, &[], None)).expect("options");
    writer
        .add(MemberSpec {
            name: b"long.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size: body.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add long.bin");
    writer
        .finish_volumes_with(out, &mut ())
        .expect("finish_volumes")
}

/// The same write through the CLI's own FILE volumes, answering each
/// volume's bytes as it lies on disk and the report.
fn write_reader_to_files(
    opts: &Options,
    body: &[u8],
    tag: &str,
) -> (Vec<Vec<u8>>, rarkit::WriteReport) {
    let dir = std::env::temp_dir().join(format!("rarfast-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let mut created = Vec::new();
    let mut volumes = Volumes {
        stem: dir.join("arc").to_string_lossy().into_owned(),
        naming: VolumeNaming::Numbered,
        estimate: 1,
        expected: 0,
        created: &mut created,
    };
    let report = write_reader(opts, body, &mut volumes);
    let bytes = created
        .iter()
        .map(|path| std::fs::read(path).expect("read a volume back"))
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    (bytes, report)
}

/// `a -m0 -v<size>` holds NOTHING for a member whose CRC32 nobody
/// stated, and writes the bytes it wrote when it held a volume.
///
/// Before `Volumes` could patch, each fragment's payload was held from
/// its placeholder header until its checksum was known, so peak RSS
/// was the volume size: 1,030 MiB at `-v1g` on an Apple M3 Mac, 28 Sep 2026.
#[test]
fn a_stored_volume_set_holds_nothing_and_keeps_its_bytes() {
    let mut opts = opts_with_cap(None);
    opts.level = super::super::args::Level::Store;
    opts.volume_size = Some(200_000);
    let body = incompressible(1 << 20, 3);

    let (files, report) = write_reader_to_files(&opts, &body, "stored-patch");
    assert!(files.len() > 1, "a 1 MiB member did not split into a set");
    assert_eq!(
        report.held_volume_bytes, 0,
        "a stored member's bytes were held until its checksum was known"
    );

    let mut held = Unpatched(Vec::new());
    let held_report = write_reader(&opts, &body, &mut held);
    assert!(
        held_report.held_volume_bytes > 0,
        "the control did not hold, so it is not the walk this row compares against"
    );
    assert_eq!(
        files, held.0,
        "patching the placeholder moved a stored volume set's bytes"
    );
}

/// `-v<size>` caps each volume FILE, headers and end block included,
/// which is what rar 7.23's `-v` means; the payload budget it used to
/// be passed as wrote every volume 73 or 74 bytes over.
#[test]
fn every_volume_is_at_most_the_cap() {
    let mut opts = opts_with_cap(None);
    opts.level = super::super::args::Level::Store;
    opts.volume_size = Some(200_000);
    let (files, _) = write_reader_to_files(&opts, &incompressible(1 << 20, 5), "file-cap");
    assert!(files.len() > 1, "a 1 MiB member did not split into a set");
    let sizes: Vec<usize> = files.iter().map(Vec::len).collect();
    assert!(
        sizes.iter().all(|size| *size <= 200_000),
        "a volume passed the 200,000 byte cap: {sizes:?}"
    );
}

/// Under `-mm` a long compressed member of a non-solid set STREAMS
/// through the CLI's file volumes (SPEC-G 3.5 mode 2)
/// rather than being held whole past the ceiling, and the files carry
/// exactly the bytes the engine's own in-memory patching provider
/// writes.
#[test]
fn mm_streams_a_long_member_through_file_volumes() {
    // ROOMY_CAP is spec G 3.5's streamed-walk terms; a READER member of
    // 1 MiB and more also holds spec G 3.8.3's sampled head until the
    // store verdict, pulled to the sample that settles it: for this
    // member, which compresses, 3/32 of its 8 MiB and half a sample
    // (a member under 128 MiB is settled by its second compressible
    // sample). The ceiling has to afford that head (spec G 3.5: the
    // walk's sum PLUS the head), and since 1 Oct 2026 the engine counts
    // it when it chooses its hold (`Run::sampled_head_bytes`). Still
    // far under the member's held-whole cost.
    const SAMPLED_HEAD: u64 = 3 * (8 << 20) / 32 + (32 << 10);
    let mut opts = opts_with_engine_limit(ROOMY_CAP + SAMPLED_HEAD);
    opts.dictionary = Some(SMALL_DICTIONARY);
    opts.volume_size = Some(200_000);
    let body = incompressible(8 << 20, 4);

    let (files, report) = write_reader_to_files(&opts, &body, "mm-patch");
    assert_eq!(
        report.ceiling_exceeded_by, None,
        "-mm over file volumes held a long member whole past its ceiling"
    );
    assert!(
        report.peak_working_memory <= ROOMY_CAP + SAMPLED_HEAD,
        "-mm over file volumes held {} bytes against a {} byte ceiling",
        report.peak_working_memory,
        ROOMY_CAP + SAMPLED_HEAD
    );

    let mut memory: Vec<Vec<u8>> = Vec::new();
    write_reader(&opts, &body, &mut memory);
    assert_eq!(
        files, memory,
        "the file volumes' patches did not land where the in-memory ones do"
    );

    // The control: an output that cannot patch a header back must hold the
    // member whole, which passes the ceiling. Until chain 40 it ran and
    // passed it (`ceiling_exceeded_by`); the named ceiling's admission now
    // charges every term the run holds (`Run::named_most_bytes`) and so
    // refuses it before a byte, naming what it needs.
    let mut reader = std::io::Cursor::new(&body[..]);
    let mut writer = Writer::new(write_options(&opts, &[], None)).expect("options");
    writer
        .add(MemberSpec {
            name: b"long.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size: body.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add long.bin");
    let refused = writer
        .finish_volumes_with(&mut Unpatched(Vec::new()), &mut ())
        .expect_err("the unpatched control held the member whole inside the ceiling");
    assert!(
        matches!(
            refused.kind(),
            rarkit::ErrorKind::LimitExceeded {
                resource: rarkit::Resource::WorkingMemory,
                ..
            }
        ),
        "the unpatched control was refused for another reason: {refused}"
    );
}

/// Without `-mm` no ceiling is NAMED, so SPEC-G 3.5's named streaming
/// mode is inert; the limit the default's held-member rule
/// and the writer's admission read is `process_default`'s
/// (SPEC-API 8.4.1): the machine's default process budget
/// less the process headroom and what the binary holds.
#[test]
fn no_mm_names_no_ceiling_and_takes_the_process_limit() {
    let mut opts = opts_with_cap(None);
    opts.volume_size = Some(200_000);
    let options = write_options(&opts, &[], None);
    assert!(!options.memory.limit_named, "no -mm named a ceiling");
    assert!(
        options.memory.working_limit
            >= rarkit::MemoryPolicy::DEFAULT_LIMIT
                .min(rarkit::MemoryPolicy::process_default(0).working_limit)
                .saturating_sub(options.memory.process_overhead),
        "no -mm left working_limit at {}, under the floor",
        options.memory.working_limit
    );
    assert!(
        options.memory.process_overhead >= rarkit::MemoryPolicy::PROCESS_HEADROOM,
        "no -mm took {} bytes off for the process, under the headroom",
        options.memory.process_overhead
    );
}

/// The `-mm` a refusal under a named `-mm` names is the least whole MiB
/// whose policy holds the figure: the figure plus the process headroom and
/// `mm_room`, at every figure, so a larger `-mm` holds whatever a smaller
/// one holds (until 24 Oct 2026 `-mm420m` held a figure `-mm512m` did not).
/// No threads, no memory beyond the policy.
#[test]
fn the_least_mm_that_holds_a_figure_is_named_in_whole_mib() {
    let opts = opts_with_cap(None);
    for needed in [1u64, 1 << 20, (100 << 20) + 1, 425_327_620, (511 << 20) + 5] {
        let mib = least_mm_that_holds(needed, &[], &opts);
        let holds = |mib: u64| {
            let policy = memory_policy(&opts_with_cap(Some(mib << 20)), &[]);
            policy.working_limit >= needed
        };
        assert!(holds(mib), "-mm{mib}m does not hold {needed}");
        assert!(
            mib == 1 || !holds(mib - 1),
            "-mm{}m already holds {needed}",
            mib - 1
        );
    }
    let room = rarkit::MemoryPolicy::PROCESS_HEADROOM + mm_room(&[], &opts_with_cap(Some(1)));
    assert_eq!(
        least_mm_that_holds(425_327_620, &[], &opts),
        (425_327_620 + room).div_ceil(1 << 20),
        "the figure named is the need, the headroom and the room, in whole MiB"
    );
    let over = least_mm_that_holds(700 << 20, &[], &opts);
    assert!(
        over >= 700 + (rarkit::MemoryPolicy::PROCESS_HEADROOM >> 20),
        "-mm{over}m for 700 MiB leaves no process headroom"
    );
}
