//! Spec G 3.5's held-member rule (30 Sep 2026):
//! under the default policy a member is HELD only where its held-whole
//! write, the packed bytes COUNTED TWICE (the buffer they grow in and the
//! one beside it), fits the policy's `working_limit`; otherwise it STREAMS
//! where the output can patch. An output that cannot patch still holds
//! the member and completes. The rule before it compared the packed
//! bound ALONE with `DEFAULT_LIMIT`, and so held S8's 356 MB member at
//! 750 MiB of process peak.
//!
//! The rows here are the spec's five acceptance tests. The ones in
//! `make ci` lower the limit (`with_stream_above`) so that a member of a
//! few MiB meets it the way a member of 360 MB meets 512 MiB, sized so
//! that the member's packed bound ALONE fits the limit: the earlier test
//! would hold it, and this rule streams it. The two rows at S8's own size
//! and the shipped limit are `#[ignore]`d for their encode time and are
//! run in release (`cargo test --release -p rarkit --features repo-tests
//! --test held_member_ceiling -- --ignored`); the process's own peak is
//! `crates/rarkit-cli/tests/held_member_process_peak.rs`.

use std::io::{Cursor, Read};
use std::sync::Arc;

use rarkit::internals::writers::{reset_streamed_members, streamed_members, with_stream_above};
use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, ReadOptions, Result,
    Sink, WriteFormat, WriteMethod, WriteOptions, WriteReport, Writer,
};

const MIB: usize = 1 << 20;

/// Bytes with no structure. These rows are about a solid member the store
/// rule does NOT store, which the held-member rule still governs (spec G
/// 3.5), so they write with `solid_store` off (`options`): the member
/// stays in the compressor and its packed bytes are about its own size, as
/// S8's video was until 1 Oct 2026, when spec G 3.8.3 began to store it.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(len);
    out
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.0.push(Vec::new());
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        if let (Some(bytes), Some(last)) = (out, self.0.last_mut()) {
            *last = bytes;
        }
        Ok(())
    }
}

fn read_back(archive: &[u8]) -> Vec<Vec<u8>> {
    let sources = vec![Arc::new(archive.to_vec()) as Arc<dyn rarkit::RangeSource>];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back: {e}"));
    sink.0
}

fn options(format: WriteFormat, level: u8, solid: bool) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid,
        solid_store: false,
        // The solid default dictionary (10 Oct 2026) is not this file's
        // subject: the peaks it compares were measured at the 2 MiB
        // window, which this keeps. `solid_default_dictionary` holds the default.
        solid_dictionary_2mib: true,
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

/// Whether the archive goes to an output that can seek (`finish_seek`,
/// a file) or one that cannot (`finish_into`, the command line's stdout).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Finish {
    Seek,
    Into,
}

/// Every member through a READER, the command line's payload. Answers the
/// archive, the report and how many members the streamed walk took.
fn write(
    options: WriteOptions,
    finish: Finish,
    members: &[&[u8]],
) -> (Vec<u8>, WriteReport, usize) {
    reset_streamed_members();
    let names: Vec<String> = (0..members.len()).map(|i| format!("m{i}.bin")).collect();
    let mut readers: Vec<Cursor<&[u8]>> = members.iter().map(|m| Cursor::new(*m)).collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, reader), data) in names.iter().zip(readers.iter_mut()).zip(members) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Reader {
                    reader: reader as &mut (dyn Read + Send),
                    size: data.len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let (archive, report) = match finish {
        Finish::Seek => {
            let mut out = Cursor::new(Vec::new());
            let report = writer.finish_seek(&mut out).expect("finish_seek");
            (out.into_inner(), report)
        }
        Finish::Into => {
            let mut out = Vec::new();
            let report = writer.finish_into(&mut out).expect("finish_into");
            (out, report)
        }
    };
    (archive, report, streamed_members())
}

/// The scaled member, and the limit it meets: its packed bound (about
/// `BIG`) fits `LIMIT`, so the earlier bound-alone test would hold it,
/// and twice it does not, so this rule streams it.
const BIG: usize = 24 * MIB + 4321;
const LIMIT: u64 = (BIG as u64) * 3 / 2;

const LEVELS: [u8; 3] = [1, 3, 5];

/// One RAR 5 block as the reader sees it: the header's fields DECODED,
/// so that a field written at another width compares equal, and its data.
#[derive(Debug, PartialEq)]
struct Block<'a> {
    kind: u64,
    flags: u64,
    extra: Option<u64>,
    data_size: Option<u64>,
    rest: &'a [u8],
    data: &'a [u8],
}

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// Walks a RAR 5 archive's blocks, answering each decoded and the raw
/// bytes of its header.
fn blocks(archive: &[u8]) -> Vec<(Block<'_>, &[u8])> {
    const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
    assert_eq!(&archive[..8], SIGNATURE, "not a RAR 5 archive");
    let mut out = Vec::new();
    let mut at = 8;
    while at < archive.len() {
        let start = at;
        at += 4;
        let size = vint(archive, &mut at) as usize;
        let end = at + size;
        let kind = vint(archive, &mut at);
        let flags = vint(archive, &mut at);
        let extra = (flags & 1 != 0).then(|| vint(archive, &mut at));
        let data_size = (flags & 2 != 0).then(|| vint(archive, &mut at));
        let rest = &archive[at..end];
        let data = &archive[end..end + data_size.unwrap_or(0) as usize];
        at = end + data.len();
        out.push((
            Block {
                kind,
                flags,
                extra,
                data_size,
                rest,
                data,
            },
            &archive[start..end],
        ));
    }
    out
}

/// Acceptance test 1, scaled: under the default policy a solid `-m1`,
/// `-m3` and `-m5` create of an incompressible member whose packed bound
/// alone fits the limit, written to an output that can seek, STREAMS it,
/// and the archive reads back to the input.
///
/// And the streamed write holds LESS than the held one, by more than half
/// the member: the held walk keeps the member's packed bytes whole, the
/// streamed walk one batch of them. That comparison is made at ONE
/// worker, where `peak_working_memory` is a function of the options and
/// the bytes: measured five times each on an M5 Max, the streamed walk
/// held 103,830,985 bytes and the held walk 118,524,738 at -m1 and -m3
/// (137,906,412 and 152,671,380 at -m5) on every run. At the default
/// width both figures follow how many parses happen to be in flight, so
/// they move from run to run (122.7 to 124.8 MB streamed, 139.5 to 141.6
/// held, idle), and under a concurrent `make ci` the streamed one was read
/// at 154.2 MB against a held 147.9 (an M3 Mac, 1 Oct 2026), which is why
/// the comparison is not made there. The width does not choose the mode
/// (test 5), so the walks compared are the walks the default takes.
#[test]
fn a_member_whose_doubled_sum_passes_the_limit_streams_at_every_level() {
    let big = noise(BIG, 1);
    for level in LEVELS {
        let (archive, _, took) = with_stream_above(LIMIT, || {
            write(
                options(WriteFormat::Rar5, level, true),
                Finish::Seek,
                &[&big],
            )
        });
        assert_eq!(took, 1, "-m{level}: the member was held");
        assert_eq!(read_back(&archive), vec![big.clone()], "-m{level}");
        let one = || WriteOptions {
            workers: Some(1),
            ..options(WriteFormat::Rar5, level, true)
        };
        let (_, streamed, one_took) =
            with_stream_above(LIMIT, || write(one(), Finish::Seek, &[&big]));
        let (_, held, _) = with_stream_above(u64::MAX, || write(one(), Finish::Seek, &[&big]));
        assert_eq!(one_took, 1, "-m{level}: one worker took another mode");
        assert!(
            streamed.peak_working_memory + (BIG as u64) / 2 < held.peak_working_memory,
            "-m{level}: streamed {} bytes, held {}",
            streamed.peak_working_memory,
            held.peak_working_memory
        );
    }
}

/// Acceptance test 2: the same solid create held (the
/// rule's test forced off) and streamed differ in the big member's packed
/// size field ONLY. Every block decodes to the same fields and carries the
/// same data; the members beside it (each at most one window, so never
/// streamed) are the same bytes; and only the big
/// member's header may differ in its raw bytes (the field's width, and
/// with it the header's length and checksum). RAR 4's field is fixed
/// width, so there the two are one archive.
#[test]
fn held_and_streamed_differ_in_the_packed_size_field_only() {
    let (small, big, after) = (
        rarkit_testdata::chatter(2, 100_000),
        noise(BIG, 3),
        rarkit_testdata::chatter(4, 250_007),
    );
    let members: [&[u8]; 3] = [&small, &big, &after];
    for level in LEVELS {
        let (streamed, _, took) = with_stream_above(LIMIT, || {
            write(
                options(WriteFormat::Rar5, level, true),
                Finish::Seek,
                &members,
            )
        });
        let (held, _, held_took) = with_stream_above(u64::MAX, || {
            write(
                options(WriteFormat::Rar5, level, true),
                Finish::Seek,
                &members,
            )
        });
        assert_eq!(took, 1, "-m{level}: the big member was held");
        assert_eq!(
            held_took, 0,
            "-m{level}: the rule forced off still streamed"
        );
        let (s, h) = (blocks(&streamed), blocks(&held));
        assert_eq!(s.len(), h.len(), "-m{level}: block count");
        let mut differ = 0;
        for (i, ((sb, sraw), (hb, hraw))) in s.iter().zip(&h).enumerate() {
            assert_eq!(sb, hb, "-m{level}: block {i} decodes differently");
            if sraw != hraw {
                differ += 1;
                assert!(
                    sb.data.len() >= BIG,
                    "-m{level}: block {i}, not the big member's header, differs"
                );
                assert!(
                    sraw.len() <= hraw.len() + 2 && hraw.len() <= sraw.len(),
                    "-m{level}: header {} bytes streamed, {} held",
                    sraw.len(),
                    hraw.len()
                );
            }
        }
        assert!(differ <= 1, "-m{level}: {differ} headers differ");
        assert_eq!(
            read_back(&streamed),
            vec![small.clone(), big.clone(), after.clone()],
            "-m{level}"
        );
    }
    let rar4 = WriteFormat::Rar4(rarkit::Rar4Version::V29);
    let (streamed, _, took) = with_stream_above(LIMIT, || {
        write(options(rar4, 3, true), Finish::Seek, &members)
    });
    let (held, _, _) = with_stream_above(u64::MAX, || {
        write(options(rar4, 3, true), Finish::Seek, &members)
    });
    assert_eq!(took, 1, "RAR 4: the big member was held");
    assert!(
        streamed == held,
        "RAR 4: the streamed archive differs from the held one"
    );
}

/// Acceptance test 3: a member whose held-whole sum fits the limit is
/// HELD, and its archive is today's to the byte: the same over an output
/// that can seek as over one that cannot, and the same as the rule forced
/// off. At the shipped limit (the policy's own `working_limit`) and at a
/// lowered one that the member's sum still fits.
#[test]
fn a_member_that_fits_is_held_and_unchanged() {
    let (small, member) = (rarkit_testdata::chatter(5, MIB), noise(6 * MIB + 5, 6));
    let members: [&[u8]; 2] = [&small, &member];
    for solid in [true, false] {
        for level in LEVELS {
            let opts = || options(WriteFormat::Rar5, level, solid);
            let (shipped, _, took) = write(opts(), Finish::Seek, &members);
            let (roomy, _, roomy_took) =
                with_stream_above(512 << 20, || write(opts(), Finish::Seek, &members));
            let (into, _, _) = write(opts(), Finish::Into, &members);
            let (off, _, _) = with_stream_above(u64::MAX, || write(opts(), Finish::Seek, &members));
            let what = format!("-m{level} solid {solid}");
            assert_eq!(took, 0, "{what}: streamed at the shipped limit");
            assert_eq!(roomy_took, 0, "{what}: streamed under a limit it fits");
            assert!(
                shipped == into,
                "{what}: the held archive depends on the output"
            );
            assert!(
                shipped == off,
                "{what}: the held archive moved with the rule"
            );
            assert!(roomy == off, "{what}");
        }
    }
}

/// Acceptance test 4: the same member written to an output
/// that cannot patch (`finish_into`, stdout) is HELD, the write completes,
/// the archive reads back, and the report states the bytes it held: its
/// working memory carries the member's packed bytes, which pass the
/// limit. Under the default, which is not a ceiling the caller chose,
/// `ceiling_exceeded_by` stays `None`.
#[test]
fn an_output_that_cannot_patch_holds_completes_and_reports() {
    let big = noise(BIG, 7);
    for level in LEVELS {
        let (archive, report, took) = with_stream_above(LIMIT, || {
            write(
                options(WriteFormat::Rar5, level, true),
                Finish::Into,
                &[&big],
            )
        });
        assert_eq!(took, 0, "-m{level}: an output that cannot patch streamed");
        assert_eq!(read_back(&archive), vec![big.clone()], "-m{level}");
        assert!(
            report.peak_working_memory >= BIG as u64,
            "-m{level}: the report states {} bytes for a held member of {BIG}",
            report.peak_working_memory
        );
        assert_eq!(report.ceiling_exceeded_by, None, "-m{level}");
    }
}

/// Acceptance test 5: the choice is a function of the policy and the
/// member alone. The same member at one worker and at sixteen takes the
/// same mode, on each side of the limit, and writes the same bytes.
#[test]
fn the_mode_is_the_same_at_one_worker_and_at_sixteen() {
    let big = noise(BIG, 8);
    for level in LEVELS {
        for limit in [LIMIT, u64::MAX] {
            let run = |workers| {
                let opts = WriteOptions {
                    workers: Some(workers),
                    ..options(WriteFormat::Rar5, level, true)
                };
                with_stream_above(limit, || write(opts, Finish::Seek, &[&big]))
            };
            let (one, _, one_took) = run(1);
            let (sixteen, _, sixteen_took) = run(16);
            assert_eq!(
                one_took, sixteen_took,
                "-m{level} limit {limit}: the mode moved"
            );
            assert_eq!(
                one_took,
                usize::from(limit == LIMIT),
                "-m{level} limit {limit}"
            );
            assert!(
                one == sixteen,
                "-m{level} limit {limit}: the bytes moved with the width"
            );
        }
    }
}

/// Acceptance test 1 at S8's own shape and the SHIPPED limit: a solid
/// create of a 360 MB incompressible member streams at `-m1`, `-m3` and
/// `-m5` under `MemoryPolicy::default`, whose packed bound alone (under
/// 512 MiB) the earlier rule held, and the writer's working memory stays under
/// 512 MiB. Release only, for the encode time.
#[test]
#[ignore = "360 MB at three levels: run in release with --ignored"]
fn s8_shape_streams_at_the_shipped_limit() {
    let big = noise(360_000_000, 9);
    for level in LEVELS {
        let (archive, report, took) = write(
            options(WriteFormat::Rar5, level, true),
            Finish::Seek,
            &[&big],
        );
        assert_eq!(took, 1, "-m{level}: a 360 MB member was held");
        assert!(
            report.peak_working_memory < 512 << 20,
            "-m{level}: {} bytes",
            report.peak_working_memory
        );
        assert!(read_back(&archive)[0] == big, "-m{level}: read back");
    }
}

/// Acceptance test 4 at S8's own shape: to stdout the 360 MB member is
/// held, completes, reads back and reports what it held.
#[test]
#[ignore = "360 MB: run in release with --ignored"]
fn s8_shape_to_stdout_holds_and_reports() {
    let big = noise(360_000_000, 10);
    let (archive, report, took) = write(options(WriteFormat::Rar5, 1, true), Finish::Into, &[&big]);
    assert_eq!(took, 0, "an output that cannot patch streamed");
    assert!(
        report.peak_working_memory >= 360_000_000,
        "{}",
        report.peak_working_memory
    );
    assert!(read_back(&archive)[0] == big, "read back");
}
