//! A compressed member LARGER THAN ONE WINDOW in a volume set, written
//! as the encoder produces it (spec G 3.5 and 3.7.3).
//!
//! **Two cases with two different conditions, since 20 Sep
//! 2026.** Spec G 3.5 first reserved the packed size field, and with it this
//! walk, for a member of a SOLID run in a volume set: case (a), which
//! streams whatever the caller's memory policy says, because what it
//! buys there is a parse pipelined across member boundaries. A later rule
//! extended the reservation to a member of a NON-SOLID volume set larger
//! than one window, case (b), and the rule of 20 Sep narrowed the STREAMING of
//! such a member to one condition: the caller set a memory ceiling that
//! holding the member whole would pass. With no ceiling the member is
//! held whole, keeps the minimum-width field of spec G 3.5 rule 2 and
//! keeps `Run::compress`'s one-region shortcut, which is what gives the
//! default its lowest wall ("otherwise, use as much as we
//! need to"). A member of either kind of set that is one window or
//! smaller is untouched by any of the three rules, which
//! `the_walk_takes_only_the_members_over_one_window` is the row for.
//!
//! **What was holding the member, and why it was the last one.** A member
//! header's packed size field IS the length of the member's packed
//! output and the header goes down first, so the writer encoded the whole
//! member, kept the bytes, and then cut them into fragments. Every other
//! term of a write's working memory follows the OPTIONS - the encoder's
//! history, the blocks in flight, a batch's pending output, the copy
//! buffer, one window - and that one followed the ARCHIVE. A member that
//! fits a batch was already bounded at one window; a member larger than
//! one window was not bounded at all.
//!
//! **What closes it.** Spec G 3.5's reserved packed size field, whose
//! width does not follow the value, so a fragment's header can be laid
//! down before the fragment is filled and corrected where it lies once
//! it is - which needs a `VolumeOut` that can be written back over
//! (`VolumeOut::can_patch`), and a one-chunk look-ahead for the one thing
//! the correction still has to know in advance: whether the volume the
//! fragment filled was the member's last.
//!
//! **The control arm, and where it stopped being a byte for byte one.** A
//! `VolumeOut` that answers `can_patch` FALSE takes the member-at-a-time
//! walk, the one this engine had before this path existed. For case (a)
//! it still writes the same archive to the byte, and every solid row
//! below compares them; a difference there is a regression and not a
//! judgement call. For case (b) under a ceiling it does NOT, and spec G
//! 3.5 grants exactly that exception: a ceiling that
//! cannot be kept completes the job rather than failing it, in the project's
//! words "i dont like the idea of failing any job that other unrar tools
//! would be able to cope with", so an output that cannot patch holds the
//! member, writes the DEFAULT mode's bytes and reports the excess in
//! `WriteReport::ceiling_exceeded_by`. The five rows named
//! `ceiling_rule_*` and `report_rule_*` are spec G 3.5's own acceptance tests
//! for that.
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, MemoryPolicy, Payload, RangeSource, Rar4Version,
    ReadOptions, Result, Sink, VolumeNaming, VolumeOut, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};

/// Collects each member's name and bytes, in archive order.
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
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1 = bytes;
        }
        Ok(())
    }
}

/// Both arms of every row below, as ONE provider with the arm as data:
/// `patches` is the only thing that differs between them, and having the
/// two arms share every other line is what makes a byte for byte
/// comparison of their output say something.
///
/// `patches` true is the streamed walk. False is spec G 3.7.2's
/// fallback, which holds a HEADER and never a payload - so a writer with
/// nowhere to correct a field goes on producing each member's packed
/// bytes whole, which is the member-at-a-time walk this engine had
/// before the streamed one.
struct Arm {
    patches: bool,
    kept: Vec<Vec<u8>>,
}

impl Arm {
    fn new(patches: bool) -> Arm {
        Arm {
            patches,
            kept: Vec::new(),
        }
    }
}

impl VolumeOut for Arm {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, index: u32, volume: Vec<u8>) -> Result<()> {
        assert_eq!(index as usize, self.kept.len(), "volumes out of order");
        self.kept.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        self.patches
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// Reads a volume set back through this crate's own reader.
fn read_back(volumes: &[Vec<u8>]) -> Vec<Member> {
    read_back_with(volumes, None)
}

/// The same, for a set whose members are encrypted.
fn read_back_with(volumes: &[Vec<u8>], password: Option<rarkit::Password>) -> Vec<Member> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let options = ReadOptions::default().with_password(password);
    extract(sources, &options, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

/// The RAR 4 family refuses a filter REQUEST (SPEC-J).
fn filters_for(format: WriteFormat) -> rarkit::FilterPolicy {
    if matches!(format, WriteFormat::Rar4(_)) {
        rarkit::FilterPolicy::Off
    } else {
        rarkit::FilterPolicy::default()
    }
}

/// Bytes that do NOT compress, so the packed output is a little LARGER
/// than the input: the case spec G 3.5 leaves open, and the one that
/// tests the reservation's width rather than its existence.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// [`noise`] that spec G 3.8.3's samples do not call incompressible, so
/// that the member still reaches the ENCODER and every row below that
/// is about the packed walk keeps measuring it.
///
/// Since 28 Sep 2026 a non-solid member of 1 MiB and more whose samples
/// all fail to compress is written STORED (`src/write/store.rs`), and
/// plain [`noise`] is such a member
/// (`plain_noise_is_now_stored_and_so_reaches_no_encoder` pins that the
/// other way). This plants a run of 512 zero bytes in the middle of the
/// samples of the first five of the sixteen segments, which outvotes the
/// rule at every size (two do under 128 MiB; from 128 MiB four may compress
/// since 1 Oct 2026), and is 2.5 KiB of the member. What the rows here
/// need of the data is unchanged: the packed output is still about the
/// member's own size, and at 4 MiB and more still a little LARGER than
/// it (measured, level 1 at 128 KiB: +1,259 bytes RAR 5 and +1,229 RAR 4
/// at 4 MiB; at 1 MiB it is 454 bytes SMALLER, which is why the row that
/// needs "larger" uses 4 MiB).
fn lz_noise(len: usize, seed: u64) -> Vec<u8> {
    let mut out = noise(len, seed);
    let span = len.min(32 << 20);
    for segment in 0..5 {
        let middle = (2 * segment + 1) * span / 32;
        out[middle - 256..middle + 256].fill(0);
    }
    out
}

/// Bytes that compress by FAR more than 128-fold, so that the vint width
/// of the member's unpacked size is wider than the vint width of its
/// packed size.
///
/// That gap is what spec G 3.5's reservation actually costs - "the number
/// of 7-bit digits compression removed" - so it is the only shape in
/// which the two modes of case (b) differ in the FIELD rather than only
/// in the packed stream, and
/// `ceiling_rule_the_two_modes_differ_and_only_there` needs it for that.
fn flat(len: usize) -> Vec<u8> {
    vec![b'='; len]
}

/// The dictionary every row asks for. Small, so that "larger than one
/// window" is a member a test can afford: the window is the dictionary
/// clamped up to one parse block, which is 256 KiB.
const DICTIONARY: u64 = 128 << 10;

/// The window that dictionary gives, which is the size threshold spec G
/// 3.5 applies to case (a) and case (b) alike.
const WINDOW: usize = 256 << 10;

/// A ceiling so tight that holding ANY member over one window whole would
/// pass it, which is what puts every case (b) row below into streaming
/// mode whatever its member sizes are.
///
/// It is NOT a ceiling the streamed walk itself fits inside, and it is
/// not meant to be: `ceiling_rule_a_budgeted_write_is_bounded_and_accepted`
/// is the row that measures the fit, and it uses [`roomy`].
const TIGHT: u64 = 1 << 20;

/// Spec G 3.5's finder term for the chains of levels 1 to 3 (restated 28
/// Sep 2026), in bytes, for a run over `span` positions: 2^20 heads, fixed
/// at every dictionary, and a link a position over
/// `min(pow2(max(2 * D, 16 Mi)), pow2(max(span, 64 Ki)))` positions.
fn chains_term(dictionary: u64, span: u64) -> u64 {
    let links = (2 * dictionary)
        .max(16 << 20)
        .next_power_of_two()
        .min(span.max(1 << 16).next_power_of_two());
    4 * (1 << 20) + 4 * links
}

/// A ceiling the STREAMED walk fits inside and the held-whole write of
/// each member of [`ceiling_rule_a_budgeted_write_is_bounded_and_accepted`]
/// does not, computed from spec G 3.5's terms (acceptance test 2 as
/// restated 28 Sep 2026) rather than hard-coded.
///
/// The walk's bound is the dictionary, one window, and the finder over
/// the window and the history it carries (the dictionary and the four
/// dictionaries of slack a run slides at): at 128 KiB that is 896 KiB of
/// positions, 1 Mi links, 8 MiB of finder with the heads. The margin, 3
/// MiB, covers the walk's buffers (the copy buffer is 1 MiB alone). The
/// 3 MiB ceiling this row used before is below the heads alone.
///
/// Measured with the lead encoder counted: the walk held about 10.6
/// MiB with the finder unheld, 4.4 MiB once the ceiling holds it
/// (`Run::chosen_hold`).
fn roomy() -> u64 {
    const MARGIN: u64 = 3 << 20;
    let history = DICTIONARY * 5;
    DICTIONARY + WINDOW as u64 + chains_term(DICTIONARY, WINDOW as u64 + history) + MARGIN
}

/// A ceiling nothing here comes near: spec G 3.5's OTHER default-mode
/// caller, the one who named a ceiling that the held-whole write fits
/// inside and who therefore gets mode 1, exactly as a caller who named
/// none does.
const GENEROUS: u64 = 64 << 20;

/// A volume set's options, capped as a whole FILE or as payload, with the
/// memory ceiling the caller is to be read as having set.
///
/// `ceiling` is `None` for a caller who set none, which is
/// `MemoryPolicy::default` and which spec G 3.5 reads as no ceiling at
/// all; `Some(bytes)` is `MemoryPolicy::from_limit(bytes)`, which is the
/// spelling 3.5 names as a caller's own choice.
fn options_of(
    format: WriteFormat,
    cap: u64,
    file_budget: bool,
    solid: bool,
    ceiling: Option<u64>,
) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(DICTIONARY),
        },
        solid,
        // Ordering is not what this test is about: keep the add order.
        order: rarkit::MemberOrder::AsAdded,
        filters: filters_for(format),
        volume_size: (!file_budget).then_some(cap),
        volume_file_size: file_budget.then_some(cap),
        host_os: rarkit::HostOs::Unix,
        memory: ceiling.map_or_else(MemoryPolicy::default, MemoryPolicy::from_limit),
        ..WriteOptions::default()
    }
}

/// The solid form of [`options_of`] with no ceiling, which is what the
/// rows that do not vary the arm for themselves use.
fn options(format: WriteFormat, cap: u64, file_budget: bool) -> WriteOptions {
    options_of(format, cap, file_budget, true, None)
}

/// The two arms that STREAM, and what each of them needs to.
///
/// A SOLID set streams whatever the policy says. A
/// NON-SOLID one streams only under a caller's ceiling, so
/// its arm carries [`TIGHT`]. Running every row both ways is what says
/// the two cases share one walk; a difference between them is a finding.
fn arms() -> [(&'static str, bool, Option<u64>); 2] {
    [
        ("solid", true, None),
        ("non-solid/budgeted", false, Some(TIGHT)),
    ]
}

fn families() -> [(&'static str, WriteFormat); 2] {
    [
        ("rar5", WriteFormat::Rar5),
        ("rar4", WriteFormat::Rar4(Rar4Version::V29)),
    ]
}

/// Loads `writer` with `members`.
fn load<'a>(writer: &mut Writer<'a>, members: &'a [Member]) {
    for (name, data) in members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
}

/// Writes `members` to a PATCHABLE provider, which is the streamed walk's
/// arm. Answers the volumes, the report, and how many members took the
/// streamed walk.
fn streamed(
    options: WriteOptions,
    members: &[Member],
) -> (Vec<Vec<u8>>, rarkit::WriteReport, usize) {
    rarkit::internals::writers::reset_streamed_members();
    let mut writer = Writer::new(options).expect("options");
    load(&mut writer, members);
    let mut out = Arm::new(true);
    let report = writer.finish_volumes(&mut out).expect("finish_volumes");
    let took = rarkit::internals::writers::streamed_members();
    (out.kept, report, took)
}

/// The same members to a provider that cannot be patched, which is the
/// member-at-a-time walk's arm.
fn held_whole(options: WriteOptions, members: &[Member]) -> (Vec<Vec<u8>>, rarkit::WriteReport) {
    let mut writer = Writer::new(options).expect("options");
    load(&mut writer, members);
    let mut out = Arm::new(false);
    let report = writer.finish_volumes(&mut out).expect("finish_volumes");
    (out.kept, report)
}

/// Runs `work` on a pool of its own, one thread wide, which is where a
/// row that compares two runs' `peak_working_memory` takes its figures.
///
/// **Why a comparison of two peaks needs it.** One term of the peak is
/// the encoder's parse scratches (`Encoder::flight_bytes`), and a parse
/// builds a scratch only when none is free, so that term counts the most
/// blocks that were parsed AT ONCE: a figure of the scheduler, not of the
/// member. On the process's global pool, which every test of this binary
/// shares under `cargo test`, a member with few parse waves can run them
/// narrower than the pool while other tests hold its threads, and reads
/// low. On 30 Sep 2026 a sharded `make ci` on an M1 Mac read the 1 MiB
/// member of `what_a_streamed_member_holds_does_not_follow_the_member`
/// at 12,983,857 bytes against a steady 15,083,497 for BOTH members, and
/// failed the row on a baseline about 2 MiB short. On one thread of
/// its own a write parses one block at a time, holds one scratch, and
/// shares the pool with nothing, so each figure is its own member's on
/// every run and under any load.
fn one_thread<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    rarkit::internals::rar20::on_threads(1, work)
}

/// One member as this file describes it: a name and its bytes.
type Member = (Vec<u8>, Vec<u8>);

/// The shapes this file writes. Each has at least one member larger than
/// one window, which is what takes the streamed walk.
fn shapes() -> Vec<(&'static str, Vec<Member>)> {
    vec![
        (
            // The plain case: one long member between two short ones, so
            // the run carries in and out of it.
            "long-in-a-run",
            vec![
                (b"head.txt".to_vec(), rarkit_testdata::chatter(1, 5_000)),
                (b"long.txt".to_vec(), rarkit_testdata::chatter(2, 2 << 20)),
                (b"tail.txt".to_vec(), rarkit_testdata::chatter(3, 6_500)),
            ],
        ),
        (
            // Two long members in a row, so the second starts from a
            // history the first carried over a volume boundary.
            "two-long",
            vec![
                (b"one.txt".to_vec(), rarkit_testdata::chatter(4, 1_500_000)),
                (b"two.txt".to_vec(), rarkit_testdata::chatter(5, 1_200_000)),
            ],
        ),
        (
            // A member that does not compress, whose packed output is
            // LARGER than its input: spec G 3.5's open point about the
            // reservation's width, on the path that cannot widen it.
            // 4 MiB of [`lz_noise`], the least that is both encoded
            // (spec G 3.8.3 stores plain noise) and still larger packed.
            "incompressible",
            vec![
                (b"head.txt".to_vec(), rarkit_testdata::chatter(6, 3_000)),
                (b"noise.bin".to_vec(), lz_noise(4 << 20, 7)),
                (b"tail.txt".to_vec(), rarkit_testdata::chatter(8, 4_000)),
            ],
        ),
        (
            // A long member last, so its final fragment closes the set.
            "long-last",
            vec![
                (b"a.txt".to_vec(), rarkit_testdata::chatter(9, 7_000)),
                (b"b.txt".to_vec(), rarkit_testdata::chatter(10, 900_000)),
            ],
        ),
    ]
}

/// The claim, for case (a) to the byte and for case (b) as far as the
/// report rule leaves it: the streamed walk writes a valid archive of the same
/// members, and the walk that cannot patch writes the archive the DEFAULT
/// mode writes.
#[test]
fn the_streamed_walk_writes_the_same_archive_as_the_walk_that_held_it() {
    for (family, format) in families() {
        for (how, solid, ceiling) in arms() {
            for (label, members) in shapes() {
                for file_budget in [false, true] {
                    for cap in [70_000u64, 250_000, 900_000] {
                        let want = options_of(format, cap, file_budget, solid, ceiling);
                        let (theirs, report, took) = streamed(want, &members);
                        assert!(
                            took > 0,
                            "{family}/{how}/{label}: no member took the streamed walk at cap \
                             {cap} (file budget {file_budget}), so this row measured nothing"
                        );
                        assert_eq!(
                            report.held_volume_bytes, 0,
                            "{family}/{how}/{label}: the streamed walk held bytes, and it patches"
                        );
                        let (control, _) = held_whole(
                            options_of(format, cap, file_budget, solid, ceiling),
                            &members,
                        );
                        if solid {
                            // Case (a). The ceiling condition did not touch it, and
                            // the two outputs still write one archive.
                            assert_eq!(
                                theirs, control,
                                "{family}/{how}/{label}: the streamed walk moved a byte at cap \
                                 {cap} (file budget {file_budget})"
                            );
                        } else {
                            // Case (b) under a ceiling. The output that
                            // cannot patch writes the DEFAULT mode's
                            // bytes, which is the rule's whole answer,
                            // and the archive is finished rather than
                            // refused.
                            let (plain, _) = held_whole(
                                options_of(format, cap, file_budget, solid, None),
                                &members,
                            );
                            assert_eq!(
                                control, plain,
                                "{family}/{how}/{label}: a ceiling changed the bytes of an \
                                 output that cannot patch, and the rule is that it writes what \
                                 the default writes"
                            );
                            assert_eq!(
                                read_back(&control),
                                members,
                                "{family}/{how}/{label}: the held-whole set did not read back"
                            );
                        }
                        assert_eq!(
                            read_back(&theirs),
                            members,
                            "{family}/{how}/{label}: the streamed set did not read back at \
                             cap {cap}"
                        );
                        if file_budget {
                            for (index, volume) in theirs.iter().enumerate() {
                                assert!(
                                    volume.len() as u64 <= cap,
                                    "{family}/{how}/{label}: volume {index} is {} bytes \
                                     against a {cap} byte file cap",
                                    volume.len()
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The pipelining depth and the thread count are not inputs to the
/// archive on this walk either (SPEC-API 2.6, spec G 3.9).
#[test]
fn the_streamed_walk_is_the_same_archive_at_every_depth_and_width() {
    let (_, members) = shapes().swap_remove(0);
    for (family, format) in families() {
        let control = rarkit::internals::writers::with_batch_depth(1, || {
            streamed(options(format, 250_000, true), &members).0
        });
        for depth in [2usize, 4, 32] {
            let theirs = rarkit::internals::writers::with_batch_depth(depth, || {
                streamed(options(format, 250_000, true), &members).0
            });
            assert_eq!(
                theirs, control,
                "{family}: depth {depth} moved a byte of a streamed member"
            );
        }
        for threads in [1usize, 2, 8] {
            let theirs = rarkit::internals::rar20::on_threads(threads, || {
                streamed(options(format, 250_000, true), &members).0
            });
            assert_eq!(
                theirs, control,
                "{family}: {threads} threads moved a byte of a streamed member"
            );
        }
    }
}

/// **The point of the change, as a figure.** The streamed walk's working
/// memory does not follow the member, and the walk that holds the member
/// whole does - which is the control that says this row is measuring the
/// thing it names and not the weather.
///
/// Every figure is taken on [`one_thread`], so that neither of a pair
/// reads the scheduler instead of its member.
#[test]
fn what_a_streamed_member_holds_does_not_follow_the_member() {
    /// How far apart two figures may be and still count as the same. One
    /// parse block, which is the grain the buffers below grow in.
    const SAME: u64 = 256 << 10;

    for (family, format) in families() {
        for (how, solid, ceiling) in arms() {
            let mut streams = Vec::new();
            let mut holds = Vec::new();
            for length in [1 << 20usize, 4 << 20] {
                // Incompressible, so the packed output really is the
                // member's size and the volumes really are many: a member
                // that compresses away measures nothing here.
                let members: Vec<Member> = vec![
                    (b"head.txt".to_vec(), rarkit_testdata::chatter(11, 4_000)),
                    (b"long.bin".to_vec(), lz_noise(length, 12)),
                ];
                let want = options_of(format, 200_000, true, solid, ceiling);
                let (volumes, report, took) = one_thread(|| streamed(want, &members));
                assert!(took > 0, "{family}/{how}: the long member did not stream");
                assert!(volumes.len() > 1, "{family}/{how}: not a set");
                let (_, control) = one_thread(|| {
                    held_whole(options_of(format, 200_000, true, solid, ceiling), &members)
                });
                eprintln!(
                    "{family}/{how}: a {length} byte member over {} volumes: streamed {} bytes, \
                 held whole {} bytes",
                    volumes.len(),
                    report.peak_working_memory,
                    control.peak_working_memory
                );
                streams.push(report.peak_working_memory);
                holds.push(control.peak_working_memory);
            }
            let (small, large) = (streams[0], streams[1]);
            assert!(
                large <= small + SAME,
                "{family}/{how}: a member four times the size streamed {large} bytes against \
             {small}, so the walk is still following the member"
            );
            assert!(
                holds[1] > holds[0] + SAME,
                "{family}/{how}: the walk that HOLDS the member whole held {} bytes for a member \
             four times the size of one it held {} for, so this row is no longer measuring \
             the difference it names",
                holds[1],
                holds[0]
            );
            assert!(
                large + SAME < holds[1],
                "{family}/{how}: the streamed walk held {large} bytes against the whole walk's \
             {}, which is not the saving this path exists for",
                holds[1]
            );
        }
    }
}

/// A member from a READER takes the walk too, and its unpacked checksum
/// is still checked against the one the caller stated (spec G 3.7.2).
#[test]
fn a_reader_payload_streams_and_is_still_checked() {
    let body = rarkit_testdata::chatter(13, 1 << 20);
    let crc = rarkit::checksum::crc32(&body);
    for (family, format) in families() {
        for (how, solid, ceiling) in arms() {
            for stated in [Some(crc), None] {
                rarkit::internals::writers::reset_streamed_members();
                let mut source = std::io::Cursor::new(body.clone());
                let mut writer = Writer::new(options_of(format, 200_000, true, solid, ceiling))
                    .expect("options");
                writer
                    .add(MemberSpec {
                        name: b"streamed.bin",
                        payload: Payload::Reader {
                            reader: &mut source,
                            size: body.len() as u64,
                            crc32: stated,
                        },
                        mtime: None,
                        attributes: 0,
                        host_os: rarkit::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
                let mut out: Vec<Vec<u8>> = Vec::new();
                writer.finish_volumes(&mut out).expect("finish_volumes");
                assert_eq!(
                    rarkit::internals::writers::streamed_members(),
                    1,
                    "{family}/{how}: a reader's long member did not stream"
                );
                let got = read_back(&out);
                assert_eq!(got.len(), 1);
                assert_eq!(
                    got[0].1, body,
                    "{family}/{how}: the streamed bytes came back wrong"
                );
            }

            // A stated CRC32 that is WRONG is still caught, over the UNPACKED
            // bytes, which this walk hashes as the windows pass.
            let mut source = std::io::Cursor::new(body.clone());
            let mut writer =
                Writer::new(options_of(format, 200_000, true, solid, ceiling)).expect("options");
            writer
                .add(MemberSpec {
                    name: b"streamed.bin",
                    payload: Payload::Reader {
                        reader: &mut source,
                        size: body.len() as u64,
                        crc32: Some(crc ^ 1),
                    },
                    mtime: None,
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
            let mut out: Vec<Vec<u8>> = Vec::new();
            let answer = writer.finish_volumes(&mut out);
            assert!(
                answer.is_err(),
                "{family}/{how}: a wrong stated CRC32 passed the streamed walk"
            );
        }
    }
}

/// One READER member written with `options` as a volume set, and the set,
/// the report and what reads back.
fn reader_member(
    options: WriteOptions,
    body: &[u8],
) -> (Vec<Vec<u8>>, rarkit::WriteReport, Vec<Member>) {
    let mut source = std::io::Cursor::new(body.to_vec());
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"head.bin",
            payload: Payload::Reader {
                reader: &mut source,
                size: body.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Arm::new(true);
    let report = writer.finish_volumes(&mut out).expect("finish_volumes");
    let back = read_back(&out.kept);
    (out.kept, report, back)
}

/// **Under a caller's ceiling the budget counts the head the store rule's
/// samples hold of a reader member** (spec G 3.5, "what the budget counts
/// for the head", and its acceptance tests 1 to 3; decided
/// 1 Oct 2026). The term is the COMMON-CASE head,
/// that of a member whose leading samples compress: for a member of 128
/// MiB and more the vote settles at the fifth compressible sample, 9/32
/// of the span and half a sample, and under `store_one_miss` (and for
/// every smaller member) at the second, 3/32.
///
/// 1. A ceiling of the walk's own terms and that head holds such a member
///    inside it, under the default rule and under the option.
/// 2. It is not a bound: a member whose first eleven samples are
///    incompressible and whose last five compress is settled at its last
///    sample, on a head of nearly the whole span, and passes the same
///    ceiling by at most the span less the counted head, which is
///    REPORTED (`ceiling_exceeded_by`) and never refused: the set is finished and reads back.
/// 3. The head is given up as it is served, so test 1's member peaks
///    BELOW the walk's sum plus its whole head.
#[test]
fn a_ceiling_counts_the_common_sampled_head_and_reports_a_late_settling_member() {
    const SAMPLE: usize = 64 << 10;
    // (the rule, the member's size, the option, the settling sample's
    // thirty-seconds of the span, the first segment of the late member
    // that compresses): four misses from 128 MiB, eleven incompressible
    // samples and then five; one miss under the option, the same member;
    // and one miss under 128 MiB, fourteen and then two. A reader's span
    // is its first 32 MiB.
    let rows = [
        (
            "four misses at 128 MiB",
            128usize << 20,
            false,
            9usize,
            11usize,
        ),
        ("the option at 128 MiB", 128 << 20, true, 3, 11),
        ("one miss at 8 MiB", 8 << 20, false, 3, 14),
    ];
    for (family, format) in families() {
        for (rule, len, one_miss, settles, late_from) in rows {
            // The opening compresses: `lz_noise` plants the first five
            // samples.
            let early = lz_noise(len, 31);
            let span = len.min(32 << 20);
            let mut late = noise(len, 32);
            for segment in late_from..16 {
                let middle = (2 * segment + 1) * span / 32;
                late[middle - 256..middle + 256].fill(0);
            }
            let common_head = (settles * span / 32 + SAMPLE / 2) as u64;
            let ceiling = roomy() + common_head;
            let options = || WriteOptions {
                store_one_miss: one_miss,
                ..options_of(format, 4 << 20, true, false, Some(ceiling))
            };
            let what = format!("{family}, {rule}");

            let (_, report, back) = reader_member(options(), &early);
            assert_eq!(
                report.ceiling_exceeded_by, None,
                "{what}: a member settled at its leading samples passed a ceiling that \
                 affords its head ({} bytes held against {ceiling})",
                report.peak_working_memory
            );
            assert!(
                report.peak_working_memory < ceiling,
                "{what}: {} bytes held, the walk's sum and the whole head ({ceiling})",
                report.peak_working_memory
            );
            assert!(back.len() == 1 && back[0].1 == early, "{what}: early");

            let (volumes, report, back) = reader_member(options(), &late);
            let over = report
                .ceiling_exceeded_by
                .unwrap_or_else(|| panic!("{what}: a head of the whole span went unreported"));
            assert!(
                over > 0 && over <= span as u64 - common_head,
                "{what}: over by {over} bytes, more than the span less the counted head"
            );
            assert!(volumes.len() > 1, "{what}: not a set");
            assert!(back.len() == 1 && back[0].1 == late, "{what}: late");
        }
    }
}

/// A reader that refuses its first read. The hold is chosen when the
/// write is built, before any member is read, so a write of such a member
/// fails at once and has still made its choice.
struct Refuses;

impl std::io::Read for Refuses {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "the hold is chosen before any member is read",
        ))
    }
}

/// The options of the two tests of the hold: level 1 at a 2 MiB
/// dictionary, where the lead's chains can be held to a window or a parse
/// block, a non-solid volume set under `ceiling`.
fn hold_options(ceiling: u64, one_miss: bool) -> WriteOptions {
    WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(2 << 20),
        },
        store_one_miss: one_miss,
        ..options_of(WriteFormat::Rar5, 8 << 20, true, false, Some(ceiling))
    }
}

/// The hold the writer CHOOSES for one reader member of `len` declared
/// bytes under `ceiling`: `None` is unheld, the widest. Read through the
/// test seam (`internals::writers::last_chosen_hold`); no member byte is
/// read or encoded.
fn chosen_hold(ceiling: u64, one_miss: bool, len: u64) -> Option<usize> {
    let mut source = Refuses;
    let mut writer = Writer::new(hold_options(ceiling, one_miss)).expect("options");
    writer
        .add(MemberSpec {
            name: b"head.bin",
            payload: Payload::Reader {
                reader: &mut source,
                size: len,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Arm::new(true);
    assert!(
        writer.finish_volumes(&mut out).is_err(),
        "a member that cannot be read was written"
    );
    rarkit::internals::writers::last_chosen_hold().expect("a write was built on this thread")
}

/// The least ceiling, to the byte, at which the writer takes its widest
/// hold for that member.
fn widest_from(one_miss: bool, len: u64) -> u64 {
    const MIB: u64 = 1 << 20;
    // Far above the streamed walk at its widest hold and still under what
    // holding the member whole would take; and under any hold but the
    // narrowest.
    let (mut below, mut at) = (48 * MIB, 120 * MIB);
    assert!(
        chosen_hold(below, one_miss, len).is_some() && chosen_hold(at, one_miss, len).is_none(),
        "one_miss={one_miss}, {len} bytes: the widest hold is not chosen between {below} and {at}"
    );
    while at - below > 1 {
        let middle = below + (at - below) / 2;
        if chosen_hold(middle, one_miss, len).is_none() {
            at = middle;
        } else {
            below = middle;
        }
    }
    at
}

/// **The budget takes a named ceiling less the common-case head** (spec G
/// 3.5, "what the budget COUNTS for the head"; tested
/// 1 Oct 2026 and restated the same day). The hold a write takes under a caller's ceiling is
/// CHOSEN when the write is built, from the options and the member table,
/// and this reads the choice itself.
///
/// For a reader member of 128 MiB the counted head is 9/32 of its 32 MiB
/// span and half a sample under the default rule and 3/32 and half a
/// sample under `store_one_miss`: 6 MiB apart. Nothing else differs
/// between the two, so the least ceiling at which the widest hold is
/// chosen is EXACTLY 6,291,456 bytes higher under the default rule: the
/// head is what the chooser took off, to the byte. One byte under 128 MiB
/// the size gate gives both rules the 3/32 head and the two ceilings are
/// the same. A writer that counted no head would give one ceiling for all
/// four.
///
/// **Why it does not time anything.** As first written this row bisected
/// over `peak_working_memory`, a high-water mark of what the threads held,
/// which moves from run to run with their timing: on a 16-thread box at
/// load 3 to 5 the two searches landed on different steps and the row
/// failed two runs in three (a 32-core box passed every time). The peak is
/// not the choice. The row below holds what a WRITE must hold; this one
/// holds the arithmetic.
#[test]
fn the_budget_takes_the_ceiling_less_the_common_case_head() {
    const GATE: u64 = 128 << 20;
    const SPAN: u64 = 32 << 20;
    let default = widest_from(false, GATE);
    let option = widest_from(true, GATE);
    assert_eq!(
        default - option,
        (9 - 3) * SPAN / 32,
        "the widest hold from a ceiling of {default} under four misses and {option} under \
         one: not the bytes between their heads"
    );
    // The same ceiling asked twice is the same choice: nothing here runs.
    assert_eq!(default, widest_from(false, GATE));
    // Under the gate both rules count the 3/32 head.
    let under = widest_from(false, GATE - 1);
    assert_eq!(under, widest_from(true, GATE - 1));
    // And at a ceiling between the two, the default rule has narrowed and
    // the option has not.
    let between = option + (default - option) / 2;
    assert!(chosen_hold(between, false, GATE).is_some());
    assert!(chosen_hold(between, true, GATE).is_none());
}

/// **Counting the head NARROWS the hold, inside a ceiling that names no
/// head, and the hold moves no byte.** A 128 MiB reader member whose
/// opening compresses, written for real under two ceilings: one far above
/// the walk at its widest hold, and one a byte under the least ceiling
/// that gets the widest hold (`widest_from`), where the chooser has taken
/// a narrower one because the head would not fit beside the wide one.
/// Both writes keep their ceiling, the member reads back, and the two
/// archives are the same bytes. What each HELD at its peak is not compared
/// with anything but its own ceiling: that figure follows the threads.
#[test]
fn counting_the_head_narrows_the_hold_inside_a_ceiling_that_names_no_head() {
    const LEN: usize = 128 << 20;
    const FAR_ABOVE: u64 = 120 << 20;
    let body = lz_noise(LEN, 33);
    let just_under = widest_from(false, LEN as u64) - 1;
    let mut archives = Vec::new();
    for (ceiling, widest) in [(FAR_ABOVE, true), (just_under, false)] {
        let (set, report, back) = reader_member(hold_options(ceiling, false), &body);
        let hold = rarkit::internals::writers::last_chosen_hold()
            .expect("a write was built on this thread");
        if std::env::var_os("HOLD_TEST_PRINT").is_some() {
            eprintln!(
                "HOLD ceiling {ceiling} hold {hold:?} peak {}",
                report.peak_working_memory
            );
        }
        assert_eq!(
            hold.is_none(),
            widest,
            "{ceiling}: the hold chosen was {hold:?}"
        );
        assert_eq!(
            report.ceiling_exceeded_by, None,
            "{} bytes held against a ceiling of {ceiling}",
            report.peak_working_memory
        );
        assert!(back.len() == 1 && back[0].1 == body, "{ceiling}");
        archives.push(set);
    }
    assert!(archives[0] == archives[1], "the hold moved a byte");
}

/// **Scope.** Nothing outside a VOLUME SET over a patchable output takes
/// this walk, and inside one only a member larger than ONE WINDOW does,
/// which is what keeps every other archive's bytes where they were.
///
/// Since 20 Sep 2026 there is one more condition, and it is the last row
/// here: a NON-SOLID set with no caller's ceiling does not stream at all,
/// whatever the member's size and whatever the output can do.
#[test]
fn only_a_volume_set_over_a_patchable_output_streams() {
    let members: Vec<Member> = vec![(b"long.txt".to_vec(), rarkit_testdata::chatter(14, 1 << 20))];
    for (family, format) in families() {
        for (how, solid, ceiling) in arms() {
            // A single archive: no cap, so no bound on a fragment.
            rarkit::internals::writers::reset_streamed_members();
            let mut writer = Writer::new(WriteOptions {
                format,
                method: WriteMethod::Compressed {
                    level: 1,
                    dictionary: Some(DICTIONARY),
                },
                solid,
                // Ordering is not what this test is about: keep the add order.
                order: rarkit::MemberOrder::AsAdded,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                memory: ceiling.map_or_else(MemoryPolicy::default, MemoryPolicy::from_limit),
                ..WriteOptions::default()
            })
            .expect("options");
            load(&mut writer, &members);
            let mut out = Vec::new();
            writer.finish_into(&mut out).expect("finish_into");
            assert_eq!(
                rarkit::internals::writers::streamed_members(),
                0,
                "{family}/{how}: a single archive streamed, and nothing bounds a fragment there"
            );

            // An output that cannot be patched.
            rarkit::internals::writers::reset_streamed_members();
            let mut writer =
                Writer::new(options_of(format, 200_000, true, solid, ceiling)).expect("options");
            load(&mut writer, &members);
            let mut out = Arm::new(false);
            writer.finish_volumes(&mut out).expect("finish_volumes");
            assert_eq!(
                rarkit::internals::writers::streamed_members(),
                0,
                "{family}/{how}: an unpatchable output streamed, and it has nowhere to correct"
            );

            // An ENCRYPTED member, whose last fragment's data area is the
            // cipher's padded length rather than the room it was given. It
            // was held whole until 28 Sep 2026, which this row pinned as
            // open; it now streams, cut where the held walk cuts it
            // (`tests/streamed_encrypted.rs` holds the two walks to the
            // byte), and reads back.
            rarkit::internals::writers::reset_streamed_members();
            let mut sealed = options_of(format, 200_000, true, solid, ceiling);
            sealed.password = Some(rarkit::Password::new("streamed"));
            let mut writer = Writer::new(sealed).expect("options");
            load(&mut writer, &members);
            let mut out: Vec<Vec<u8>> = Vec::new();
            writer.finish_volumes(&mut out).expect("finish_volumes");
            assert!(
                rarkit::internals::writers::streamed_members() > 0,
                "{family}/{how}: an encrypted member over a patchable output did not stream"
            );
            assert_eq!(
                read_back_with(&out, Some(rarkit::Password::new("streamed"))),
                members,
                "{family}/{how}: the encrypted streamed set read back"
            );
        }

        // A NON-SOLID set with no ceiling holds its member
        // whole, which is the default the rule of 20 Sep 2026 restored; since
        // 28 Sep 2026 that is so for a member whose held packed
        // bound is under `DEFAULT_LIMIT`, as every member here is
        // (`tests/stream_default.rs` has the members above it).
        let (_, _, took) = streamed(options_of(format, 200_000, true, false, None), &members);
        assert_eq!(
            took, 0,
            "{family}: a non-solid set streamed with no ceiling set, and the rule is that the \
             default holds the member"
        );
    }
}

/// **The window is the threshold, in a non-solid set as in a solid one**
/// (spec G 3.5's exception, "which members", cases (a) and (b)).
///
/// A set of members that are each one window or smaller streams NOTHING,
/// which is what "every smaller member is unchanged" means on this walk:
/// those members keep the minimum-width packed size field of rule 2 and
/// the one-region encode `Run::compress` gives them, and a set holding
/// one member over the window streams that member and no other. A ceiling
/// does not move the threshold: the ceiling is a SECOND
/// condition on case (b), never a replacement for the size one.
#[test]
fn the_walk_takes_only_the_members_over_one_window() {
    let small: Vec<Member> = vec![
        (b"a.txt".to_vec(), rarkit_testdata::chatter(40, 60_000)),
        (b"b.txt".to_vec(), rarkit_testdata::chatter(41, WINDOW)),
        (b"c.txt".to_vec(), rarkit_testdata::chatter(42, 60_000)),
    ];
    let mut mixed = small.clone();
    mixed.insert(
        2,
        (
            b"long.txt".to_vec(),
            rarkit_testdata::chatter(43, WINDOW + 1),
        ),
    );

    for (family, format) in families() {
        for (how, solid, ceiling) in arms() {
            let want = options_of(format, 200_000, true, solid, ceiling);
            let (volumes, report, took) = streamed(want, &small);
            assert_eq!(
                took, 0,
                "{family}/{how}: a member one window or smaller streamed, and none of the three \
                 streaming rules reaches it"
            );
            assert_eq!(report.held_volume_bytes, 0);
            let (control, _) =
                held_whole(options_of(format, 200_000, true, solid, ceiling), &small);
            assert_eq!(
                volumes, control,
                "{family}/{how}: a set of small members moved a byte between the two outputs"
            );
            assert_eq!(
                read_back(&volumes),
                small,
                "{family}/{how}: the small set read back"
            );

            let (volumes, _, took) =
                streamed(options_of(format, 200_000, true, solid, ceiling), &mixed);
            assert_eq!(
                took, 1,
                "{family}/{how}: {took} members streamed where exactly one is over the window"
            );
            assert_eq!(
                read_back(&volumes),
                mixed,
                "{family}/{how}: the mixed set read back"
            );
            if solid {
                let (control, _) =
                    held_whole(options_of(format, 200_000, true, solid, ceiling), &mixed);
                assert_eq!(
                    volumes, control,
                    "{family}/{how}: the mixed set moved a byte between the two outputs"
                );
            }
        }
    }
}

/// An inline recovery record is computed over the volume's bytes AS THEY
/// FINALLY STAND (spec G 3.11 and SPEC-L 3.5.1), so a walk that corrects
/// a header where it lies has to correct the copy the record is folded
/// over too. This row is the one that would notice if it did not.
#[test]
fn a_streamed_set_carries_an_inline_recovery_record() {
    let members = vec![
        (b"head.txt".to_vec(), rarkit_testdata::chatter(30, 3_000)),
        (b"long.bin".to_vec(), lz_noise(1 << 20, 31)),
        (b"tail.txt".to_vec(), rarkit_testdata::chatter(32, 5_000)),
    ];
    // The RAR 4 family refuses a recovery record on a split set
    // (spec G 3.11), so this is a RAR 5 row.
    for (how, solid, ceiling) in arms() {
        let mut want = options_of(WriteFormat::Rar5, 300_000, true, solid, ceiling);
        want.recovery_percent = Some(5);
        let (volumes, report, took) = streamed(want, &members);
        assert!(took > 0, "{how}: nothing streamed");
        assert_eq!(report.held_volume_bytes, 0);
        assert!(volumes.len() > 1, "{how}: not a set");
        for (index, volume) in volumes.iter().enumerate() {
            assert!(
                volume.len() <= 300_000,
                "{how}: volume {index} is {} bytes against a 300,000 byte cap",
                volume.len()
            );
        }
        assert_eq!(
            read_back(&volumes),
            members,
            "{how}: the recovered set read back"
        );

        // Every streamed volume's record agrees with the volume as it
        // finally stands: every slice of every group checks clean. That is
        // what a walk correcting headers where they lie must keep true.
        for (index, volume) in volumes.iter().enumerate() {
            let check = rarkit::recovery::check_inline(volume, &ReadOptions::default())
                .unwrap_or_else(|e| panic!("{how}: volume {index}'s record: {e}"));
            for group in &check.groups {
                assert!(
                    group.rows > 0 && group.damaged.is_empty(),
                    "{how}: volume {index} group at {}: {group:?}",
                    group.offset
                );
            }
        }

        // The held-whole control writes to an output that cannot patch,
        // which carries no recovery locator (spec G 3.11), so
        // its volumes are not the streamed set's bytes: a capped volume
        // with a locator splits a few bytes earlier. It must still read
        // back as the same members.
        let mut control = options_of(WriteFormat::Rar5, 300_000, true, solid, ceiling);
        control.recovery_percent = Some(5);
        let (held, _) = held_whole(control, &members);
        assert_eq!(
            read_back(&held),
            members,
            "{how}: the held-whole set with a recovery record read back"
        );
    }
}

/// The old engine and the reference binaries all read a streamed set.
///
/// BOTH reference binaries test it: `unrar t` and `rar t` are separate
/// programs and a set that one accepts is not thereby a set the other
/// does, which is why this row runs each where it is installed and says
/// so when it is not. It is also spec G 3.5's acceptance test 2 in its
/// "passes reference `rar t` and `unrar t` and extracts to the input"
/// half, for the budgeted arm as much as the solid one.
#[test]
fn the_old_engine_and_reference_unrar_read_a_streamed_set() {
    let reference = std::process::Command::new("unrar")
        .output()
        .ok()
        .map(|_| "unrar");
    if reference.is_none() {
        eprintln!("SKIPPED the reference arm: unrar is not on PATH");
    } else {
        eprintln!("the reference arm: unrar IS on PATH");
    }
    let packer = std::process::Command::new("rar")
        .output()
        .ok()
        .map(|_| "rar");
    if packer.is_none() {
        eprintln!("SKIPPED the `rar t` arm: rar is not on PATH");
    } else {
        eprintln!("the `rar t` arm: rar IS on PATH");
    }
    let root = std::env::temp_dir().join(format!("rarkit-streamed-{}", std::process::id()));
    for (family, format) in families() {
        for (how, solid, ceiling) in arms() {
            for (label, members) in shapes() {
                let want = options_of(format, 200_000, true, solid, ceiling);
                let (volumes, _, took) = streamed(want, &members);
                assert!(took > 0, "{family}/{how}/{label}: nothing streamed");

                #[cfg(feature = "oracle-compare")]
                {
                    let borrowed: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
                    match rarkit_oracle::extract(&borrowed, None) {
                        Ok(old) => {
                            let got: Vec<Vec<u8>> = old.into_iter().map(|m| m.data).collect();
                            let want: Vec<Vec<u8>> = members.iter().map(|m| m.1.clone()).collect();
                            assert_eq!(
                                got, want,
                                "{family}/{how}/{label}: the old engine read this set back differently"
                            );
                        }
                        Err(e) => {
                            panic!("{family}/{how}/{label}: the old engine refused this set: {e:?}")
                        }
                    }
                }

                if reference.is_none() && packer.is_none() {
                    continue;
                }
                let dir = root.join(format!("{family}-{how}-{label}").replace('/', "-"));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let total = volumes.len() as u32;
                for (index, volume) in volumes.iter().enumerate() {
                    let name = rarkit::volume_file_name(
                        "set",
                        index as u32,
                        total,
                        VolumeNaming::Numbered,
                    );
                    std::fs::write(dir.join(name), volume).unwrap();
                }
                let first = dir.join(rarkit::volume_file_name(
                    "set",
                    0,
                    total,
                    VolumeNaming::Numbered,
                ));
                for tester in [reference, packer].into_iter().flatten() {
                    let out = std::process::Command::new(tester)
                        .arg("t")
                        .arg("-inul")
                        .arg(&first)
                        .output()
                        .unwrap_or_else(|e| panic!("{tester} t: {e}"));
                    assert!(
                        out.status.success(),
                        "{family}/{how}/{label}: {tester} t exited {:?}\n{}",
                        out.status.code(),
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                let Some(unrar) = reference else {
                    let _ = std::fs::remove_dir_all(&dir);
                    continue;
                };
                let out = std::process::Command::new(unrar)
                    .arg("x")
                    .arg("-inul")
                    .arg("-y")
                    .arg(&first)
                    .current_dir(&dir)
                    .output()
                    .expect("unrar x");
                assert!(
                    out.status.success(),
                    "{family}/{how}/{label}: unrar x exited {:?}\n{}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                );
                for (name, data) in &members {
                    let path = dir.join(String::from_utf8(name.clone()).unwrap());
                    let got = std::fs::read(&path)
                        .unwrap_or_else(|e| panic!("{family}/{how}/{label}: {path:?}: {e}"));
                    assert_eq!(
                        &got, data,
                        "{family}/{how}/{label}: reference unrar extracted {name:?} differently"
                    );
                }
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------
// Spec G 3.5's five acceptance tests for the ceiling condition, and the report rule's.
// ---------------------------------------------------------------------

/// **Acceptance test 1: the default mode is what `main` writes.**
///
/// With no memory ceiling set, and with a ceiling the held-whole write
/// fits inside, no member of a non-solid volume set streams, and the
/// archive is the same whatever the output can do.
///
/// Spec G 3.5 puts this as byte identity with an earlier revision. A test
/// inside the tree cannot hold another commit's bytes, so what it checks
/// is the property that made those bytes what they were: case (b) is
/// inert, so the patchable and the non-patchable output agree to the
/// byte, exactly as they did before case (b) was built, and no packed
/// size field is reserved because `Run::packed_reserve` never reaches
/// case (b). The wall half of that acceptance test is a bench leg and is
/// not here.
#[test]
fn ceiling_rule_the_default_mode_is_the_archive_the_two_outputs_agree_on() {
    for (family, format) in families() {
        for (label, members) in shapes() {
            for cap in [70_000u64, 250_000, 900_000] {
                let mut seen: Option<Vec<Vec<u8>>> = None;
                for ceiling in [None, Some(GENEROUS)] {
                    let named = ceiling.map_or("none".to_string(), |c| c.to_string());
                    let (volumes, report, took) =
                        streamed(options_of(format, cap, true, false, ceiling), &members);
                    assert_eq!(
                        took, 0,
                        "{family}/{label}: a member streamed at cap {cap} with ceiling {named}, \
                         and the rule holds it whole unless the ceiling would be passed"
                    );
                    assert_eq!(
                        report.ceiling_exceeded_by, None,
                        "{family}/{label}: a ceiling of {named} was reported passed, and the \
                         held-whole write fits inside it"
                    );
                    let (control, _) =
                        held_whole(options_of(format, cap, true, false, ceiling), &members);
                    assert_eq!(
                        volumes, control,
                        "{family}/{label}: the two outputs disagreed at cap {cap} with ceiling \
                         {named}, and in the default mode nothing depends on patching"
                    );
                    assert_eq!(read_back(&volumes), members, "{family}/{label}: read back");
                    match &seen {
                        None => seen = Some(volumes),
                        Some(first) => assert_eq!(
                            first, &volumes,
                            "{family}/{label}: a ceiling the write fits inside moved a byte at \
                             cap {cap}, and a ceiling that is never reached decides nothing"
                        ),
                    }
                }
            }
        }
    }
}

/// **Acceptance test 2: a budgeted write is bounded and accepted.**
///
/// With a ceiling the held-whole write of a member would exceed, over a
/// patchable output, the writer's peak working memory does not grow with
/// the member's size and stays inside the ceiling; the archive reads
/// back to the input. The reference `rar t` and `unrar t` half is
/// `the_old_engine_and_reference_unrar_read_a_streamed_set`, which runs
/// the budgeted arm over every shape.
///
/// The ceiling is held at the process pool's width; the two members'
/// figures are compared on [`one_thread`], for the reason given there.
#[test]
fn ceiling_rule_a_budgeted_write_is_bounded_and_accepted() {
    /// How far apart two figures may be and still count as the same: one
    /// parse block, the grain these buffers grow in.
    const SAME: u64 = 256 << 10;

    for (family, format) in families() {
        let mut peaks = Vec::new();
        let mut holds = Vec::new();
        let roomy = roomy();
        for length in [2 << 20usize, 8 << 20] {
            // Each member's held-whole write passes the ceiling (spec G
            // 3.5's sum, the finder over the member's own length).
            let whole_cost =
                DICTIONARY + chains_term(DICTIONARY, length as u64) + WINDOW as u64 + length as u64;
            assert!(whole_cost > roomy, "{length} B would be held whole");
            let members: Vec<Member> = vec![
                (b"head.txt".to_vec(), rarkit_testdata::chatter(50, 4_000)),
                (b"long.bin".to_vec(), lz_noise(length, 51)),
            ];
            let want = || options_of(format, 1 << 20, true, false, Some(roomy));
            // The ceiling is held at the width a caller gets, the
            // process's pool: a scheduler that runs the parses narrower
            // than the pool only lowers this figure, so it cannot pass a
            // write that should fail.
            let (volumes, report, took) = streamed(want(), &members);
            assert!(
                took > 0,
                "{family}: a {length} byte member did not stream under a {roomy} byte ceiling"
            );
            assert!(volumes.len() > 1, "{family}: not a set");
            assert!(
                report.peak_working_memory <= roomy,
                "{family}: a {length} byte member held {} bytes against a {roomy} byte ceiling",
                report.peak_working_memory
            );
            assert_eq!(
                report.ceiling_exceeded_by, None,
                "{family}: the budgeted write reported passing a ceiling it stayed inside"
            );
            assert_eq!(
                read_back(&volumes),
                members,
                "{family}: the budgeted set did not read back"
            );
            // The pair that says the walk does not follow the member is
            // compared on [`one_thread`], each figure its own member's.
            let (_, alone, took_alone) = one_thread(|| streamed(want(), &members));
            assert!(
                took_alone > 0,
                "{family}: a {length} byte member did not stream on one thread"
            );
            assert!(
                alone.peak_working_memory <= roomy,
                "{family}: a {length} byte member held {} bytes on one thread against a \
                 {roomy} byte ceiling",
                alone.peak_working_memory
            );
            let (_, control) = one_thread(|| held_whole(want(), &members));
            eprintln!(
                "{family}: a {length} byte member: streamed {} bytes ({} on one thread), held \
                 whole {} bytes on one thread, ceiling {roomy}",
                report.peak_working_memory, alone.peak_working_memory, control.peak_working_memory
            );
            peaks.push(alone.peak_working_memory);
            holds.push(control.peak_working_memory);
        }
        assert!(
            peaks[1] <= peaks[0] + SAME,
            "{family}: a member four times the size streamed {} bytes against {}, so the \
             budgeted walk still follows the member",
            peaks[1],
            peaks[0]
        );
        assert!(
            holds[1] > holds[0] + SAME,
            "{family}: the held-whole control did not grow with the member, so this row is no \
             longer measuring what it names"
        );
    }
}

/// **Acceptance test 3: the mode is a function of the policy and the
/// member.**
///
/// The same policy and member choose the same mode on every run, at any
/// width and under any load, and the archive's bytes do not move with
/// them. What makes it true is what `Run::held_whole_bytes` is allowed to
/// read - the dictionary the options choose, the member's own size and
/// the caller's `working_limit`, and nothing else - and this row is the
/// behavioural half of that: no clock, no resident-size figure and no
/// count of what is in flight can reach the decision, because varying
/// every one of them moves neither `took` nor a byte.
#[test]
fn ceiling_rule_the_mode_is_a_function_of_the_policy_and_the_member() {
    let (_, members) = shapes().swap_remove(0);
    for (family, format) in families() {
        let want = || options_of(format, 250_000, true, false, Some(TIGHT));
        let (control, _, control_took) = streamed(want(), &members);
        assert!(
            control_took > 0,
            "{family}: the budgeted member did not stream"
        );

        for depth in [1usize, 2, 4, 32] {
            let (bytes, _, took) =
                rarkit::internals::writers::with_batch_depth(depth, || streamed(want(), &members));
            assert_eq!(took, control_took, "{family}: depth {depth} moved the mode");
            assert_eq!(
                bytes, control,
                "{family}: depth {depth} moved a byte of a budgeted member"
            );
        }
        for threads in [1usize, 2, 8] {
            let (bytes, _, took) =
                rarkit::internals::rar20::on_threads(threads, || streamed(want(), &members));
            assert_eq!(
                took, control_took,
                "{family}: {threads} threads moved the mode"
            );
            assert_eq!(
                bytes, control,
                "{family}: {threads} threads moved a byte of a budgeted member"
            );
        }

        // Under LOAD, which is the one input a mode chosen from a clock
        // or a resident-size figure would answer differently to.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let spinners: Vec<_> = (0..4)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut x = 0u64;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    }
                    x
                })
            })
            .collect();
        let (bytes, _, took) = streamed(want(), &members);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for spinner in spinners {
            let _ = spinner.join();
        }
        assert_eq!(took, control_took, "{family}: load moved the mode");
        assert_eq!(
            bytes, control,
            "{family}: load moved a byte of a budgeted member"
        );
    }
}

/// **Acceptance test 4: a ceiling that cannot be kept is
/// reported, never refused.**
///
/// A ceiling exceeded over an output that cannot patch writes the
/// held-whole archive - the bytes the default mode writes - returns `Ok`,
/// and reports the excess. It never returns an error for the ceiling.
#[test]
fn report_rule_a_ceiling_over_an_output_that_cannot_patch_holds_and_reports() {
    for (family, format) in families() {
        for (label, members) in shapes() {
            let (held, report) = held_whole(
                options_of(format, 200_000, true, false, Some(TIGHT)),
                &members,
            );
            let (plain, plain_report) =
                held_whole(options_of(format, 200_000, true, false, None), &members);
            assert_eq!(
                held, plain,
                "{family}/{label}: a ceiling changed the bytes an output that cannot patch \
                 writes, and the rule is that they are the default mode's"
            );
            let (default_patchable, _, took) =
                streamed(options_of(format, 200_000, true, false, None), &members);
            assert_eq!(took, 0, "{family}/{label}: the default mode streamed");
            assert_eq!(
                held, default_patchable,
                "{family}/{label}: the default mode's two outputs disagreed"
            );
            assert_eq!(
                read_back(&held),
                members,
                "{family}/{label}: the held-whole archive did not read back"
            );
            let over = report.ceiling_exceeded_by.unwrap_or_else(|| {
                panic!(
                    "{family}/{label}: holding the member whole passed a {TIGHT} byte ceiling \
                     and reported nothing; it held {} bytes",
                    report.peak_working_memory
                )
            });
            assert_eq!(
                report.peak_working_memory - TIGHT,
                over,
                "{family}/{label}: the excess reported is not the excess held"
            );
            assert_eq!(
                plain_report.ceiling_exceeded_by, None,
                "{family}/{label}: a caller who set no ceiling was told one was passed"
            );
        }
    }
}

/// **Acceptance test 5: the two modes differ, and only there.**
///
/// For a case (b) member the two modes' archives are each valid and they
/// differ; for a set with no case (b) member in it - every member one
/// window or smaller - they are equal to the byte, which is the "and only
/// there" half and the one that says the exception to spec G 3.5's
/// same-bytes rule is as narrow as question 3 now says it is.
///
/// **Two things this row found that 3.5 does not yet say, both reported
/// rather than worked around.**
///
/// 1. *The two modes are often the SAME bytes.* 3.5's "The consequence,
///    stated plainly" reads as though a case (b) member always costs "1
///    or 2 bytes more". It costs what the earlier paragraph says, "the
///    number of 7-bit digits compression removed", which is ZERO for a
///    member that compresses by less than 128-fold within its digit -
///    which ordinary text at level 1 does. Measured here: a 1 MiB text
///    member in a RAR 5 set, and a 2 MiB one in a RAR 4 set, come out
///    byte for byte identical in the two modes. So this row uses
///    [`flat`], which compresses far enough to move the width, for the
///    archives it asserts a difference between.
/// 2. *Where they differ it is not ONLY the field.* The streaming mode
///    hands the encoder a chain of WINDOWS where the held-whole mode
///    encodes the member as one REGION over its own slice, and the two
///    are not the same packed stream. RAR 4 writes a fixed-width packed
///    size field and reserves nothing, and its two modes still differ by
///    8 bytes on a 2 MiB flat member, which can only be the stream. The
///    archives are all valid and reference `rar t` and `unrar t` accept
///    both, so nothing in the rule is disturbed; the SENTENCE is what
///    wants an erratum.
///
/// So this row asserts what is true: outside case (b) the modes are one
/// archive, inside it they may differ and each is a readable archive of
/// the same members.
#[test]
fn ceiling_rule_the_two_modes_differ_and_only_there() {
    let small: Vec<Member> = vec![
        (b"a.txt".to_vec(), rarkit_testdata::chatter(60, 60_000)),
        (b"b.txt".to_vec(), rarkit_testdata::chatter(61, WINDOW)),
        (b"c.txt".to_vec(), rarkit_testdata::chatter(62, 60_000)),
    ];
    let case_b: Vec<Member> = vec![
        (b"head.txt".to_vec(), rarkit_testdata::chatter(63, 5_000)),
        (b"long.txt".to_vec(), flat(2 << 20)),
        (b"tail.txt".to_vec(), rarkit_testdata::chatter(65, 6_500)),
    ];

    for (family, format) in families() {
        // Outside case (b) the two modes are one mode.
        let (budgeted, _, took) = streamed(
            options_of(format, 200_000, true, false, Some(TIGHT)),
            &small,
        );
        assert_eq!(took, 0, "{family}: a member one window or smaller streamed");
        let (default, _, _) = streamed(options_of(format, 200_000, true, false, None), &small);
        assert_eq!(
            budgeted, default,
            "{family}: a ceiling moved a byte of a set with no case (b) member in it, and the \
             exception to 3.5's same-bytes rule does not reach there"
        );

        // Inside it they differ, and both are archives.
        let (mode2, _, took) = streamed(
            options_of(format, 200_000, true, false, Some(TIGHT)),
            &case_b,
        );
        assert_eq!(took, 1, "{family}: the case (b) member did not stream");
        let (mode1, _, took) = streamed(options_of(format, 200_000, true, false, None), &case_b);
        assert_eq!(took, 0, "{family}: the default mode streamed");
        assert_ne!(
            mode1, mode2,
            "{family}: the two modes wrote the same bytes, so either the reservation is not \
             being spent or this row is no longer reaching case (b)"
        );
        eprintln!(
            "{family}: case (b) in {} bytes held whole against {} streamed",
            mode1.iter().map(Vec::len).sum::<usize>(),
            mode2.iter().map(Vec::len).sum::<usize>()
        );
        for (which, volumes) in [("held whole", &mode1), ("streamed", &mode2)] {
            assert_eq!(
                read_back(volumes),
                case_b,
                "{family}: the {which} archive did not read back"
            );
            #[cfg(feature = "oracle-compare")]
            {
                let borrowed: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
                let old = rarkit_oracle::extract(&borrowed, None).unwrap_or_else(|e| {
                    panic!("{family}: the old engine refused the {which} archive: {e:?}")
                });
                let got: Vec<Vec<u8>> = old.into_iter().map(|m| m.data).collect();
                let want: Vec<Vec<u8>> = case_b.iter().map(|m| m.1.clone()).collect();
                assert_eq!(
                    got, want,
                    "{family}: the old engine read the {which} archive back differently"
                );
            }
        }
    }
}

/// **An ENCRYPTED member streams under a ceiling and is held with none.**
///
/// Until 28 Sep 2026 an encrypted member was never streamed, and this row
/// (then `a_ceiling_does_not_move_an_encrypted_members_bytes`) pinned that
/// a ceiling it could not keep moved none of its bytes and was reported.
/// The streamed walk now takes an encrypted member: under a ceiling it
/// STREAMS, keeps the ceiling, and reports nothing; with none, below
/// `DEFAULT_LIMIT`, it is held as before. Both read back with the
/// password.
///
/// The entropy is SEEDED, because an encrypted archive draws a salt and
/// an initialisation vector per member and two runs of the same members
/// are otherwise different bytes by design (spec G 3.13).
#[test]
fn a_ceiling_streams_an_encrypted_member_and_none_holds_it() {
    let members: Vec<Member> = vec![
        (b"head.txt".to_vec(), rarkit_testdata::chatter(70, 5_000)),
        (b"long.txt".to_vec(), flat(2 << 20)),
    ];
    for (family, format) in families() {
        let sealed = |ceiling| {
            let mut want = options_of(format, 200_000, true, false, ceiling);
            want.password = Some(rarkit::Password::new("budgeted"));
            want.entropy = rarkit::Entropy::Seeded([9u8; 32]);
            want
        };
        // `roomy()`, the ceiling the acceptance row derives: above
        // what the streamed walk holds and below the held-whole cost of a
        // 2 MiB member, so a walk that keeps it reports nothing.
        let (budgeted, report, took) = streamed(sealed(Some(roomy())), &members);
        assert!(
            took > 0,
            "{family}: an encrypted member under a ceiling did not stream"
        );
        assert!(
            report.ceiling_exceeded_by.is_none(),
            "{family}: a streamed encrypted member reported the ceiling passed"
        );
        let (default, _, held) = streamed(sealed(None), &members);
        assert_eq!(
            held, 0,
            "{family}: with no ceiling an encrypted member streamed"
        );
        for (label, set) in [("budgeted", &budgeted), ("default", &default)] {
            assert_eq!(
                read_back_with(set, Some(rarkit::Password::new("budgeted"))),
                members,
                "{family}: the {label} encrypted set did not read back"
            );
        }
    }
}

/// **The rows above moved onto [`lz_noise`], and this is why, pinned the
/// other way.** The plain [`noise`] member they used before 28 Sep 2026,
/// written the way they wrote it (non-solid, under the budgeted arm's
/// ceiling, over a patchable output), is now STORED by spec G 3.8.3's
/// samples: no member takes the streamed walk, the member costs its own
/// bytes and no more, and it reads back. In a SOLID run it is stored too
/// since 1 Oct 2026, when the rule began to judge solid members; with
/// `WriteOptions::solid_store` off the rule takes no samples there, so the
/// same member is still encoded and still streams.
#[test]
fn plain_noise_is_now_stored_and_so_reaches_no_encoder() {
    for (family, format) in families() {
        let member = noise(1 << 20, 7);
        let members: Vec<Member> = vec![
            (b"head.txt".to_vec(), rarkit_testdata::chatter(6, 3_000)),
            (b"noise.bin".to_vec(), member.clone()),
        ];
        let (volumes, report, took) = streamed(
            options_of(format, 250_000, true, false, Some(TIGHT)),
            &members,
        );
        assert_eq!(took, 0, "{family}: a stored member took the streamed walk");
        assert_eq!(report.held_volume_bytes, 0);
        let total: usize = volumes.iter().map(Vec::len).sum();
        assert!(
            total < member.len() + 3_000 + 64 * volumes.len() + 512,
            "{family}: {total} bytes over {} volumes for a stored {} byte member",
            volumes.len(),
            member.len()
        );
        assert_eq!(read_back(&volumes), members, "{family}: read back");

        let (solid_set, _, solid_took) =
            streamed(options_of(format, 250_000, true, true, None), &members);
        assert_eq!(
            solid_took, 0,
            "{family}: in a solid run the stored noise member took the streamed walk"
        );
        assert_eq!(read_back(&solid_set), members, "{family}: solid read back");
        let (_, _, kept_took) = streamed(
            WriteOptions {
                solid_store: false,
                ..options_of(format, 250_000, true, true, None)
            },
            &members,
        );
        assert!(
            kept_took > 0,
            "{family}: in a solid run with solid_store off the noise member did not stream"
        );
    }
}
