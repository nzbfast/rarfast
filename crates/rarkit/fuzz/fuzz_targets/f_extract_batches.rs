//! Small member batches (`RARKIT_SMALL_BATCH`, 26 Sep
//! 2026) under the fuzzer: `extract_parallel` with batches on, against
//! `extract`, on the same damaged bytes.
//!
//! WHY A TARGET OF ITS OWN. `f_extract_parallel` lowers the offload floor
//! to zero so that every member leaves the walking thread, and a batch
//! admits only members BELOW that floor (`extract::batchable`), so that
//! target never forms a batch at all. This one keeps the engine's own
//! floor, asks for a batch shape and a member team width chosen by the
//! fuzzer, and feeds archives made of many small compressed members, which
//! is the only shape the batches are for.
//!
//! The property is SPEC-API 4.4's, the same one `f_extract_parallel`
//! holds: per member output identical to the sequential form, closes in
//! archive order, the first failure reported first. A batch is a new way
//! for that to break, because a worker now holds several members, and a
//! failure in the first of them must neither lose nor reorder the others.
//!
//! REACHABILITY. An equivalence target passes just as well if the batch
//! arm quietly fell back to one member at a time, so every run reads
//! `probe::peak_batch` and the target prints how many batches it has sent
//! at every power of two runs. A campaign log that never shows a nonzero
//! count did not fuzz the batches.

#![no_main]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use rarkit::{
    extract, extract_parallel, Disposition, FilterPolicy, HostOs, MemberInfo, MemberOutcome,
    MemberSpec, MemoryPolicy, ParallelSink, Payload, RangeSource, Rar4Version, ReadOptions, Result,
    Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// One member as either driver closed it: name, verdict, length, CRC32.
/// A digest and not the bytes, for the reason `f_extract_parallel` gives.
type Seen = (Vec<u8>, Option<bool>, u64, u32);

/// The most one member may hand the sink. Per member, never shared, so the
/// same member reaches it whichever driver ran and in whatever order.
const MOST_PER_MEMBER: u64 = 4 << 20;

/// The listing fast path: an archive declaring more than this in total is
/// not decoded at all.
const MOST_OUTPUT: u64 = 4 << 20;

#[derive(Default)]
struct Digest {
    crc: rarkit::checksum::Crc32,
    bytes: u64,
}

impl std::io::Write for Digest {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.bytes += data.len() as u64;
        if self.bytes > MOST_PER_MEMBER {
            return Err(std::io::Error::other(
                "past this target's per-member ceiling",
            ));
        }
        self.crc.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn seen(member: &MemberInfo<'_>, out: Option<Digest>, outcome: &MemberOutcome) -> Seen {
    (
        member.name.to_vec(),
        outcome.checksum_ok,
        outcome.bytes,
        out.map_or(0, |d| d.crc.finish()),
    )
}

#[derive(Default)]
struct Serial {
    seen: Vec<Seen>,
}

impl Sink for Serial {
    type Out = Digest;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::default()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Digest>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.push(seen(member, out, outcome));
        Ok(())
    }
}

#[derive(Default)]
struct Wide {
    seen: Mutex<Vec<Seen>>,
}

impl ParallelSink for Wide {
    type Out = Digest;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::default()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Digest>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen
            .lock()
            .expect("the sink's own lock")
            .push(seen(member, out, outcome));
        Ok(())
    }
}

/// An error's kind with a `LimitExceeded`'s `needed` blanked, because that
/// figure is the decoder's history and not the archive's (see
/// `f_extract_parallel`'s `kind_of`).
fn kind_of(e: &rarkit::Error) -> String {
    let text = format!("{:?}", e.kind());
    match text.split_once("needed: ") {
        Some((head, rest)) => {
            let tail = rest.split_once(',').map_or("", |(_, tail)| tail);
            format!("{head}needed: _,{tail}")
        }
        None => text,
    }
}


/// The member sizes of the written archives: most well below the engine's
/// 16 KiB compressed offload floor, so they are batchable, a few above it
/// so admission mixes batches with members sent alone, one empty member
/// (never worth a worker), and one directory.
const SIZES: [usize; 40] = [
    1, 17, 90, 300, 512, 700, 1_000, 1_500, 2_048, 2_500, 3_000, 3_333, 4_096, 5_000, 6_000, 7_000,
    8_000, 9_000, 10_000, 11_000, 12_000, 13_000, 14_000, 15_000, 16_000, 16_383, 0, 200, 400, 800,
    1_600, 3_200, 6_400, 12_800, 20_000, 40_000, 5, 64, 128, 256,
];

/// A non-solid, compressed archive of [`SIZES`]'s members, written once.
fn many_small(format: WriteFormat) -> Vec<u8> {
    let options = WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        // SPEC-J: the RAR 4 family refuses a filter request
        // rather than resolving it to `Off`, so both formats ask for none.
        filters: FilterPolicy::Off,
        solid: false,
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("the many-small archive's options");
    let bodies: Vec<Vec<u8>> = SIZES
        .iter()
        .enumerate()
        .map(|(i, &n)| rarkit_testdata::chatter(i as u64, n))
        .collect();
    let names: Vec<Vec<u8>> = (0..SIZES.len())
        .map(|i| format!("small/m{i:02}.txt").into_bytes())
        .collect();
    writer
        .add(MemberSpec {
            name: b"small",
            payload: Payload::Bytes(&[]),
            mtime: None,
            attributes: 0o755,
            host_os: HostOs::Unix,
            is_directory: true,
        })
        .expect("the many-small archive's directory");
    for (name, body) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0o644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("a many-small member");
    }
    let mut out = Vec::new();
    writer
        .finish_into(&mut out)
        .expect("the many-small archive");
    out
}

/// The inputs, built or read once per process: two written many-small
/// archives, RAR 5 and RAR 4, and the fixtures with several small
/// compressed non-solid members each (`tests/small_batch_caps.rs` is held
/// to `r550_m3.rar`'s batches).
fn inputs() -> &'static [Vec<u8>] {
    static INPUTS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    INPUTS.get_or_init(|| {
        vec![
            many_small(WriteFormat::Rar5),
            many_small(WriteFormat::Rar4(Rar4Version::V40)),
            include_bytes!("../../../../fixtures/legacy/archives/r550_m3.rar").to_vec(),
            include_bytes!("../../../../fixtures/legacy/archives/r550_m5.rar").to_vec(),
            include_bytes!("../../../../fixtures/legacy/archives/r420_m5.rar").to_vec(),
            include_bytes!("../../../../fixtures/legacy/archives/r393_m3.rar").to_vec(),
            include_bytes!("../../../../specs/vectors-F/archives/f03_m3.rar").to_vec(),
            include_bytes!("../../../../specs/vectors-F/archives/f05_blake.rar").to_vec(),
        ]
    })
}

/// Batch shapes, `(members, cap bytes)`: the shipped pair, wider ones, a
/// cap no member fits (every member sent alone), and one at a time.
const SHAPES: [(usize, u64); 8] = [
    (2, 64 << 10),
    (1, 64 << 10),
    (3, 16 << 10),
    (4, 256 << 10),
    (8, 64 << 10),
    (64, 1 << 20),
    (4, 1),
    (2, 4 << 10),
];

/// Member team widths: uncapped, one, two, the default eight.
const TEAMS: [usize; 4] = [0, 1, 2, 8];

static RUNS: AtomicU64 = AtomicU64::new(0);
static BATCHES: AtomicU64 = AtomicU64::new(0);
static BATCHED_RUNS: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let pick = data[0];
    let shape = SHAPES[usize::from(data[1] % 8)];
    let team = TEAMS[usize::from((data[1] >> 3) & 3)];
    let width = usize::from(data[2] % 8) + 1;
    let body = &data[4..];

    // The engine's own floor: a batch admits only members below it.
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_small_batch(Some(shape));
    rarkit::probe::set_small_team(Some(team));
    rarkit::probe::set_outputs_over_breadth(Some(if data[2] & 8 != 0 { 2 } else { 1 }));

    // The memory policy: the default most of the time, which is what
    // `small_batch_caps.rs` sends batches under, and otherwise a limit of
    // 128 MiB to 1 GiB, which sets `max_workers` to two to sixteen.
    let memory = match data[3] % 5 {
        0 => MemoryPolicy::from_limit(128 << 20),
        1 => MemoryPolicy::from_limit(1 << 30),
        _ => MemoryPolicy::default(),
    };
    let opts = ReadOptions::default()
        .with_memory(memory)
        .with_password(Some(rarkit::Password::from("Secret")));

    let inputs = inputs();
    let mut bytes = inputs[usize::from(pick) % inputs.len()].clone();
    if !body.is_empty() {
        let at = usize::from(pick) * 131 % bytes.len();
        for (i, b) in body.iter().enumerate().take(bytes.len() - at) {
            bytes[at + i] ^= b;
        }
    }

    let listed: Arc<dyn RangeSource> = Arc::new(bytes.clone());
    if let Ok(archive) = rarkit::Archive::open(listed, &opts) {
        let declared: u64 = archive
            .members()
            .map(|m| m.unpacked_size.unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        if declared > MOST_OUTPUT {
            return;
        }
    }

    let one: Arc<dyn RangeSource> = Arc::new(bytes.clone());
    let mut serial = Serial::default();
    let want = extract(vec![one], &opts, &mut serial, &mut ());

    rarkit::probe::reset_peak_batch();
    let two: Arc<dyn RangeSource> = Arc::new(bytes);
    let wide = Wide::default();
    let have = extract_parallel(vec![two], &opts, &wide, width);
    let (_, _, sent) = rarkit::probe::peak_batch();
    let seen = wide.seen.into_inner().expect("the sink's own lock");

    let runs = RUNS.fetch_add(1, Ordering::Relaxed) + 1;
    BATCHES.fetch_add(sent as u64, Ordering::Relaxed);
    if sent > 0 {
        BATCHED_RUNS.fetch_add(1, Ordering::Relaxed);
    }
    if runs.is_power_of_two() {
        eprintln!(
            "f_extract_batches: {runs} runs, {} sent a batch, {} batches",
            BATCHED_RUNS.load(Ordering::Relaxed),
            BATCHES.load(Ordering::Relaxed)
        );
    }

    let label = format!("width {width} batch {shape:?} team {team}");
    for (at, (a, b)) in serial.seen.iter().zip(&seen).enumerate() {
        assert_eq!(a.0, b.0, "{label}: member {at} closed out of order");
        assert_eq!(a.1, b.1, "{label}: member {at} got another verdict");
        assert_eq!(a.2, b.2, "{label}: member {at} produced another length");
        assert_eq!(
            a.3, b.3,
            "{label}: member {at} produced other bytes (CRC32)"
        );
    }
    match (&want, &have) {
        (Ok(want), Ok(have)) => {
            assert_eq!(
                serial.seen.len(),
                seen.len(),
                "{label}: two runs that both succeeded closed different numbers of members"
            );
            assert_eq!(want.members, have.members, "{label}: report.members");
            assert_eq!(want.bytes, have.bytes, "{label}: report.bytes");
            assert_eq!(
                want.checksum_failures, have.checksum_failures,
                "{label}: report.checksum_failures"
            );
        }
        (Err(want), Err(have)) => assert_eq!(
            kind_of(want),
            kind_of(have),
            "{label}: the two drivers ended with different errors\n  \
             sequential: {want:?}\n  concurrent: {have:?}"
        ),
        (want, have) => panic!(
            "{label}: one driver failed and the other did not: \
             sequential {want:?}, concurrent {have:?}"
        ),
    }
});
