//! A STORED member inside a SOLID set, extracted to a file: its ranges are
//! handed to the caller's thread, which reads, hashes and writes them wide
//! (`read::handed`, `RARKIT_SOLID_STORED_WIDE`), and the set says and
//! writes exactly what it said and wrote before.
//!
//! Every case reads its set THREE WAYS and holds them equal:
//!
//! - `Sequential`: the walk on the caller's own thread (the solid path
//!   off), which is the engine before any of this;
//! - `Before`: the solid path, every byte through its queue (the knob
//!   off);
//! - `After`: the solid path with stored ranges handed over.
//!
//! and asserts that the `After` arm really handed ranges and the other two
//! handed none, so no comparison is of an arm with itself.
//!
//! The sets: every member stored (this crate's writer, one archive and a
//! volume set whose members cross volumes); stored members first, in the
//! middle and last among compressed ones that continue one chain across
//! them (spliced from two of this crate's archives, block for block, in
//! both layouts: the stored members' solid bit clear, as this crate will
//! write them, and set, as reference `rar -ms` writes them, spec G 3.9);
//! and reference `rar`'s own `-s -ms` sets where `rar` is on the path,
//! clear, `-p` and `-hp`, one archive and volumes.

#![cfg(feature = "test-support")]

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rarkit::{
    extract, probe, Disposition, MemberInfo, MemberOrder, MemberOutcome, MemberSpec, Password,
    Payload, Progress, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const SECRET: &str = "solidstore";

/// A volume's size: not a whole number of pieces or of pages, smaller
/// than the largest member, and large enough that a member's fragment is
/// above the wide read's 16 MiB floor.
const PER: u64 = (19 << 20) + 4_093;

/// Incompressible, deterministic bytes.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x2929_0929_7f4a_7c15 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// The stored members: each above the wide read's 16 MiB floor, none a
/// whole number of pieces or of pages.
fn videos() -> [(&'static [u8], Vec<u8>); 3] {
    [
        (b"ep1.mkv", noise((17 << 20) + 3, 1)),
        (b"ep2.mkv", noise((21 << 20) + 4_099, 2)),
        (b"ep3.mkv", noise((18 << 20) + 77, 3)),
    ]
}

fn subtitles() -> [(&'static [u8], Vec<u8>); 3] {
    [
        (b"ep1.srt", rarkit_testdata::chatter(1, 700_000)),
        (b"ep2.srt", rarkit_testdata::chatter(2, 650_001)),
        (b"ep3.srt", rarkit_testdata::chatter(3, 712_345)),
    ]
}

fn written(options: WriteOptions, members: &[(&[u8], Vec<u8>)]) -> Vec<Vec<u8>> {
    let volumes = options.volume_size.is_some();
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    if volumes {
        let mut out: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut out).expect("finish");
        out
    } else {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish");
        vec![one]
    }
}

/// Every member stored, in a solid archive, by this crate's writer.
fn all_stored(per: Option<u64>) -> Vec<Vec<u8>> {
    written(
        WriteOptions {
            method: WriteMethod::Stored,
            solid: true,
            order: MemberOrder::AsAdded,
            volume_size: per,
            ..WriteOptions::default()
        },
        &videos().map(|(n, d)| (n, d)),
    )
}

// ---------------------------------------------------------------------------
// A solid archive spliced from two, block for block (spec F 3.2.2, 3.2.6)
// ---------------------------------------------------------------------------

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    for shift in 0..10 {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 0x7f) << (7 * shift);
        if b & 0x80 == 0 {
            break;
        }
    }
    value
}

/// One RAR 5 block: its type, where its header ends, and its whole span.
struct Block {
    kind: u64,
    start: usize,
    header_end: usize,
    end: usize,
}

/// The blocks of one RAR 5 archive, by spec F 3.2.2's framing alone.
fn blocks(archive: &[u8]) -> Vec<Block> {
    assert_eq!(&archive[..8], SIGNATURE);
    let mut at = 8;
    let mut out = Vec::new();
    while at < archive.len() {
        let start = at;
        at += 4;
        let size = vint(archive, &mut at) as usize;
        let header_end = at + size;
        let kind = vint(archive, &mut at);
        let flags = vint(archive, &mut at);
        if flags & 1 != 0 {
            vint(archive, &mut at);
        }
        let data = if flags & 2 != 0 {
            vint(archive, &mut at) as usize
        } else {
            0
        };
        out.push(Block {
            kind,
            start,
            header_end,
            end: header_end + data,
        });
        at = header_end + data;
    }
    out
}

/// A copy of one file block with the solid bit of its compression
/// information set (spec F 3.2.6, bit 6) and its header CRC32 made right
/// again (3.2.2: over everything after the CRC field, to the header's end).
fn with_solid_bit(archive: &[u8], block: &Block) -> Vec<u8> {
    let mut out = archive[block.start..block.end].to_vec();
    let mut at = 4;
    vint(&out, &mut at);
    vint(&out, &mut at);
    let flags = vint(&out, &mut at);
    if flags & 1 != 0 {
        vint(&out, &mut at);
    }
    if flags & 2 != 0 {
        vint(&out, &mut at);
    }
    let file_flags = vint(&out, &mut at);
    vint(&out, &mut at);
    vint(&out, &mut at);
    if file_flags & 2 != 0 {
        at += 4;
    }
    if file_flags & 4 != 0 {
        at += 4;
    }
    assert_eq!(out[at] & 0x40, 0, "the member already continues a chain");
    out[at] |= 0x40;
    let header = block.header_end - block.start;
    let crc = crc32fast::hash(&out[4..header]);
    out[..4].copy_from_slice(&crc.to_le_bytes());
    out
}

/// A solid archive of three subtitle members compressed as ONE chain and
/// three stored videos, in the order video, text, video, text, text,
/// video: a stored member first, in the middle and last, and a compressed
/// member that continues the chain across a stored one. `flagged` sets
/// the solid bit on the stored members that follow a compressed one, as
/// reference `rar -ms` lays them out; clear, they are as this crate
/// writes a stored member (spec G 3.9).
fn spliced(flagged: bool) -> Vec<u8> {
    let texts = written(
        WriteOptions {
            method: WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            solid: true,
            order: MemberOrder::AsAdded,
            ..WriteOptions::default()
        },
        &subtitles().map(|(n, d)| (n, d)),
    )
    .remove(0);
    let stored = written(
        WriteOptions {
            method: WriteMethod::Stored,
            order: MemberOrder::AsAdded,
            ..WriteOptions::default()
        },
        &videos().map(|(n, d)| (n, d)),
    )
    .remove(0);
    let (tb, sb) = (blocks(&texts), blocks(&stored));
    let files = |b: &[Block]| -> Vec<usize> { (0..b.len()).filter(|&i| b[i].kind == 2).collect() };
    let (tf, sf) = (files(&tb), files(&sb));
    assert_eq!((tf.len(), sf.len()), (3, 3));
    let main = tb.iter().find(|b| b.kind == 1).expect("a main header");
    let end = tb.iter().find(|b| b.kind == 5).expect("an end record");
    let mut out = SIGNATURE.to_vec();
    out.extend_from_slice(&texts[main.start..main.end]);
    let text_block = |i: usize| texts[tb[tf[i]].start..tb[tf[i]].end].to_vec();
    let video = |i: usize, after_compressed: bool| {
        let block = &sb[sf[i]];
        if flagged && after_compressed {
            with_solid_bit(&stored, block)
        } else {
            stored[block.start..block.end].to_vec()
        }
    };
    out.extend(video(0, false));
    out.extend(text_block(0));
    out.extend(video(1, true));
    out.extend(text_block(1));
    out.extend(text_block(2));
    out.extend(video(2, true));
    out.extend_from_slice(&texts[end.start..end.end]);
    out
}

/// What the spliced archive must give back, in its order.
fn spliced_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    let (v, t) = (videos(), subtitles());
    [&v[0], &t[0], &v[1], &t[1], &t[2], &v[2]]
        .into_iter()
        .map(|(n, d)| (n.to_vec(), d.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// Reference `rar -s -ms`
// ---------------------------------------------------------------------------

/// A solid set by reference `rar`, in the order given, its `.bin` members
/// stored (`-msbin`) and the rest compressed, or `None` without `rar`.
fn reference_set(tag: &str, extra: &[&str]) -> Option<Vec<Vec<u8>>> {
    // The process id and the tag in the path: two runs of the suite share
    // `temp_dir`, and two cases of this file run on two threads.
    let dir = std::env::temp_dir().join(format!("rarkit-sswide-{tag}-{}", std::process::id()));
    let files = dir.join("in");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&files).ok()?;
    let (v, t) = (videos(), subtitles());
    let members: [(&str, &Vec<u8>); 5] = [
        ("a.bin", &v[0].1),
        ("b.txt", &t[0].1),
        ("c.bin", &v[1].1),
        ("d.txt", &t[1].1),
        ("e.bin", &v[2].1),
    ];
    for (name, data) in members {
        std::fs::write(files.join(name), data).ok()?;
    }
    let made = std::process::Command::new("rar")
        .current_dir(&files)
        .args([
            "a", "-ma5", "-m3", "-s", "-ds", "-msbin", "-ep", "-idq", "-y",
        ])
        .args(extra)
        .arg(dir.join("set.rar"))
        .args(members.map(|(name, _)| name))
        .status()
        .is_ok_and(|s| s.success());
    let mut volumes = Vec::new();
    if made {
        if let Ok(one) = std::fs::read(dir.join("set.rar")) {
            volumes.push(one);
        } else {
            for part in 1.. {
                match std::fs::read(dir.join(format!("set.part{part}.rar"))) {
                    Ok(v) => volumes.push(v),
                    Err(_) => break,
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    (!volumes.is_empty()).then_some(volumes)
}

fn reference_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    let (v, t) = (videos(), subtitles());
    vec![
        (b"a.bin".to_vec(), v[0].1.clone()),
        (b"b.txt".to_vec(), t[0].1.clone()),
        (b"c.bin".to_vec(), v[1].1.clone()),
        (b"d.txt".to_vec(), t[1].1.clone()),
        (b"e.bin".to_vec(), v[2].1.clone()),
    ]
}

// ---------------------------------------------------------------------------
// One read, three ways
// ---------------------------------------------------------------------------

/// One member's writes: the length of each, and whether its buffer began
/// on a page.
type Calls = Vec<(usize, bool)>;

/// A writer that keeps what it is given and how it was given: the length
/// of each write and whether its buffer began on a page. It refuses past
/// `limit` bytes, as a full disk would.
struct Kept {
    bytes: Vec<u8>,
    calls: Calls,
    limit: Option<usize>,
}

impl Write for Kept {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self
            .limit
            .is_some_and(|l| self.bytes.len() + data.len() > l)
        {
            return Err(std::io::Error::other("full"));
        }
        self.calls
            .push((data.len(), (data.as_ptr() as usize).is_multiple_of(4096)));
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What the sink does with a member, by its name.
#[derive(Clone, Copy, PartialEq)]
enum Take {
    Write,
    Verify,
    /// Skip the members whose names end `.mkv` or `.bin`, write the rest.
    SkipVideo,
    /// Write only the LAST member, skip every other.
    OnlyLast(&'static [u8]),
}

struct Verdicts {
    take: Take,
    limit: Option<usize>,
    outcomes: Vec<(Vec<u8>, MemberOutcome)>,
    bytes: Vec<(Vec<u8>, Vec<u8>)>,
    calls: Vec<(Vec<u8>, Calls)>,
}

impl Sink for Verdicts {
    type Out = Kept;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Kept>> {
        let video = member.name.ends_with(b".mkv") || member.name.ends_with(b".bin");
        let write = match self.take {
            Take::Write => true,
            Take::Verify => return Ok(Disposition::Verify),
            Take::SkipVideo => !video,
            Take::OnlyLast(name) => member.name == name,
        };
        Ok(if write {
            Disposition::Write(Kept {
                bytes: Vec::new(),
                calls: Vec::new(),
                limit: self.limit,
            })
        } else {
            Disposition::Skip
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Kept>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if let Some(out) = out {
            self.bytes.push((member.name.to_vec(), out.bytes));
            self.calls.push((member.name.to_vec(), out.calls));
        }
        self.outcomes.push((member.name.to_vec(), *outcome));
        Ok(())
    }
}

/// The drop-behind reports, which must stay monotone per volume, and the
/// output count, which must only grow.
struct Trail {
    done: Vec<u32>,
    released: Vec<(u32, u64)>,
    output: u64,
    /// Raise this once the output passes `cancel_after`.
    cancel: Option<Arc<AtomicBool>>,
    cancel_after: u64,
}

impl Progress for Trail {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        if let Some(&(v, last)) = self.released.iter().rev().find(|(v, _)| *v == volume) {
            assert!(offset >= last, "released went backwards on volume {v}");
        }
        self.released.push((volume, offset));
        Ok(())
    }

    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.done.push(volume);
        Ok(())
    }

    fn output(&mut self, total: u64) -> Result<()> {
        assert!(total >= self.output, "the output count went backwards");
        self.output = total;
        if let Some(cancel) = &self.cancel {
            if total >= self.cancel_after {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Arm {
    Sequential,
    Before,
    After,
}

#[derive(Clone, Copy)]
struct How {
    workers: usize,
    take: Take,
    /// `Some(true)` is `x` (and `p` into a file): the solid path's hint.
    sink_is_file: Option<bool>,
    password: Option<&'static str>,
    limit: Option<usize>,
    cancel_after: Option<u64>,
    piece: Option<u64>,
    /// One reader in order, the window's pieces at once, or (`None`) the
    /// system's own default.
    in_order: Option<bool>,
    /// Whether the set takes the solid path under the hint: not at a
    /// width of one, and not where its headers are encrypted (the path's
    /// peek at the main header answers no for one it cannot read).
    solid: bool,
}

/// `x`: every member written, to a writer the caller says is a file.
const X: How = How {
    workers: 4,
    take: Take::Write,
    sink_is_file: Some(true),
    password: None,
    limit: None,
    cancel_after: None,
    piece: None,
    in_order: None,
    solid: true,
};

#[derive(Debug, PartialEq)]
struct Said {
    /// Each member's name and outcome, or how the read failed.
    outcomes: std::result::Result<Vec<(Vec<u8>, MemberOutcome)>, String>,
    /// The report's members, bytes and checksum failures.
    report: Option<(u64, u64, u64)>,
    done: Vec<u32>,
    /// The last offset released on each volume.
    released: Vec<(u32, u64)>,
    /// Each written member's name, length and CRC32, in order.
    written: Vec<(Vec<u8>, usize, u32)>,
}

struct Read {
    said: Said,
    /// Ranges handed to this thread.
    ranges: u64,
    /// Extractions that took the solid path.
    solid: u64,
    bytes: Vec<(Vec<u8>, Vec<u8>)>,
    calls: Vec<(Vec<u8>, Calls)>,
}

fn read(volumes: &[Vec<u8>], arm: Arm, how: How) -> Read {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let cancel = how.cancel_after.map(|_| Arc::new(AtomicBool::new(false)));
    let options = ReadOptions::default()
        .with_workers(Some(how.workers))
        .with_sink_is_file(how.sink_is_file)
        .with_password(how.password.map(Password::from))
        .with_cancel(cancel.clone());
    let mut sink = Verdicts {
        take: how.take,
        limit: how.limit,
        outcomes: Vec::new(),
        bytes: Vec::new(),
        calls: Vec::new(),
    };
    let mut trail = Trail {
        done: Vec::new(),
        released: Vec::new(),
        output: 0,
        cancel,
        cancel_after: how.cancel_after.unwrap_or(u64::MAX),
    };
    probe::set_solid_ahead(Some(arm != Arm::Sequential));
    probe::set_solid_stored_wide(Some(arm == Arm::After));
    probe::set_solid_stored_piece(how.piece);
    probe::set_solid_stored_in_order(how.in_order);
    probe::reset_solid_stored_ranges();
    probe::reset_solid_ahead_seen();
    let outcome = extract(sources, &options, &mut sink, &mut trail);
    let ranges = probe::solid_stored_ranges();
    let solid = probe::solid_ahead_seen().0;
    probe::set_solid_ahead(None);
    probe::set_solid_stored_wide(None);
    probe::set_solid_stored_piece(None);
    probe::set_solid_stored_in_order(None);
    let (outcomes, report) = match outcome {
        Ok(report) => (
            Ok(sink.outcomes),
            Some((report.members, report.bytes, report.checksum_failures)),
        ),
        Err(e) => (
            Err(format!(
                "{:?} member {:?} volume {:?} offset {:?}",
                e.kind(),
                e.member().map(<[u8]>::to_vec),
                e.volume(),
                e.offset()
            )),
            None,
        ),
    };
    let mut released: Vec<(u32, u64)> = Vec::new();
    for &(volume, offset) in &trail.released {
        match released.iter_mut().find(|(v, _)| *v == volume) {
            Some(last) => last.1 = offset,
            None => released.push((volume, offset)),
        }
    }
    let written = sink
        .bytes
        .iter()
        .map(|(name, b)| (name.clone(), b.len(), rarkit::checksum::crc32(b)))
        .collect();
    Read {
        said: Said {
            outcomes,
            report,
            done: trail.done,
            released,
            written,
        },
        ranges,
        solid,
        bytes: sink.bytes,
        calls: sink.calls,
    }
}

/// The same read three ways: only the `After` arm handed ranges, both
/// solid arms took the solid path where the caller's writer is a file,
/// and all three said the same. Answers the `After` arm.
fn three_ways(volumes: &[Vec<u8>], how: How) -> Read {
    let sequential = read(volumes, Arm::Sequential, how);
    let before = read(volumes, Arm::Before, how);
    let after = read(volumes, Arm::After, how);
    assert_eq!(
        sequential.ranges, 0,
        "the walk on this thread hands nothing"
    );
    assert_eq!(sequential.solid, 0, "the solid path ran with its knob off");
    assert_eq!(before.ranges, 0, "the queue arm handed a range");
    let solid = u64::from(how.solid && how.sink_is_file == Some(true));
    assert_eq!(before.solid, solid, "the solid path, with the queue");
    assert_eq!(after.solid, solid, "the solid path, with ranges");
    assert_eq!(
        before.said, sequential.said,
        "the queue arm against the walk"
    );
    assert_eq!(
        after.said, sequential.said,
        "the handed arm against the walk"
    );
    after
}

fn whole(read: &Read, members: &[(Vec<u8>, Vec<u8>)]) {
    let outcomes = read.said.outcomes.as_ref().expect("a whole set reads");
    assert_eq!(outcomes.len(), members.len());
    for ((name, outcome), (want, data)) in outcomes.iter().zip(members) {
        assert_eq!(name, want);
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "{:?}",
            String::from_utf8_lossy(name)
        );
        assert_eq!(outcome.bytes, data.len() as u64);
    }
    assert_eq!(read.bytes.len(), members.len());
    for ((name, bytes), (want, data)) in read.bytes.iter().zip(members) {
        assert_eq!(name, want);
        assert!(
            bytes == data,
            "{:?} came back wrong",
            String::from_utf8_lossy(name)
        );
    }
}

fn video_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    videos().into_iter().map(|(n, d)| (n.to_vec(), d)).collect()
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

/// Every member stored, one archive: each member is one range.
#[test]
fn a_solid_set_of_stored_members_is_handed_member_by_member() {
    let set = all_stored(None);
    let after = three_ways(&set, X);
    whole(&after, &video_members());
    assert_eq!(after.ranges, 3, "one range a member");
}

/// The same set in volumes its members cross: each fragment is a range,
/// and the volumes are done in order, each after its last byte was read.
#[test]
fn a_stored_solid_volume_set_is_handed_fragment_by_fragment() {
    let set = all_stored(Some(PER));
    assert!(set.len() >= 3, "a set of {} volumes", set.len());
    let after = three_ways(&set, X);
    whole(&after, &video_members());
    assert!(after.ranges >= 3, "only {} ranges", after.ranges);
    assert_eq!(
        after.said.done,
        (0..set.len() as u32).collect::<Vec<_>>(),
        "every volume done, in order"
    );
}

/// Stored members first, in the middle and last, among compressed members
/// of ONE chain, in both layouts of the stored member's solid bit: the
/// compressed members still decode against each other across them.
#[test]
fn stored_members_among_a_compressed_chain_are_handed_in_both_layouts() {
    for flagged in [false, true] {
        let set = vec![spliced(flagged)];
        let after = three_ways(&set, X);
        whole(&after, &spliced_members());
        assert_eq!(
            after.ranges, 3,
            "the three stored members (flagged: {flagged})"
        );
    }
}

/// A handed member is written in whole pieces, half the read-ahead each,
/// from buffers that begin on a page, at multiples of the piece in the
/// member: what a writer past the OS cache takes without a copy. Its
/// first bytes, which the walk had read with its header, are part of the
/// first piece and not a write of their own. A member whose first
/// fragment was too short to hand over is brought to a multiple of the
/// piece by one short write after that fragment's.
#[test]
fn a_handed_member_is_written_in_whole_aligned_pieces() {
    let piece = (ReadOptions::default().memory.read_ahead / 2) as usize;
    let sets = [vec![spliced(false)], all_stored(Some(PER))];
    for (set, in_order) in sets.iter().flat_map(|s| [(s, false), (s, true)]) {
        let one = set.len() == 1;
        let after = read(
            set,
            Arm::After,
            How {
                in_order: Some(in_order),
                ..X
            },
        );
        assert!(after.ranges >= 3);
        for (name, calls) in &after.calls {
            if !name.ends_with(b".mkv") {
                continue;
            }
            let name = String::from_utf8_lossy(name);
            // The writes before the first whole piece at a multiple of the
            // piece: none for a member that begins with a range.
            let mut at = 0usize;
            let mut early = 0usize;
            while !(at.is_multiple_of(piece) && calls[early] == (piece, true)) {
                at += calls[early].0;
                early += 1;
                assert!(early < calls.len(), "{name}: no whole piece at all");
            }
            if one {
                assert_eq!(early, 0, "{name} begins with whole pieces");
            }
            assert!(at < (16 << 20) + piece, "{name}: {at} bytes before a range");
            let (last, whole) = calls[early..].split_last().expect("writes");
            let total: usize = calls.iter().map(|c| c.0).sum();
            assert_eq!(whole.len(), (total - at) / piece, "{name}");
            for (index, call) in whole.iter().enumerate() {
                assert_eq!(*call, (piece, true), "write {index} of {name}");
            }
            assert_eq!(last.0, total % piece);
        }
    }
}

/// One reader in order and the window's pieces at once (each system ships
/// one of them): both say and write what the walk does, on the spliced
/// set, on the volume set and on a set cut short inside a range.
#[test]
fn both_reading_orders_say_the_same() {
    let mut cut = spliced(false);
    cut.truncate((17 << 20) + (2 << 20) + (9 << 20) + 123);
    for in_order in [false, true] {
        let how = How {
            in_order: Some(in_order),
            ..X
        };
        let after = three_ways(&[spliced(true)], how);
        whole(&after, &spliced_members());
        assert_eq!(after.ranges, 3);
        let after = three_ways(&all_stored(Some(PER)), how);
        whole(&after, &video_members());
        let after = three_ways(std::slice::from_ref(&cut), how);
        assert!(after.said.outcomes.is_err());
    }
}

/// A named piece cuts the same bytes (the measuring arm of the knob).
#[test]
fn a_named_piece_writes_the_same_bytes() {
    let set = vec![spliced(true)];
    let after = three_ways(
        &set,
        How {
            piece: Some(512 * 1024),
            ..X
        },
    );
    whole(&after, &spliced_members());
    for (name, calls) in &after.calls {
        if name.ends_with(b".mkv") {
            assert!(calls[..calls.len() - 1]
                .iter()
                .all(|c| *c == (512 * 1024, true)));
        }
    }
}

/// A width of one has no wide read, so nothing is handed and the knob
/// changes nothing.
#[test]
fn a_width_of_one_hands_nothing() {
    let set = vec![spliced(false)];
    let after = three_ways(
        &set,
        How {
            workers: 1,
            solid: false,
            ..X
        },
    );
    whole(&after, &spliced_members());
    assert_eq!(after.ranges, 0);
}

/// A caller that only CHECKS, or that skips the stored members, under the
/// same hint: a range with no writer is hashed wide and written nowhere,
/// and a skipped member is counted as it was.
#[test]
fn checked_and_skipped_members_say_the_same() {
    let set = vec![spliced(true)];
    for take in [Take::Verify, Take::SkipVideo, Take::OnlyLast(b"ep3.mkv")] {
        let after = three_ways(&set, How { take, ..X });
        assert_eq!(after.ranges, 3, "every stored member is still read");
        let outcomes = after.said.outcomes.as_ref().expect("reads");
        match take {
            Take::Verify => {
                assert_eq!(outcomes.len(), 6);
                assert!(outcomes.iter().all(|(_, o)| o.checksum_ok == Some(true)));
                assert!(after.bytes.is_empty());
            }
            Take::SkipVideo => assert_eq!(after.bytes.len(), 3),
            _ => {
                assert_eq!(after.bytes.len(), 1);
                assert!(after.bytes[0].1 == videos()[2].1);
            }
        }
    }
}

/// `t` (no hint) never takes the solid path: the walk's own wide verify
/// reads a stored member, as before, and the knob is not in it.
#[test]
fn a_test_without_the_hint_is_untouched() {
    let set = vec![spliced(false)];
    probe::reset_wide_verifies();
    let after = three_ways(
        &set,
        How {
            take: Take::Verify,
            sink_is_file: None,
            ..X
        },
    );
    assert_eq!(after.ranges, 0);
    assert_eq!(after.solid, 0);
    assert!(
        probe::wide_verifies() >= 3,
        "the walk's wide verify did not run"
    );
}

/// One damaged byte inside a handed range: the member's verdict is a
/// checksum failure, with the same bytes written, and the set carries on.
#[test]
fn a_damaged_stored_member_fails_its_checksum_the_same_way() {
    let mut set = vec![spliced(false)];
    // Inside the second stored member's data: past the first video and
    // the first subtitle's blocks, well inside the 21 MiB that follow.
    let at = (17 << 20) + (2 << 20) + (9 << 20);
    set[0][at] ^= 0x10;
    let after = three_ways(&set, X);
    let outcomes = after
        .said
        .outcomes
        .as_ref()
        .expect("the set reads to its end");
    let failed: Vec<&[u8]> = outcomes
        .iter()
        .filter(|(_, o)| o.checksum_ok == Some(false))
        .map(|(n, _)| n.as_slice())
        .collect();
    assert_eq!(failed, [b"ep2.mkv".as_slice()]);
    assert_eq!(after.said.report.map(|r| r.2), Some(1));
    assert_eq!(after.ranges, 3);
}

/// An archive cut short inside a handed range ends the read where the
/// serial read ends it, naming the same member and offset, after the
/// bytes that were there were written.
#[test]
fn a_truncated_stored_member_ends_the_read_the_same_way() {
    let mut set = vec![spliced(false)];
    set[0].truncate((17 << 20) + (2 << 20) + (9 << 20) + 123);
    let after = three_ways(&set, X);
    let error = after
        .said
        .outcomes
        .as_ref()
        .expect_err("a cut archive fails");
    assert!(error.starts_with("Truncated"), "{error}");
}

/// A writer that refuses part way through a handed member ends the read
/// with the caller's error on every arm, and neither thread is left
/// parked: the call returns.
#[test]
fn a_refusing_writer_ends_the_read_on_every_arm() {
    let set = vec![spliced(false)];
    for limit in [0, (5 << 20) + 1, (16 << 20) + 9] {
        for arm in [Arm::Sequential, Arm::Before, Arm::After] {
            let read = read(
                &set,
                arm,
                How {
                    limit: Some(limit),
                    ..X
                },
            );
            let error = read
                .said
                .outcomes
                .expect_err("a full writer fails the read");
            assert!(error.starts_with("Caller"), "{arm:?} at {limit}: {error}");
        }
    }
}

/// A cancel raised part way through a handed member stops every arm with
/// `Cancelled`.
#[test]
fn a_raised_cancel_stops_every_arm() {
    let set = all_stored(None);
    for arm in [Arm::Sequential, Arm::Before, Arm::After] {
        let read = read(
            &set,
            arm,
            How {
                cancel_after: Some(20 << 20),
                ..X
            },
        );
        let error = read.said.outcomes.expect_err("a cancelled read fails");
        assert!(error.starts_with("Cancelled"), "{arm:?}: {error}");
    }
}

/// Reference `rar -s -ms`: stored members first, in the middle and last
/// with the compressed chain across them, one archive and volumes the
/// stored members cross.
#[test]
fn reference_rar_sets_with_stored_members_are_handed() {
    for (tag, extra) in [("one", &[][..]), ("vol", &["-v19926037b"][..])] {
        let Some(set) = reference_set(tag, extra) else {
            eprintln!("    reference `rar` is not on the path; skipped");
            return;
        };
        let after = three_ways(&set, X);
        whole(&after, &reference_members());
        assert!(after.ranges >= 3, "{tag}: only {} ranges", after.ranges);
    }
}

/// The same sets ENCRYPTED (`-p` and `-hp`). An encrypted stored member's
/// pieces are deciphered wide on the walk's side, where its key is,
/// so nothing of it is handed: the knob leaves it as it was, and
/// the three arms still agree.
#[test]
fn encrypted_reference_sets_are_left_on_the_walk() {
    for (tag, extra) in [
        ("p", &["-psolidstore"][..]),
        ("hp", &["-hpsolidstore"][..]),
        ("hpvol", &["-hpsolidstore", "-v19926037b"][..]),
    ] {
        let Some(set) = reference_set(tag, extra) else {
            eprintln!("    reference `rar` is not on the path; skipped");
            return;
        };
        let after = three_ways(
            &set,
            How {
                password: Some(SECRET),
                solid: !tag.starts_with("hp"),
                ..X
            },
        );
        whole(&after, &reference_members());
        assert_eq!(after.ranges, 0, "{tag}: an encrypted range was handed");
    }
}
