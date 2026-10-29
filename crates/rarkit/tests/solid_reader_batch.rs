//! A SOLID set whose members arrive as READERS, encoded in batches (the
//! solid -m5 work, 28 Sep
//! 2026).
//!
//! **The claim is that a batch is a WIDTH and never a byte.** The command
//! line hands the writer every member as a `Payload::Reader`, and until
//! this change a solid reader was encoded a member at a time: one parse
//! block per flush, walked and parsed on the writing thread. Now a run of
//! reader members of at most one window is pulled whole, in `add` order,
//! and staged as one batch, whose small members the tree's walk takes
//! together (`Engine::with_tree`'s passes). Every row here writes one set
//! three ways - bytes a member at a time (batch depth 1, the control),
//! bytes batched, readers batched - and compares the archives byte for
//! byte, then reads the batched one back and compares every member with
//! its input.
//!
//! One set is built so that a member of several parse blocks STRADDLES
//! the boundary between two waves of the tree's hints: a wave that ended
//! inside that member's walk group would walk the group as two, with
//! other comparison limits, and the member-at-a-time archive would be
//! lost. The walk takes whole groups into a wave, and this row holds it
//! to that.
//!
//! A reader that is short, or longer than it declared, ends the write at
//! ITS member, with the error a member at a time meets, and nothing after
//! it is pulled.
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, Disposition, Entropy, ErrorKind, MemberInfo, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// A member of a test set.
struct Entry {
    name: Vec<u8>,
    bytes: Vec<u8>,
    directory: bool,
}

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

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// `count` small members, of up to 16 KiB, with an empty member and a
/// directory scattered through them.
fn small_set(count: usize, seed: u64) -> Vec<Entry> {
    let mut state = seed | 1;
    (0..count)
        .map(|i| {
            let pick = xorshift(&mut state);
            let (len, directory) = match i % 31 {
                9 => (0, false),
                17 => (0, true),
                _ => ((pick % 16_384) as usize + 1, false),
            };
            Entry {
                name: if directory {
                    format!("d{i:04}").into_bytes()
                } else {
                    format!("d/f{i:04}.txt").into_bytes()
                },
                bytes: rarkit_testdata::chatter(pick, len),
                directory,
            }
        })
        .collect()
}

/// Five members of three parse blocks, then one of four and a few small
/// ones, all in one batch at a 2 MiB dictionary (whose batch holds 8 MiB):
/// the tree's hints hold sixteen blocks, so the member of four blocks, one
/// walk group, starts at the sixteenth and runs past the wave.
fn straddling_set() -> Vec<Entry> {
    let mut entries: Vec<Entry> = (0..5)
        .map(|i| Entry {
            name: format!("three{i}.txt").into_bytes(),
            bytes: rarkit_testdata::chatter(100 + i as u64, 700_000 + i * 1_000),
            directory: false,
        })
        .collect();
    entries.push(Entry {
        name: b"four.txt".to_vec(),
        bytes: rarkit_testdata::chatter(200, 1_000_000),
        directory: false,
    });
    entries.extend((0..6).map(|i| Entry {
        name: format!("tail{i}.txt").into_bytes(),
        bytes: rarkit_testdata::chatter(300 + i as u64, 3_000 + i * 500),
        directory: false,
    }));
    entries
}

/// A reader that notes each member it is read from, in order, and may
/// end short of its length or run past it.
struct Logged<'a> {
    index: usize,
    bytes: &'a [u8],
    at: usize,
    end: usize,
    /// Bytes it yields past `end`, for a reader longer than declared.
    extra: usize,
    log: Arc<Mutex<Vec<usize>>>,
}

impl Read for Logged<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.log.lock().unwrap().push(self.index);

        if self.at >= self.end {
            let n = buffer.len().min(self.extra);
            buffer[..n].fill(b'!');
            self.extra -= n;
            return Ok(n);
        }
        let n = buffer.len().min(self.end - self.at);
        buffer[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

fn options(format: WriteFormat, level: u8, dictionary: Option<u64>) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed { level, dictionary },
        solid: true,
        // The reads are checked in `add` order.
        order: rarkit::MemberOrder::AsAdded,
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::default()
        },
        entropy: Entropy::Seeded([9; 32]),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

/// How a member is handed over, and what its reader does.
#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Bytes,
    Readers,
    /// Readers, member `.0` stopping at half its length.
    Short(usize),
    /// Readers, member `.0` yielding one byte more than it declared.
    Long(usize),
}

/// Writes `entries` as one seekable archive, as the command line does,
/// at batch depth `depth`, and returns it with the order of the reads.
fn write(
    entries: &[Entry],
    shape: Shape,
    options: WriteOptions,
    depth: usize,
) -> (Result<Vec<u8>>, Vec<usize>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut readers: Vec<Logged<'_>> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| Logged {
            index,
            bytes: &entry.bytes,
            at: 0,
            end: match shape {
                Shape::Short(at) if at == index => entry.bytes.len() / 2,
                _ => entry.bytes.len(),
            },
            extra: match shape {
                Shape::Long(at) if at == index => 1,
                _ => 0,
            },
            log: Arc::clone(&log),
        })
        .collect();
    let written = rarkit::internals::writers::with_batch_depth(depth, || {
        let mut writer = Writer::new(options).expect("options");
        for (entry, reader) in entries.iter().zip(readers.iter_mut()) {
            let payload = if shape != Shape::Bytes && !entry.directory && !entry.bytes.is_empty() {
                Payload::Reader {
                    reader,
                    size: entry.bytes.len() as u64,
                    crc32: None,
                }
            } else {
                Payload::Bytes(&entry.bytes)
            };
            writer
                .add(MemberSpec {
                    name: &entry.name,
                    payload,
                    mtime: None,
                    attributes: if entry.directory { 0o40755 } else { 0o100644 },
                    host_os: rarkit::HostOs::Unix,
                    is_directory: entry.directory,
                })
                .expect("add");
        }
        let mut out = Cursor::new(Vec::new());
        writer.finish_seek(&mut out).map(|_| out.into_inner())
    });
    drop(readers);
    let log = log.lock().unwrap().clone();
    (written, log)
}

/// Reads an archive back and compares every file member with its input.
fn assert_reads_back(archive: &[u8], entries: &[Entry], what: &str) {
    let sources = vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: reading back what this writer wrote: {e}"));
    let files: Vec<(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .filter(|entry| !entry.directory)
        .map(|entry| (entry.name.clone(), entry.bytes.clone()))
        .collect();
    let got: Vec<(Vec<u8>, Vec<u8>)> = sink
        .members
        .into_iter()
        .filter(|(name, _)| files.iter().any(|(want, _)| want == name))
        .collect();
    assert!(got == files, "{what}: a member read back differently");
}

/// One row: what it is, the format, the level, the dictionary and the set.
type Row = (&'static str, WriteFormat, u8, Option<u64>, Vec<Entry>);

/// The claim: readers batched, bytes batched and bytes a member at a time
/// are one archive, and every reader is pulled once, in `add` order.
#[test]
fn solid_readers_batched_write_the_member_at_a_time_archive() {
    let rows: Vec<Row> = vec![
        (
            "rar5 m5 small",
            WriteFormat::Rar5,
            5,
            None,
            small_set(300, 3),
        ),
        (
            "rar5 m3 small",
            WriteFormat::Rar5,
            3,
            None,
            small_set(200, 4),
        ),
        (
            "rar4 m5 small",
            WriteFormat::Rar4(rarkit::Rar4Version::V29),
            5,
            None,
            small_set(150, 5),
        ),
        // More members than a batch holds (1,024), so the second and
        // third batches' readers are pulled while the batch before them
        // is encoded.
        (
            "rar5 m1 many",
            WriteFormat::Rar5,
            1,
            None,
            small_set(2_100, 6),
        ),
        (
            "rar5 m4 straddle",
            WriteFormat::Rar5,
            4,
            Some(2 << 20),
            straddling_set(),
        ),
    ];
    for (what, format, level, dictionary, entries) in rows {
        let (control, _) = write(
            &entries,
            Shape::Bytes,
            options(format, level, dictionary),
            1,
        );
        let control = control.unwrap_or_else(|e| panic!("{what}: control: {e}"));
        assert_reads_back(&control, &entries, what);
        let (bytes, _) = write(
            &entries,
            Shape::Bytes,
            options(format, level, dictionary),
            1024,
        );
        assert!(
            bytes.expect("bytes batched") == control,
            "{what}: bytes batched moved a byte"
        );
        let (readers, log) = write(
            &entries,
            Shape::Readers,
            options(format, level, dictionary),
            1024,
        );
        assert!(
            readers.expect("readers batched") == control,
            "{what}: readers batched moved a byte"
        );
        // Each reader is read in one run of reads, the runs in `add`
        // order, and every member with bytes is read.
        let mut runs = log.clone();
        runs.dedup();
        let pulled: Vec<usize> = (0..entries.len())
            .filter(|&i| !entries[i].directory && !entries[i].bytes.is_empty())
            .collect();
        assert!(
            runs == pulled,
            "{what}: the readers were not pulled once each, in order"
        );
    }
}

/// A reader that ends short, or runs past its declared length, inside a
/// batch ends the write with a member at a time's error, and nothing
/// after it is pulled, also where its pull is made ahead, beside the
/// batch before it.
#[test]
fn a_bad_reader_in_a_solid_batch_ends_the_write_at_its_member() {
    // The bad member in the SECOND batch, so its pull is the one made
    // while the first batch is encoded.
    let entries = small_set(1_200, 8);
    let bad = (1_060..entries.len())
        .find(|&i| !entries[i].directory && entries[i].bytes.len() > 100)
        .expect("a member with bytes");
    for (shape, wants) in [
        (Shape::Short(bad), "Truncated"),
        (Shape::Long(bad), "PayloadLength"),
    ] {
        for depth in [1, 1024] {
            let (written, log) = write(&entries, shape, options(WriteFormat::Rar5, 1, None), depth);
            let error = written.expect_err("a bad reader is an error");
            let kind = format!("{:?}", error.kind());
            assert!(
                kind.contains(wants),
                "depth {depth}: wanted {wants}, got {kind} ({error})"
            );
            if wants == "Truncated" {
                assert!(matches!(error.kind(), ErrorKind::Truncated));
            }
            assert!(
                log.iter().all(|&index| index <= bad),
                "depth {depth}: a member after the bad one was pulled"
            );
        }
    }
}
