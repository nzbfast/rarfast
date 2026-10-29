//! `WriteOptions::encrypted_read_ahead` (SPEC-API 7.1):
//! stored encrypted members enciphered AHEAD of the writer, written in
//! order, make the archive the walk without the option makes, to the byte.
//!
//! The entropy is SEEDED, so both walks draw from the same stream, and the
//! chains ahead are given their vectors in the order the walk without them
//! draws them (spec G 3.13). The archive with the option on is compared
//! with the archive with it off: one archive under `-p` and `-hp`, a
//! volume set under `-p` whose members cross volumes, CRC32 and BLAKE2sp,
//! one to four chains, a held-bytes cap small enough to park a chain. A
//! count says the chains ran where they were meant to and nowhere else:
//! not without the option, not at one worker, not in a `-hp` volume set.
//! A reader that fails part way leaves the output and the error of the
//! walk without the option, whichever member fails first. Without the
//! option no reader is touched before the member before it is done. And
//! the peak the writer states stays inside a named ceiling.

use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rarkit::internals::writers::{
    chain_members, chain_stall, reset_chain_members, with_chains_ahead,
};
use rarkit::{
    extract, ChecksumKind, Disposition, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Password, Payload, RangeSource, ReadOptions, Result, Sink, VolumeOut, WriteMethod,
    WriteOptions, WriteReport, Writer,
};

const PASSWORD: &str = "ahead of the writer";

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as u8
        })
        .collect()
}

/// A reader that fails once `fail_at` bytes have been read, and says, on
/// its first read, how many reads every reader of the set had made before.
struct Watched<'d> {
    data: &'d [u8],
    at: usize,
    fail_at: Option<usize>,
    clock: &'d AtomicUsize,
    first: Option<usize>,
    last: usize,
}

impl Read for Watched<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let tick = self.clock.fetch_add(1, Ordering::SeqCst);
        self.first.get_or_insert(tick);
        self.last = tick;
        if self.fail_at.is_some_and(|limit| self.at >= limit) {
            return Err(std::io::Error::other("the reader failed"));
        }
        let end = self
            .fail_at
            .map_or(self.data.len(), |limit| limit.min(self.data.len()));
        let n = buf.len().min(end - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

#[derive(Clone)]
struct Shape {
    headers: bool,
    checksum: ChecksumKind,
    workers: usize,
    volume: Option<u64>,
    ahead: bool,
    memory: Option<MemoryPolicy>,
}

fn options(shape: &Shape) -> WriteOptions {
    WriteOptions {
        method: WriteMethod::Stored,
        password: Some(Password::new(PASSWORD)),
        encrypt_headers: shape.headers,
        checksum: shape.checksum,
        entropy: rarkit::Entropy::Seeded([9u8; 32]),
        workers: Some(shape.workers),
        volume_size: shape.volume,
        encrypted_read_ahead: shape.ahead,
        memory: shape.memory.unwrap_or_default(),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

struct Volumes(Vec<Vec<u8>>);

impl VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> Result<()> {
        self.0.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// What one write left: its volumes (one for a single archive), its
/// outcome, how many members came from a chain ahead, and whether any
/// reader was first read before the reader before it was last read.
struct Wrote {
    volumes: Vec<Vec<u8>>,
    outcome: Result<WriteReport>,
    from_chains: usize,
    overlapped: bool,
}

/// The set: `(bytes, is a directory)`. `fail` names members whose readers
/// fail after that many bytes.
fn write(shape: &Shape, members: &[(Vec<u8>, bool)], fail: &[(usize, usize)]) -> Wrote {
    let clock = AtomicUsize::new(0);
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i:02}.bin").into_bytes())
        .collect();
    let mut readers: Vec<Watched<'_>> = members
        .iter()
        .enumerate()
        .map(|(i, (data, _))| Watched {
            data,
            at: 0,
            fail_at: fail.iter().find(|(member, _)| *member == i).map(|f| f.1),
            clock: &clock,
            first: None,
            last: 0,
        })
        .collect();
    reset_chain_members();
    let mut volumes = Volumes(Vec::new());
    let outcome = {
        let mut writer = Writer::new(options(shape)).expect("options");
        for ((name, (data, directory)), reader) in names.iter().zip(members).zip(readers.iter_mut())
        {
            let payload = if *directory {
                Payload::Bytes(&[])
            } else {
                Payload::Reader {
                    reader: reader as &mut (dyn Read + Send),
                    size: data.len() as u64,
                    crc32: None,
                }
            };
            writer
                .add(MemberSpec {
                    name,
                    payload,
                    mtime: None,
                    attributes: if *directory { 0o755 } else { 0o644 },
                    host_os: rarkit::HostOs::Unix,
                    is_directory: *directory,
                })
                .expect("add");
        }
        if shape.volume.is_some() {
            writer.finish_volumes(&mut volumes)
        } else {
            let mut out = Cursor::new(Vec::new());
            let outcome = writer.finish_seek(&mut out);
            volumes.0.push(out.into_inner());
            outcome
        }
    };
    let read: Vec<(usize, usize)> = readers
        .iter()
        .filter_map(|reader| reader.first.map(|first| (first, reader.last)))
        .collect();
    let overlapped = read.windows(2).any(|pair| pair[1].0 < pair[0].1);
    Wrote {
        volumes: volumes.0,
        outcome,
        from_chains: chain_members(),
        overlapped,
    }
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
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "a member failed its checksum"
        );
        if let (Some(bytes), Some(last)) = (out, self.0.last_mut()) {
            *last = bytes;
        }
        Ok(())
    }
}

fn read_back(volumes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let options = ReadOptions::default().with_password(Some(Password::new(PASSWORD)));
    extract(sources, &options, &mut sink, &mut ()).unwrap_or_else(|e| panic!("reading back: {e}"));
    sink.0
}

/// Stored members big enough for a chain, with a directory, an empty file
/// and a small file between them.
fn members() -> Vec<(Vec<u8>, bool)> {
    vec![
        (noise(4 << 20, 1), false),
        (noise((5 << 20) + 5, 2), false),
        (Vec::new(), true),
        (noise((4 << 20) + 16, 3), false),
        (Vec::new(), false),
        (noise(70_001, 4), false),
        (noise((6 << 20) + 1, 5), false),
        (noise(4 << 20, 6), false),
        (noise((4 << 20) + 3, 7), false),
    ]
}

fn shapes() -> Vec<(Shape, bool)> {
    let mut shapes = Vec::new();
    for (headers, volume) in [
        (false, None),
        (true, None),
        (false, Some(3_000_000u64)),
        (true, Some(3_000_000)),
    ] {
        for checksum in [ChecksumKind::Crc32, ChecksumKind::Blake2sp] {
            for workers in [1usize, 2, 8] {
                // Where the chains are meant to run: more than one worker,
                // and not a volume set under encrypted headers.
                let reached = workers >= 2 && !(headers && volume.is_some());
                shapes.push((
                    Shape {
                        headers,
                        checksum,
                        workers,
                        volume,
                        ahead: false,
                        memory: None,
                    },
                    reached,
                ));
            }
        }
    }
    shapes
}

/// The seeded byte-identity pin: with the option on the archive is the
/// archive without it, in every shape, and the chains ran exactly where
/// they are meant to.
#[test]
fn chains_ahead_write_the_same_archive() {
    let members = members();
    for (shape, reached) in shapes() {
        let what = format!(
            "headers={} {:?} workers={} volume={:?}",
            shape.headers, shape.checksum, shape.workers, shape.volume
        );
        let plain = write(&shape, &members, &[]);
        plain
            .outcome
            .as_ref()
            .unwrap_or_else(|e| panic!("{what}: without the option: {e}"));
        assert_eq!(plain.from_chains, 0, "{what}: chains without the option");
        let back = read_back(&plain.volumes);
        assert_eq!(back.len(), members.len(), "{what}: members read back");
        for (got, (want, _)) in back.iter().zip(&members) {
            assert!(got == want, "{what}: a member read back differs");
        }
        let on = Shape {
            ahead: true,
            ..shape.clone()
        };
        for (chains, cap) in [
            (1, None),
            (4, None),
            (3, Some(40 << 20)),
            (2, Some(1 << 20)),
        ] {
            let ahead = with_chains_ahead(chains, cap, || write(&on, &members, &[]));
            ahead
                .outcome
                .as_ref()
                .unwrap_or_else(|e| panic!("{what} chains={chains}: {e}"));
            assert!(
                ahead.volumes == plain.volumes,
                "{what} chains={chains} cap={cap:?}: the archive differs"
            );
            // A cap under the least budget worth a chain keeps the walk
            // without them.
            let runs = reached && cap.is_none_or(|cap| cap >= 32 << 20);
            assert_eq!(
                ahead.from_chains > 0,
                runs,
                "{what} chains={chains} cap={cap:?}: {} members came from chains",
                ahead.from_chains
            );
        }
        // The default count of chains, as shipped.
        let shipped = write(&on, &members, &[]);
        assert!(shipped.volumes == plain.volumes, "{what}: as shipped");
        assert_eq!(shipped.from_chains > 0, reached, "{what}: as shipped");
    }
}

/// Without the option no reader is read before the reader before it is
/// done (SPEC-API 7.1's promise), at any width; with it, readers overlap.
#[test]
fn the_default_reads_no_reader_ahead() {
    let members = members();
    let mut overlapped = false;
    for (shape, reached) in shapes() {
        let plain = with_chains_ahead(3, None, || write(&shape, &members, &[]));
        assert!(
            !plain.overlapped,
            "a reader was read ahead without the option"
        );
        assert_eq!(plain.from_chains, 0);
        if reached {
            let on = Shape {
                ahead: true,
                ..shape
            };
            overlapped |= write(&on, &members, &[]).overlapped;
        }
    }
    assert!(overlapped, "no reader was ever read ahead under the option");
}

/// A reader that fails part way: the output and the error are the walk's
/// without the option, whichever member fails, and when two fail the
/// first in archive order is the one reported.
#[test]
fn a_failing_reader_leaves_the_same_output_and_error() {
    let members = members();
    for (shape, _) in shapes() {
        let what = format!(
            "headers={} {:?} workers={} volume={:?}",
            shape.headers, shape.checksum, shape.workers, shape.volume
        );
        let on = Shape {
            ahead: true,
            ..shape.clone()
        };
        for fail in [
            vec![(6usize, (3usize << 20) + 77)],
            vec![(0, 100)],
            vec![(8, 4 << 20)],
            vec![(3, 2 << 20), (6, 10)],
            vec![(7, 0), (6, 5 << 20)],
        ] {
            let plain = write(&shape, &members, &fail);
            let plain_error = format!("{:?}", plain.outcome.expect_err("it must fail"));
            for chains in [1, 3] {
                let ahead = with_chains_ahead(chains, None, || write(&on, &members, &fail));
                let ahead_error = format!("{:?}", ahead.outcome.expect_err("it must fail"));
                assert_eq!(
                    ahead_error, plain_error,
                    "{what} fail={fail:?} chains={chains}"
                );
                assert!(
                    ahead.volumes == plain.volumes,
                    "{what} fail={fail:?} chains={chains}: the output differs"
                );
            }
        }
    }
}

/// What the chains hold is charged: the peak the writer states stays
/// inside a named ceiling, and without a ceiling it says what was held.
#[test]
fn the_stated_peak_stays_inside_a_named_ceiling() {
    // Members of 48 MiB: three chains ahead would hold 96 MiB and more.
    let members: Vec<(Vec<u8>, bool)> = (0..6).map(|i| (noise(48 << 20, 20 + i), false)).collect();
    let base = Shape {
        headers: true,
        checksum: ChecksumKind::Crc32,
        workers: 8,
        volume: None,
        ahead: true,
        memory: None,
    };
    let free = write(&base, &members, &[]);
    let free_peak = free.outcome.expect("no ceiling").peak_working_memory;
    assert!(free.from_chains > 0, "no chain ran");
    assert!(
        free_peak >= 48 << 20,
        "chains ran and the stated peak is {free_peak}"
    );
    for limit in [512u64 << 20, 160 << 20] {
        let named = Shape {
            memory: Some(MemoryPolicy::from_limit(limit)),
            ..base.clone()
        };
        let wrote = write(&named, &members, &[]);
        let report = wrote.outcome.expect("a named ceiling");
        assert!(wrote.volumes == free.volumes, "limit {limit}: the archive");
        assert_eq!(
            report.ceiling_exceeded_by, None,
            "limit {limit}: the stated peak {} passed the ceiling",
            report.peak_working_memory
        );
    }
    // A ceiling with no room for a chain keeps the walk without them.
    let tight = Shape {
        memory: Some(MemoryPolicy::from_limit(100 << 20)),
        ..base
    };
    let wrote = write(&tight, &members, &[]);
    wrote.outcome.expect("a tight ceiling");
    assert_eq!(wrote.from_chains, 0, "a chain under a ceiling with no room");
    assert!(wrote.volumes == free.volumes, "the tight archive");
}

/// **A volume set whose fragments are long and do not line up with the
/// chains' buffers completes, under a budget smaller than a member**
/// (found 2 Oct 2026 on a Zen 4 rental: `-m0 -p -v1g -mm512m` of eight
/// members slept for ever, every thread parked). The write runs under a
/// DEADLINE, so a wedge fails here with where it stood instead of hanging
/// the suite; and the archive is the one without the option.
#[test]
fn a_volume_set_under_a_small_budget_does_not_wedge() {
    // Members of 44 to 56 MiB, LARGER than the budgets below, so a chain is
    // still enciphering when the writer takes from it; volumes of about
    // 21 MiB: fragments of 4 MiB and more, starting at offsets that are no
    // multiple of a buffer.
    let members: Vec<(Vec<u8>, bool)> = (0..4)
        .map(|i| {
            (
                noise((44 << 20) + (i << 22) + 4_099 * (i + 1), 40 + i as u64),
                false,
            )
        })
        .collect();
    for (limit, cap) in [
        (Some(130u64 << 20), None),
        (None, Some(34u64 << 20)),
        (None, None),
    ] {
        let shape = Shape {
            headers: false,
            checksum: ChecksumKind::Crc32,
            workers: 8,
            volume: Some((21 << 20) + 1_234),
            ahead: false,
            memory: limit.map(MemoryPolicy::from_limit),
        };
        let plain = write(&shape, &members, &[]);
        plain.outcome.as_ref().expect("without the option");
        let on = Shape {
            ahead: true,
            ..shape
        };
        let set = members.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let wrote = with_chains_ahead(3, cap, || write(&on, &set, &[]));
            let _ = done_tx.send((wrote.volumes, wrote.outcome.is_ok(), wrote.from_chains));
        });
        let what = format!("limit={limit:?} cap={cap:?}");
        match done_rx.recv_timeout(std::time::Duration::from_secs(120)) {
            Ok((volumes, ok, from_chains)) => {
                assert!(ok, "{what}: the write failed");
                assert!(from_chains > 0, "{what}: no chain ran");
                assert!(volumes == plain.volumes, "{what}: the archive differs");
            }
            Err(_) => panic!(
                "{what}: WEDGED, no archive after 120 s; the last stall: {:?}",
                chain_stall()
            ),
        }
    }
}

/// **No reached shape wedges under a budget smaller than its members**: a
/// wedge is silent in a green suite, so every reached shape is written
/// under a DEADLINE: one archive under `-p` and `-hp`, a `-p` volume set
/// at three volume sizes (fragments shorter and longer than the read
/// ahead's floor, none a multiple of a buffer), under a named ceiling and
/// under a held-bytes cap that park a chain, at 2, 4 and 12 workers. Each
/// archive is the one without the option.
#[test]
fn no_reached_shape_wedges_under_a_budget_smaller_than_its_members() {
    let members: Vec<(Vec<u8>, bool)> = (0..3)
        .map(|i| {
            (
                noise((36 << 20) + (i << 21) + 811 * (i + 1), 60 + i as u64),
                false,
            )
        })
        .collect();
    for (headers, volume) in [
        (false, None),
        (true, None),
        (false, Some((3u64 << 20) + 77)),
        (false, Some((9 << 20) + 4_099)),
        (false, Some((30 << 20) + 1_234)),
    ] {
        let shape = Shape {
            headers,
            checksum: ChecksumKind::Crc32,
            workers: 1,
            volume,
            ahead: false,
            memory: None,
        };
        let plain = write(&shape, &members, &[]);
        plain.outcome.as_ref().expect("without the option");
        let plain = Arc::new(plain.volumes);
        for (limit, cap) in [(Some(130u64 << 20), None), (None, Some(33u64 << 20))] {
            for workers in [2usize, 4, 12] {
                let on = Shape {
                    workers,
                    ahead: true,
                    memory: limit.map(MemoryPolicy::from_limit),
                    ..shape.clone()
                };
                let set = members.clone();
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let wrote = with_chains_ahead(3, cap, || write(&on, &set, &[]));
                    let _ = done_tx.send((wrote.volumes, wrote.outcome.is_ok(), wrote.from_chains));
                });
                let what = format!(
                    "headers={headers} volume={volume:?} limit={limit:?} cap={cap:?} workers={workers}"
                );
                match done_rx.recv_timeout(std::time::Duration::from_secs(120)) {
                    Ok((volumes, ok, from_chains)) => {
                        assert!(ok, "{what}: the write failed");
                        assert!(from_chains > 0, "{what}: no chain ran");
                        assert!(volumes == *plain, "{what}: the archive differs");
                    }
                    Err(_) => panic!(
                        "{what}: WEDGED, no archive after 120 s; the last stall: {:?}",
                        chain_stall()
                    ),
                }
            }
        }
    }
}

/// **A member given as a source that can SEEK is read ahead as a reader
/// is** (`Payload::Seekable`, which is how `rarfast` hands every regular
/// file to the writer): the run turns such a source into the reader it is
/// before it plans anything, so the chains take it. Every member here is
/// seekable; with the option on members come from chains and the archive
/// is the one without it, in one archive under `-p` and `-hp` and in a
/// `-p` volume set.
#[test]
fn a_seekable_payload_is_read_ahead_as_a_reader_is() {
    let members: Vec<Vec<u8>> = (0..5)
        .map(|i| noise((4 << 20) + (i << 19) + 31 * (i + 1), 80 + i as u64))
        .collect();
    let write = |shape: &Shape| -> (Vec<Vec<u8>>, usize) {
        let names: Vec<Vec<u8>> = (0..members.len())
            .map(|i| format!("m{i:02}.bin").into_bytes())
            .collect();
        let mut sources: Vec<Cursor<&[u8]>> =
            members.iter().map(|data| Cursor::new(&data[..])).collect();
        reset_chain_members();
        let mut writer = Writer::new(options(shape)).expect("options");
        for ((name, data), source) in names.iter().zip(&members).zip(sources.iter_mut()) {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Seekable {
                        reader: source,
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
        let mut volumes = Volumes(Vec::new());
        if shape.volume.is_some() {
            writer.finish_volumes(&mut volumes).expect("finish_volumes");
        } else {
            let mut out = Cursor::new(Vec::new());
            writer.finish_seek(&mut out).expect("finish_seek");
            volumes.0.push(out.into_inner());
        }
        (volumes.0, chain_members())
    };
    for (headers, volume) in [(false, None), (true, None), (false, Some(3_000_000u64))] {
        let off = Shape {
            headers,
            checksum: ChecksumKind::Crc32,
            workers: 8,
            volume,
            ahead: false,
            memory: None,
        };
        let on = Shape {
            ahead: true,
            ..off.clone()
        };
        let what = format!("headers={headers} volume={volume:?}");
        let (plain, none) = write(&off);
        assert_eq!(none, 0, "{what}: chains without the option");
        let (ahead, from_chains) = write(&on);
        assert!(
            from_chains > 0,
            "{what}: no seekable member came from a chain"
        );
        assert!(ahead == plain, "{what}: the archive differs");
        let back = read_back(&ahead);
        assert_eq!(back.len(), members.len(), "{what}: members read back");
        for (got, want) in back.iter().zip(&members) {
            assert!(got == want, "{what}: a member read back differs");
        }
    }
}
