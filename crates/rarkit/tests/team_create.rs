//! The WORKER TEAM of a non-solid compressed write: members of at most
//! one parse block encoded ahead, several at once, by crews of their own,
//! and written in `add` order by the writing thread.
//!
//! **The claim is that the team is a WIDTH and never a byte.** Every row
//! here writes one set twice, once with `WriteOptions::workers` at one,
//! which is the member-at-a-time walk (`Run::team_width` below two), and
//! once wide, and compares the two archives byte for byte; then reads the
//! wide one back through this crate's reader and compares every member
//! with its input. A row whose team did not run proves nothing, so each
//! says that it did (`internals::writers::team_prepared`), wherever the
//! test's pool has room for a crew at all.
//!
//! The sets mix what the team takes with what it does not - an empty
//! member, a directory, a member over one parse block - so the walk's
//! seams between a team batch and a member it writes by itself are
//! crossed many times. Reader payloads are pulled in `add` order, which a
//! row below records read by read; one whose reader is short ends the
//! write with `Truncated` and pulls nothing after it.
use std::io::Read;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, ChecksumKind, Disposition, Entropy, ErrorKind, MemberInfo, MemberSpec, Password,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, Sink, VolumeOut, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

/// A member of a test set: its name, its bytes, and whether it is a
/// directory.
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

/// Collects a volume set's volumes.
#[derive(Default)]
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
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// A set of `count` members: mostly small, with an empty member, a
/// directory and a member over one parse block (256 KiB) scattered
/// through it, so the team's batches are cut by members it does not take.
fn set(count: usize, seed: u64) -> Vec<Entry> {
    let mut state = seed | 1;
    (0..count)
        .map(|i| {
            let pick = xorshift(&mut state);
            let (len, directory) = match i % 29 {
                7 => (0, false),
                13 => (0, true),
                23 => (300 << 10, false),
                _ => ((pick % 20_000) as usize + 1, false),
            };
            let name = if directory {
                format!("dir{i:04}").into_bytes()
            } else {
                format!("dir/file{i:04}.txt").into_bytes()
            };
            Entry {
                name,
                bytes: rarkit_testdata::chatter(pick, len),
                directory,
            }
        })
        .collect()
}

/// A reader that notes the index of every member it is read from, in the
/// order the reads happen, and that may end early.
struct Logged<'a> {
    index: usize,
    bytes: &'a [u8],
    at: usize,
    /// Where it stops, short of its declared length when a row wants it to.
    end: usize,
    log: Arc<Mutex<Vec<usize>>>,
}

impl Read for Logged<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.log.lock().unwrap().push(self.index);
        let n = buffer.len().min(self.end - self.at);
        buffer[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// The options every row starts from.
fn options(format: WriteFormat, level: u8, workers: usize) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::default()
        },
        entropy: Entropy::Seeded([7; 32]),
        workers: Some(workers),
        ..WriteOptions::default()
    }
}

/// How a row hands its members over.
#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Bytes,
    Readers,
}

/// Writes `entries` once as ONE archive, or as a volume set of `volume`
/// bytes, and returns the volumes and the order the readers were read in.
fn write(
    entries: &[Entry],
    shape: Shape,
    options: WriteOptions,
    volume: Option<u64>,
) -> (Result<Vec<Vec<u8>>>, Vec<usize>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut readers: Vec<Logged<'_>> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| Logged {
            index,
            bytes: &entry.bytes,
            at: 0,
            end: entry.bytes.len(),
            log: Arc::clone(&log),
        })
        .collect();
    let options = WriteOptions {
        volume_size: volume,
        ..options
    };
    let mut writer = Writer::new(options).expect("options");
    for (entry, reader) in entries.iter().zip(readers.iter_mut()) {
        let payload = if shape == Shape::Readers && !entry.directory && !entry.bytes.is_empty() {
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
    let written = match volume {
        None => {
            let mut out = Vec::new();
            writer.finish_into(&mut out).map(|_| vec![out])
        }
        Some(_) => {
            let mut out = Volumes::default();
            writer.finish_volumes(&mut out).map(|_| out.0)
        }
    };
    drop(readers);
    let log = log.lock().unwrap().clone();
    (written, log)
}

/// Reads an archive back and compares every member with its input.
fn assert_reads_back(volumes: &[Vec<u8>], entries: &[Entry], password: Option<Password>) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let read = ReadOptions::default().with_password(password);
    extract(sources, &read, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what the team wrote: {e}"));
    assert_eq!(sink.members.len(), entries.len());
    for ((name, bytes), entry) in sink.members.iter().zip(entries) {
        assert_eq!(name, &entry.name);
        assert!(bytes == &entry.bytes, "member {:?} differs", entry.name);
    }
}

/// Whether the test's pool has room for a crew beside another, which is
/// the least a team needs to run at all.
fn pool_is_wide() -> bool {
    rayon::current_num_threads() >= 2
}

/// Writes `entries` narrow and wide and holds the two to one archive.
fn narrow_equals_wide(entries: &[Entry], shape: Shape, wide: WriteOptions, volume: Option<u64>) {
    let narrow = WriteOptions {
        workers: Some(1),
        ..clone_options(&wide)
    };
    rarkit::internals::writers::reset_team_prepared();
    let (one, _) = write(entries, shape, narrow, volume);
    assert_eq!(
        rarkit::internals::writers::team_prepared(),
        0,
        "one worker is the member-at-a-time walk"
    );
    let (many, _) = write(entries, shape, wide, volume);
    let took = rarkit::internals::writers::team_prepared();
    let (one, many) = (one.expect("narrow write"), many.expect("wide write"));
    assert!(one == many, "the team moved a byte of the archive");
    // Readers in a volume set are the team's too since 2 Oct 2026: they
    // were left to the member-at-a-time walk while a caller could only
    // read the member being written off its reader's first read
    // (`Progress::member_started` says it now; `tests/volume_reader_batch.rs`).
    if pool_is_wide() {
        assert!(took > entries.len() / 2, "the team encoded {took} members");
    }
    assert_reads_back(&many, entries, None);
}

/// `WriteOptions` is not `Clone` (its entropy may be a caller's source),
/// so a row that writes twice builds its second set of options from the
/// first's fields.
fn clone_options(options: &WriteOptions) -> WriteOptions {
    WriteOptions {
        format: options.format,
        method: options.method,
        password: options.password.clone(),
        encrypt_headers: options.encrypt_headers,
        solid: options.solid,
        volume_size: options.volume_size,
        checksum: options.checksum,
        filters: options.filters,
        entropy: match &options.entropy {
            Entropy::Seeded(seed) => Entropy::Seeded(*seed),
            _ => Entropy::Os,
        },
        workers: options.workers,
        memory: options.memory,
        ..WriteOptions::default()
    }
}

#[test]
fn every_level_writes_the_member_at_a_time_archive() {
    let entries = set(300, 1);
    for level in 1..=5 {
        narrow_equals_wide(
            &entries,
            Shape::Bytes,
            options(WriteFormat::Rar5, level, 4),
            None,
        );
    }
}

#[test]
fn the_rar4_family_writes_the_member_at_a_time_archive() {
    let entries = set(200, 2);
    for level in [1, 3, 5] {
        narrow_equals_wide(
            &entries,
            Shape::Bytes,
            options(WriteFormat::Rar4(Rar4Version::V29), level, 4),
            None,
        );
    }
}

#[test]
fn readers_write_the_member_at_a_time_archive_and_are_pulled_in_order() {
    let entries = set(300, 3);
    for level in [1, 3, 5] {
        narrow_equals_wide(
            &entries,
            Shape::Readers,
            options(WriteFormat::Rar5, level, 4),
            None,
        );
    }
    let (written, log) = write(
        &entries,
        Shape::Readers,
        options(WriteFormat::Rar5, 3, 8),
        None,
    );
    written.expect("wide write");
    let mut first_reads: Vec<usize> = Vec::new();
    for index in log {
        if first_reads.last() != Some(&index) {
            assert!(
                !first_reads.contains(&index),
                "member {index} was read again after a later member"
            );
            first_reads.push(index);
        }
    }
    assert!(
        first_reads.windows(2).all(|pair| pair[0] < pair[1]),
        "readers were pulled out of add order"
    );
}

#[test]
fn a_volume_set_writes_the_member_at_a_time_archive() {
    let entries = set(250, 4);
    for shape in [Shape::Bytes, Shape::Readers] {
        narrow_equals_wide(
            &entries,
            shape,
            options(WriteFormat::Rar5, 3, 4),
            Some(300 << 10),
        );
    }
    narrow_equals_wide(
        &entries,
        Shape::Bytes,
        options(WriteFormat::Rar4(Rar4Version::V29), 3, 4),
        Some(300 << 10),
    );
}

#[test]
fn encryption_and_blake2sp_write_the_member_at_a_time_archive() {
    let entries = set(150, 5);
    let wide = WriteOptions {
        password: Some(Password::new("team")),
        checksum: ChecksumKind::Blake2sp,
        ..options(WriteFormat::Rar5, 3, 4)
    };
    let narrow = WriteOptions {
        workers: Some(1),
        ..clone_options(&wide)
    };
    let (one, _) = write(&entries, Shape::Bytes, narrow, None);
    let (many, _) = write(&entries, Shape::Bytes, wide, None);
    let (one, many) = (one.expect("narrow"), many.expect("wide"));
    assert!(one == many, "the team moved a byte of an encrypted archive");
    assert_reads_back(&many, &entries, Some(Password::new("team")));
}

#[test]
fn a_short_reader_ends_the_write_and_nothing_after_it_is_pulled() {
    let entries = set(120, 6);
    // A member well inside a batch, of a size the team takes.
    let short = (40..entries.len())
        .find(|&i| !entries[i].directory && entries[i].bytes.len() > 100 && i % 29 != 23)
        .expect("a small member");
    for workers in [1, 4] {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut readers: Vec<Logged<'_>> = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| Logged {
                index,
                bytes: &entry.bytes,
                at: 0,
                end: if index == short {
                    entry.bytes.len() / 2
                } else {
                    entry.bytes.len()
                },
                log: Arc::clone(&log),
            })
            .collect();
        let mut writer = Writer::new(options(WriteFormat::Rar5, 3, workers)).expect("options");
        for (entry, reader) in entries.iter().zip(readers.iter_mut()) {
            let payload = if !entry.directory && !entry.bytes.is_empty() {
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
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: entry.directory,
                })
                .expect("add");
        }
        let error = writer
            .finish_into(Vec::new())
            .expect_err("a short reader is an error");
        assert!(
            matches!(error.kind(), ErrorKind::Truncated),
            "workers {workers}: {error}"
        );
        drop(readers);
        let log = log.lock().unwrap();
        assert!(
            log.iter().all(|&index| index <= short),
            "workers {workers}: a member after the short one was pulled"
        );
    }
}

/// Writes `entries` (small readers or bytes, and one member of 1.1 MiB,
/// which keeps the fitted dictionary at the default 2 MiB) and returns
/// the archive, its report and how many members the team encoded.
fn write_lifted(
    entries: &[Entry],
    large: &[u8],
    shape: Shape,
    options: WriteOptions,
) -> (Vec<u8>, rarkit::WriteReport, usize) {
    let mut readers: Vec<&[u8]> = entries.iter().map(|entry| &entry.bytes[..]).collect();
    rarkit::internals::writers::reset_team_prepared();
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"large.bin",
            payload: Payload::Bytes(large),
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    for (entry, reader) in entries.iter().zip(readers.iter_mut()) {
        let payload = match shape {
            Shape::Readers => Payload::Reader {
                reader,
                size: entry.bytes.len() as u64,
                crc32: None,
            },
            Shape::Bytes => Payload::Bytes(&entry.bytes),
        };
        writer
            .add(MemberSpec {
                name: &entry.name,
                payload,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    let report = writer.finish_into(&mut out).expect("write");
    (out, report, rarkit::internals::writers::team_prepared())
}

#[test]
fn a_reader_crew_at_level_5_is_charged_the_chains_it_builds_under_a_callers_ceiling() {
    // `Run::crew_bytes`: a READER member's crew is charged the finder its
    // windowed encode builds. That used to be the tree, sized
    // from the fitted dictionary (2 MiB here: 20 MiB of tree and 4 MiB of
    // hints at level 5), and a caller's 128 MiB ceiling, which leaves the
    // team about 47 MiB beside the large member (`Run::beside_team_bytes`,
    // with the parses in flight and the kept buffers the -m4 and -m5
    // memory work counts), afforded ONE crew of readers against two of
    // bytes. Now
    // (SPEC-H3 8.1) a non-solid member of at most one parse block at
    // levels 4 and 5 is walked by the CHAINS, sized from the member, so a
    // reader crew is charged what a bytes crew is and the same share
    // affords two of either. Four workers, so
    // the parses beside the team do not follow the test box's pool. Every
    // archive is the member-at-a-time walk's.
    let mut state = 11u64;
    let entries: Vec<Entry> = (0..120)
        .map(|i| {
            let len = (xorshift(&mut state) % 12_000) as usize + 1;
            Entry {
                name: format!("small{i:03}.txt").into_bytes(),
                bytes: rarkit_testdata::chatter((i) as u64, len),
                directory: false,
            }
        })
        .collect();
    let large = rarkit_testdata::chatter(99, 1_100 << 10);
    let ceiling = rarkit::MemoryPolicy {
        working_limit: 128 << 20,
        // A ceiling this row names (SPEC-API 8's `limit_named`).
        limit_named: true,
        ..rarkit::MemoryPolicy::default()
    };
    let with = |workers: usize, memory: rarkit::MemoryPolicy| WriteOptions {
        memory,
        ..options(WriteFormat::Rar5, 5, workers)
    };
    let (alone, _, took) = write_lifted(
        &entries,
        &large,
        Shape::Readers,
        with(1, rarkit::MemoryPolicy::default()),
    );
    assert_eq!(took, 0);

    let (readers, _, took) = write_lifted(&entries, &large, Shape::Readers, with(4, ceiling));
    assert!(readers == alone);
    if pool_is_wide() {
        assert!(
            took > 0,
            "two reader crews on the chains fit a 47 MiB share"
        );
    }

    let (bytes, _, took) = write_lifted(&entries, &large, Shape::Bytes, with(4, ceiling));
    assert!(bytes == alone);
    if pool_is_wide() {
        assert!(took > 0, "two crews of bytes members fit the same share");
    }

    let (wide, _, took) = write_lifted(
        &entries,
        &large,
        Shape::Readers,
        with(8, rarkit::MemoryPolicy::default()),
    );
    assert!(wide == alone);
    if pool_is_wide() {
        assert!(took > 0, "the default policy keeps its team");
    }
}

#[test]
fn a_callers_budget_holds_the_lead_encoder_and_moves_no_byte() {
    // `Run::chosen_hold`: under a caller's ceiling the lead's chains and
    // hints are held to fewer blocks in flight where the budget needs it
    // (`Engine::hold_wave`), and the team takes what that frees. Neither
    // the hold nor the width reaches a byte: every archive is the default
    // policy's, at every level, shape and budget. The large member, 5 MiB
    // of bytes, is more than two windows, so under the tightest budget it
    // is written a window at a time (spec G 3.5).
    let mut state = 23u64;
    let entries: Vec<Entry> = (0..60)
        .map(|i| {
            let len = (xorshift(&mut state) % 9_000) as usize + 1;
            Entry {
                name: format!("small{i:03}.txt").into_bytes(),
                bytes: rarkit_testdata::chatter((i) as u64, len),
                directory: false,
            }
        })
        .collect();
    let large = rarkit_testdata::chatter(7, 5 << 20);
    for level in [1u8, 3, 5] {
        let with = |limit: Option<u64>| WriteOptions {
            memory: limit.map_or_else(rarkit::MemoryPolicy::default, |limit| {
                rarkit::MemoryPolicy {
                    working_limit: limit,
                    // A ceiling this row names (SPEC-API 8's
                    // `limit_named`).
                    limit_named: true,
                    ..rarkit::MemoryPolicy::default()
                }
            }),
            // Level 3's own default dictionary is not taken under a
            // NAMED ceiling (9 Oct 2026), so the unnamed arm keeps 2 MiB
            // too: this row is about the hold and the width, which reach
            // no byte at one dictionary.
            level3_dictionary_2mib: true,
            ..options(WriteFormat::Rar5, level, 8)
        };
        for shape in [Shape::Readers, Shape::Bytes] {
            let (free, _, _) = write_lifted(&entries, &large, shape, with(None));
            for limit in [96u64 << 20, 128 << 20, 256 << 20] {
                let (held, _, _) = write_lifted(&entries, &large, shape, with(Some(limit)));
                assert!(held == free, "level {level}, {limit} B");
            }
        }
    }
}

#[test]
fn the_team_is_the_pools_width_and_only_a_ceiling_under_512_mib_keeps_max_workers() {
    // `Run::team_width`: with no memory ceiling named, the team is the
    // pool's width held to `WriteOptions::workers` and to what the default
    // `working_limit` affords at a crew's real charge, and
    // `MemoryPolicy::max_workers` (eight at the default) is not in it. A
    // ceiling the caller names at 512 MiB or more admits what the default
    // admits (spec G 3.7.3's named-ceiling rule of 1 Oct 2026); one
    // under 512 MiB keeps `max_workers`, as every named ceiling did
    // before. Twelve threads, so both figures can be told apart; every
    // archive is the member-at-a-time walk's.
    let mut state = 29u64;
    let entries: Vec<Entry> = (0..300)
        .map(|i| {
            let len = (xorshift(&mut state) % 20_000) as usize + 1;
            Entry {
                name: format!("small{i:03}.txt").into_bytes(),
                bytes: rarkit_testdata::chatter((i) as u64, len),
                directory: false,
            }
        })
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(12)
        .build()
        .expect("a pool of twelve");
    for level in [1u8, 3, 5] {
        let alone = write(
            &entries,
            Shape::Bytes,
            options(WriteFormat::Rar5, level, 1),
            None,
        )
        .0
        .expect("write");
        let (wide, crews) = pool.install(|| {
            let out = write(
                &entries,
                Shape::Bytes,
                options(WriteFormat::Rar5, level, 12),
                None,
            );
            (
                out.0.expect("write"),
                rarkit::internals::writers::team_crews(),
            )
        });
        assert!(wide == alone, "level {level}: the width moved a byte");
        assert_eq!(
            crews, 12,
            "level {level}: the default team is the pool's width"
        );
        assert!(crews > rarkit::MemoryPolicy::default().max_workers);

        let named = |memory: rarkit::MemoryPolicy| {
            pool.install(|| {
                let with = WriteOptions {
                    memory,
                    ..options(WriteFormat::Rar5, level, 12)
                };
                let out = write(&entries, Shape::Bytes, with, None);
                (
                    out.0.expect("write"),
                    rarkit::internals::writers::team_crews(),
                )
            })
        };
        let budget = rarkit::MemoryPolicy::from_limit(rarkit::MemoryPolicy::DEFAULT_LIMIT);
        let (held, crews) = named(budget);
        assert!(held == alone, "level {level}: a ceiling moved a byte");
        assert_eq!(
            crews, 12,
            "level {level}: a ceiling of 512 MiB fields the default's team"
        );
        let small = rarkit::MemoryPolicy::from_limit(rarkit::MemoryPolicy::DEFAULT_LIMIT - 1);
        let (held, crews) = named(small);
        assert!(held == alone, "level {level}: a small ceiling moved a byte");
        assert!(
            (2..=small.max_workers).contains(&crews),
            "level {level}: a ceiling under 512 MiB keeps max_workers ({crews} crews)"
        );
    }
}

#[test]
fn the_default_team_takes_members_of_several_blocks_and_moves_no_byte() {
    // `Run::choose_team_most`: with no memory ceiling named, the team takes
    // members of several parse blocks too (up to sixteen), each encoded
    // with the call the member-at-a-time walk makes for it, so the archive
    // is that walk's. Small members with a few of 300 KB to 1 MB
    // among them, bytes and readers, every level the chains and the tree
    // cover.
    let mut state = 31u64;
    let entries: Vec<Entry> = (0..90)
        .map(|i| {
            let len = if i % 15 == 7 {
                // Under 1 MiB, still up to four parse blocks: from 1 MiB
                // spec G 3.8.3's store rule samples a member, and one of
                // these incompressible members it STORES is the writing
                // thread's, not the team's (the non-solid work's own
                // resolution at its merge).
                300_000 + (xorshift(&mut state) % 700_000) as usize
            } else {
                (xorshift(&mut state) % 20_000) as usize + 1
            };
            Entry {
                name: format!("m{i:03}.bin").into_bytes(),
                bytes: rarkit_testdata::chatter((i) as u64, len),
                directory: false,
            }
        })
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .expect("a pool of eight");
    for shape in [Shape::Bytes, Shape::Readers] {
        for level in [1u8, 3, 5] {
            let alone = write(&entries, shape, options(WriteFormat::Rar5, level, 1), None)
                .0
                .expect("write");
            let (wide, took) = pool.install(|| {
                rarkit::internals::writers::reset_team_prepared();
                let out = write(&entries, shape, options(WriteFormat::Rar5, level, 8), None);
                (
                    out.0.expect("write"),
                    rarkit::internals::writers::team_prepared(),
                )
            });
            assert!(wide == alone, "level {level}: the team moved a byte");
            assert_eq!(
                took,
                entries.len(),
                "level {level}: every member, the multi-block ones too, is the team's"
            );
            assert_reads_back(&wide, &entries, None);
        }
    }
}

#[test]
fn the_large_member_lane_takes_members_above_the_team_bound_and_moves_no_byte() {
    // `Run::choose_large_lane`: with no ceiling named, members above the
    // small crews' bound and up to one window are taken by large crews of
    // their own, charged apart. Many members of about 1.5 MiB among small
    // ones, at a 2 MiB window, so the small crews' bound steps down below
    // them at level 5 and the lane is what takes them. Bytes and readers,
    // levels 1, 3 and 5; every archive is the member-at-a-time walk's.
    let mut state = 41u64;
    let entries: Vec<Entry> = (0..120)
        .map(|i| {
            let len = if i % 6 == 3 {
                1_300_000 + (xorshift(&mut state) % 400_000) as usize
            } else {
                (xorshift(&mut state) % 20_000) as usize + 1
            };
            Entry {
                name: format!("m{i:03}.bin").into_bytes(),
                bytes: rarkit_testdata::chatter((i) as u64, len),
                directory: false,
            }
        })
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .expect("a pool of eight");
    let mut lanes = 0;
    for shape in [Shape::Bytes, Shape::Readers] {
        for level in [1u8, 3, 5] {
            let alone = write(&entries, shape, options(WriteFormat::Rar5, level, 1), None)
                .0
                .expect("write");
            let (wide, took, large) = pool.install(|| {
                rarkit::internals::writers::reset_team_prepared();
                let out = write(&entries, shape, options(WriteFormat::Rar5, level, 8), None);
                (
                    out.0.expect("write"),
                    rarkit::internals::writers::team_prepared(),
                    rarkit::internals::writers::team_large(),
                )
            });
            assert!(wide == alone, "level {level}: the lane moved a byte");
            if large.0 > 0 {
                lanes += 1;
                assert_eq!(
                    took,
                    entries.len(),
                    "level {level}: the lane took the large members"
                );
                assert!(large.0 < 8, "level {level}: small crews remain");
            }
            assert_reads_back(&wide, &entries, None);
        }
    }
    assert!(lanes > 0, "no row ran the large-member lane");
}

#[test]
fn a_team_batch_passes_over_directories_and_empty_files_in_the_command_lines_order() {
    // `Run::plan_batch`: a member that carries no bytes (a directory, an
    // empty file) is passed over rather than ending the batch, and written
    // by the writing thread in `add` order. `rarfast a -r` adds a directory
    // member after each directory's files, so a batch that stopped at each
    // one was one directory's files (found and
    // fixed here). 40 directories of 8 small files and one empty file each, in
    // that order; the archive is the member-at-a-time walk's, the team
    // takes every file with bytes, and in far fewer batches than there
    // are directories.
    let mut state = 51u64;
    let mut entries = Vec::new();
    for dir in 0..40 {
        for file in 0..8 {
            let len = (xorshift(&mut state) % 9_000) as usize + 1;
            entries.push(Entry {
                name: format!("d{dir:02}/f{file}.txt").into_bytes(),
                bytes: rarkit_testdata::chatter((dir * 8 + file) as u64, len),
                directory: false,
            });
        }
        entries.push(Entry {
            name: format!("d{dir:02}/empty").into_bytes(),
            bytes: Vec::new(),
            directory: false,
        });
        entries.push(Entry {
            name: format!("d{dir:02}").into_bytes(),
            bytes: Vec::new(),
            directory: true,
        });
    }
    let with_bytes = entries.iter().filter(|e| !e.bytes.is_empty()).count();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .expect("a pool of eight");
    for shape in [Shape::Bytes, Shape::Readers] {
        let alone = write(&entries, shape, options(WriteFormat::Rar5, 3, 1), None)
            .0
            .expect("write");
        let (wide, took, batches) = pool.install(|| {
            rarkit::internals::writers::reset_team_prepared();
            let out = write(&entries, shape, options(WriteFormat::Rar5, 3, 8), None);
            (
                out.0.expect("write"),
                rarkit::internals::writers::team_prepared(),
                rarkit::internals::writers::team_batches(),
            )
        });
        assert!(wide == alone, "passing over directories moved a byte");
        assert_eq!(took, with_bytes, "the team took every member with bytes");
        assert!(
            batches < 10,
            "{batches} batches for 40 directories: a batch ended at a directory"
        );
        assert_reads_back(&wide, &entries, None);
    }
}

#[test]
fn members_of_one_to_four_mib_reuse_the_teams_packed_buffers_and_stay_inside_the_ceiling() {
    // `Run::lend_packed`: a member the team encodes is lent a packed buffer
    // from one pool, reserved to its bound, and gives it back once written,
    // so no buffer is allocated, regrown and freed per member. On text4g
    // (2,571 members, mostly 256 KiB to 4 MiB) that churn held 115 MiB of
    // whole-process RSS above the live heap at -m3, over the 512
    // MiB ceiling. Here:
    // 48 members of 1 to 2 MiB with small ones between, the default
    // policy, a pool of eight; the archive is the member-at-a-time walk's,
    // and the pool allocates far fewer buffers than it lends. The
    // whole-process peak itself is the small-member RSS guard script's.
    let mut state = 61u64;
    let mut entries = Vec::new();
    for i in 0..48u64 {
        let len = (1 << 20) + (xorshift(&mut state) % (1 << 20)) as usize;
        entries.push(Entry {
            name: format!("big{i:02}.txt").into_bytes(),
            bytes: rarkit_testdata::chatter(i * 3, len),
            directory: false,
        });
        let len = (xorshift(&mut state) % 30_000) as usize + 1;
        entries.push(Entry {
            name: format!("small{i:02}.txt").into_bytes(),
            bytes: rarkit_testdata::chatter(i * 3 + 1, len),
            directory: false,
        });
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .expect("a pool of eight");
    let alone = write(
        &entries,
        Shape::Bytes,
        options(WriteFormat::Rar5, 1, 1),
        None,
    )
    .0
    .expect("write");
    let (wide, took, fresh) = pool.install(|| {
        rarkit::internals::writers::reset_team_prepared();
        let out = write(
            &entries,
            Shape::Bytes,
            options(WriteFormat::Rar5, 1, 8),
            None,
        );
        (
            out.0.expect("write"),
            rarkit::internals::writers::team_prepared(),
            rarkit::internals::writers::packed_fresh(),
        )
    });
    assert!(wide == alone, "the pool moved a byte");
    assert!(took > entries.len() / 2, "the team encoded {took} members");
    assert!(
        fresh * 3 < took,
        "{fresh} fresh packed buffers for {took} members: one allocated per member"
    );
    assert_reads_back(&wide, &entries, None);
}
