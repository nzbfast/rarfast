//! An archive written past the OS cache, or through it with held
//! corrections, is the same archive.

use super::*;

fn noise(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::scramble(seed, len)
}

fn stored(volume_size: Option<u64>) -> Options {
    Options {
        level: super::super::args::Level::Store,
        volume_size,
        ..Options::default()
    }
}

fn writer<'r>(opts: &Options, reader: &'r mut (dyn std::io::Read + Send), size: u64) -> Writer<'r> {
    let mut writer = Writer::new(write_options(opts, &[], None)).expect("options");
    writer
        .add(MemberSpec {
            name: b"full.mkv",
            payload: Payload::Reader {
                reader,
                size,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    writer
}

/// A scratch directory whose files take a past-the-cache open, or
/// `None` where none here does (a tmpfs).
fn direct_dir(tag: &str) -> Option<PathBuf> {
    for base in [std::env::temp_dir(), std::env::current_dir().ok()?] {
        let dir = base.join(format!("rarfast-direct-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok()?;
        let probe = dir.join("probe");
        let direct = crate::unbuffered::Output::create(&probe, 1 << 40)
            .map(|out| out.is_direct())
            .unwrap_or(false);
        let _ = std::fs::remove_file(&probe);
        if direct {
            return Some(dir);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    None
}

/// An archive with a recovery record keeps its output in the cache,
/// whatever its size; one without is sized by its input.
#[test]
fn a_recovery_record_keeps_the_output_cached() {
    let files = vec![Chosen {
        shown: "full.mkv".into(),
        disk: PathBuf::from("full.mkv"),
        stored: "full.mkv".into(),
        is_dir: false,
        size: 12 << 30,
        mtime: None,
        attributes: 0,
    }];
    let mut opts = stored(None);
    assert_eq!(output_expected(&files, &opts), 12 << 30);
    opts.recovery_percent = Some(5);
    assert_eq!(output_expected(&files, &opts), 0);
}

/// **`a -m0` of a big member writes, past the OS cache, exactly the
/// archive it writes through it**: a single archive (its headers
/// corrected where they lie on disk, `finish_seek_read`) and a volume
/// set of 65 MiB volumes (`Volumes`, each volume past the cache and
/// closed by `finished`), each the same bytes as the same write into
/// memory.
#[test]
fn a_big_stored_archive_written_past_the_cache_is_the_same_archive() {
    let _serial = crate::unbuffered::TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !crate::unbuffered::ABLE {
        eprintln!("no past-the-cache open on this target: skipped");
        return;
    }
    let Some(dir) = direct_dir("a") else {
        eprintln!("no directory here takes a direct open: skipped");
        return;
    };

    // A single archive.
    let body = noise(70 << 20, 1);
    let opts = stored(None);
    let path = dir.join("single.rar");
    let mut out = crate::unbuffered::Output::create(&path, body.len() as u64).expect("create");
    assert!(out.is_direct(), "a 70 MiB archive was not written direct");
    let mut reader = std::io::Cursor::new(&body[..]);
    writer(&opts, &mut reader, body.len() as u64)
        .finish_seek_read_with(&mut out, &mut ())
        .expect("finish");
    out.close().expect("close");
    let mut memory = std::io::Cursor::new(Vec::new());
    let mut reader = std::io::Cursor::new(&body[..]);
    writer(&opts, &mut reader, body.len() as u64)
        .finish_seek_read_with(&mut memory, &mut ())
        .expect("finish");
    assert!(
        std::fs::read(&path).expect("read") == memory.into_inner(),
        "the direct single archive differs from the one written in memory"
    );

    // A volume set, every volume past the cache.
    let body = noise(140 << 20, 2);
    let cap = 65 << 20;
    let opts = stored(Some(cap));
    let mut created = Vec::new();
    let mut volumes = Volumes {
        stem: dir.join("set").to_string_lossy().into_owned(),
        naming: VolumeNaming::Numbered,
        estimate: 3,
        expected: cap,
        created: &mut created,
    };
    let mut reader = std::io::Cursor::new(&body[..]);
    writer(&opts, &mut reader, body.len() as u64)
        .finish_volumes_with(&mut volumes, &mut ())
        .expect("finish_volumes");
    let files: Vec<Vec<u8>> = created
        .iter()
        .map(|path| std::fs::read(path).expect("read a volume"))
        .collect();
    let mut memory: Vec<Vec<u8>> = Vec::new();
    let mut reader = std::io::Cursor::new(&body[..]);
    writer(&opts, &mut reader, body.len() as u64)
        .finish_volumes(&mut memory)
        .expect("finish_volumes");
    assert_eq!(files.len(), 3, "140 MiB over 65 MiB volumes");
    assert!(
        files == memory,
        "a direct volume set differs from the one written in memory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Members of an archive, each a reader payload of the bytes given.
fn writer_of<'r>(
    opts: &Options,
    bodies: &'r mut [(String, std::io::Cursor<Vec<u8>>)],
) -> Writer<'r> {
    let mut writer = Writer::new(write_options(opts, &[], None)).expect("options");
    for (name, body) in bodies.iter_mut() {
        let size = body.get_ref().len() as u64;
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Reader {
                    reader: body,
                    size,
                    crc32: None,
                },
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    writer
}

/// A many-member set's shape in small: members of 2 to 3 MiB (over the small
/// member read-ahead, so each is a reader payload whose header is
/// corrected once its bytes have passed), incompressible unless `text`,
/// then half of them text.
fn many_members(members: usize, text: bool) -> Vec<(String, std::io::Cursor<Vec<u8>>)> {
    (0..members)
        .map(|n| {
            let len = (2 << 20) + n * 100_003;
            let body = if text && n % 2 == 1 {
                b"a line of text that a compressor shortens, again and again\n"
                    .iter()
                    .copied()
                    .cycle()
                    .take(len)
                    .collect()
            } else {
                noise(len, 7 + n as u64)
            };
            (
                format!("subset/element-{n:02}.mkv"),
                std::io::Cursor::new(body),
            )
        })
        .collect()
}

/// **A cached output that holds its corrections until its close writes,
/// byte for byte, the archive the same write makes in memory**
/// (`unbuffered::Held`), for every shape whose members are corrected
/// where they lie: several stored members (the corrections are HELD,
/// one a member at the least, which is what this pins of the engine),
/// one member, stored beside compressed members, a solid set, BLAKE2sp
/// checksums, and an archive with a recovery record, whose read-back
/// must see every correction.
#[test]
fn a_cached_archive_with_held_corrections_is_the_same_archive() {
    crate::unbuffered::TEST_HOLDS.with(|h| h.set(Some(crate::unbuffered::Holds::Always)));
    let dir = std::env::temp_dir().join(format!("rarfast-held-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    let default_level = || Options::default();
    let cases: Vec<(&str, Options, usize, bool, bool)> = vec![
        ("several stored members", stored(None), 6, false, true),
        ("one stored member", stored(None), 1, false, false),
        ("stored beside compressed", default_level(), 6, true, false),
        (
            "a solid set",
            Options {
                solid: true,
                ..default_level()
            },
            5,
            true,
            false,
        ),
        (
            "BLAKE2sp",
            Options {
                hash: super::super::args::HashType::Blake2sp,
                ..stored(None)
            },
            4,
            false,
            true,
        ),
        (
            "a recovery record",
            Options {
                recovery_percent: Some(5),
                ..stored(None)
            },
            4,
            false,
            false,
        ),
    ];
    for (what, opts, members, text, held_each) in cases {
        let path = dir.join("held.rar");
        let mut out = crate::unbuffered::Output::create(&path, 1 << 20).expect("create");
        assert!(!out.is_direct(), "{what}: a small expectation went direct");
        let mut bodies = many_members(members, text);
        writer_of(&opts, &mut bodies)
            .finish_seek_read_with(&mut out, &mut ())
            .expect("finish");
        if held_each {
            assert!(
                out.held_count() >= members,
                "{what}: {} corrections held for {members} members",
                out.held_count()
            );
        }
        out.close().expect("close");
        assert_eq!(
            out.held_count(),
            0,
            "{what}: corrections left after the close"
        );
        drop(out);
        let mut memory = std::io::Cursor::new(Vec::new());
        let mut bodies = many_members(members, text);
        writer_of(&opts, &mut bodies)
            .finish_seek_read_with(&mut memory, &mut ())
            .expect("finish");
        assert!(
            std::fs::read(&path).expect("read") == memory.into_inner(),
            "{what}: the cached archive differs from the one written in memory"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// **More stored members than the held list's bound**: the list is
/// written early, in order, when it fills, and starts again, and the
/// archive is byte for byte the one written in memory.
#[test]
fn more_corrections_than_the_bound_are_the_same_archive() {
    crate::unbuffered::TEST_HOLDS.with(|h| h.set(Some(crate::unbuffered::Holds::Always)));
    let dir = std::env::temp_dir().join(format!("rarfast-held-over-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    let members = crate::unbuffered::HELD_SPANS_MOST + 100;
    let many = || -> Vec<(String, std::io::Cursor<Vec<u8>>)> {
        (0..members)
            .map(|n| {
                (
                    format!("many/member-{n:04}.bin"),
                    std::io::Cursor::new(noise(40_000 + n, 1_000 + n as u64)),
                )
            })
            .collect()
    };
    let opts = Options {
        hash: super::super::args::HashType::Blake2sp,
        ..stored(None)
    };
    let path = dir.join("over.rar");
    let mut out = crate::unbuffered::Output::create(&path, 1 << 20).expect("create");
    let mut bodies = many();
    writer_of(&opts, &mut bodies)
        .finish_seek_read_with(&mut out, &mut ())
        .expect("finish");
    let held = out.held_count();
    assert!(
        held > 0 && held < crate::unbuffered::HELD_SPANS_MOST,
        "{held} corrections held at the end of {members} members: the list was not written early"
    );
    out.close().expect("close");
    drop(out);
    let mut memory = std::io::Cursor::new(Vec::new());
    let mut bodies = many();
    writer_of(&opts, &mut bodies)
        .finish_seek_read_with(&mut memory, &mut ())
        .expect("finish");
    assert!(
        std::fs::read(&path).expect("read") == memory.into_inner(),
        "the archive differs from the one written in memory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A volume set through cached volumes is the set written in
/// memory**: each volume's corrections are held by that volume's own
/// output and made when `finished` closes it, so none is left for a
/// volume already closed.
#[test]
fn a_cached_volume_set_with_held_corrections_is_the_same_set() {
    crate::unbuffered::TEST_HOLDS.with(|h| h.set(Some(crate::unbuffered::Holds::Always)));
    let dir = std::env::temp_dir().join(format!("rarfast-held-set-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    for (what, opts) in [
        ("stored", stored(Some(3 << 20))),
        (
            "stored with a recovery record",
            Options {
                recovery_percent: Some(5),
                ..stored(Some(3 << 20))
            },
        ),
    ] {
        let mut created = Vec::new();
        let mut volumes = Volumes {
            stem: dir.join("set").to_string_lossy().into_owned(),
            naming: VolumeNaming::Numbered,
            estimate: 6,
            expected: 3 << 20,
            created: &mut created,
        };
        let mut bodies = many_members(6, false);
        writer_of(&opts, &mut bodies)
            .finish_volumes_with(&mut volumes, &mut ())
            .expect("finish_volumes");
        let files: Vec<Vec<u8>> = created
            .iter()
            .map(|path| std::fs::read(path).expect("read a volume"))
            .collect();
        let mut memory: Vec<Vec<u8>> = Vec::new();
        let mut bodies = many_members(6, false);
        writer_of(&opts, &mut bodies)
            .finish_volumes(&mut memory)
            .expect("finish_volumes");
        assert!(files.len() >= 5, "{what}: {} volumes", files.len());
        assert!(
            files == memory,
            "{what}: the cached volume set differs from the one written in memory"
        );
        for path in &created {
            let _ = std::fs::remove_file(path);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The shipped dial of lever (a)**: a create's input is advised as
/// read in order on Linux, and on no other system.
#[test]
fn a_creates_input_is_advised_by_default_on_linux_only() {
    let shipped = cfg!(target_os = "linux");
    assert_eq!(ADVISES_INPUT, shipped);
    assert_eq!(
        advises_input(),
        shipped,
        "the default is not the shipped dial"
    );
}

/// **Which members are sampled, and what a sample means**: a member of
/// [`SAMPLED_FROM`] and more is; a sample is warm only when it says
/// resident, and cold where the kernel will not say, which keeps the
/// form every create took before.
#[test]
fn only_a_resident_sample_is_warm() {
    use crate::residency::Residency;
    assert!(warm(Residency::Resident));
    assert!(!warm(Residency::Cold));
    assert!(!warm(Residency::Unknown));
    assert_eq!(SAMPLED_FROM, 16 << 20);
}

/// **The shipped dial of the small members' sample: on**, and what the
/// rule samples either way. Off, it is the rule as it stood: a member
/// of the floor and more, and nothing else. On, of the members of 8 MiB
/// and more that the writer reads, the first is sampled, and then each
/// one at which 16 MiB of them have passed since the last sample; a
/// member under 8 MiB, a member the read-ahead loads and a directory
/// neither count nor are sampled; a large member starts the count
/// again; and under 16 MiB of such members in all, nothing is sampled.
#[test]
fn small_members_are_sampled_by_the_bytes_since_the_last_sample() {
    let shipped = true;
    assert_eq!(SAMPLES_SMALL, shipped);
    assert_eq!(
        samples_small(),
        shipped,
        "the default is not the shipped dial"
    );
    assert_eq!(SMALL_FROM, 8 << 20);
    const MIB: u64 = 1 << 20;
    let of = |members: &[(u64, bool)], small| sampled_members(members.iter().copied(), small);
    // Off: the floor alone, whatever lies between.
    let mixed = [
        (8 * MIB, true),
        (8 * MIB, true),
        (16 * MIB, true),
        (4096, false),
        (0, false),
        (64 * MIB, true),
        (12 * MIB, true),
        (7 * MIB, true),
        (12 * MIB, true),
    ];
    assert_eq!(
        of(&mixed, false),
        [false, false, true, false, false, true, false, false, false]
    );
    // On: the first 8 MiB member is sampled and the second, 8 MiB after
    // it, is not; the large members are sampled as before and start the
    // count again, so the 12 MiB member after one keeps its verdict;
    // the 7 MiB member says nothing and counts for nothing; the second
    // 12 MiB member completes 24.
    assert_eq!(
        of(&mixed, true),
        [true, false, true, false, false, true, false, false, true]
    );
    // 512 members of 8 MiB: the first and every second after it, 256
    // samples for 4 GiB.
    let album = vec![(8 * MIB, true); 512];
    let on = of(&album, true);
    assert_eq!(on.iter().filter(|&&s| s).count(), 256);
    assert!(on.iter().enumerate().all(|(i, &s)| s == (i % 2 == 0)));
    assert!(of(&album, false).iter().all(|&s| !s));
    // 12 MiB members: the first, then every second (24 MiB a sample).
    let twelves = vec![(12 * MIB, true); 6];
    assert_eq!(of(&twelves, true), [true, false, true, false, true, false]);
    // A small member ahead of a big member is sampled, and so is the big member.
    assert_eq!(
        of(&[(12 * MIB, true), (4096 * MIB, true)], true),
        [true, true]
    );
    assert_eq!(
        of(&[(12 * MIB, true), (4096 * MIB, true)], false),
        [false, true]
    );
    // Members under 8 MiB, however many: never sampled, as before.
    for size in [MIB + 1, 2 * MIB, 4 * MIB, 8 * MIB - 1] {
        let small = vec![(size, true); 2048];
        assert!(of(&small, true).iter().all(|&s| !s), "{size}");
    }
    // Under 16 MiB of such members in all: nothing is sampled, whatever
    // smaller members stand beside them.
    assert_eq!(of(&[(15 * MIB, true)], true), [false]);
    assert_eq!(
        of(&[(8 * MIB, true), (7 * MIB, true), (MIB, false)], true),
        [false; 3]
    );
    // Members the read-ahead loads say nothing and count for nothing.
    let loaded = vec![(MIB, false); 64];
    assert!(of(&loaded, true).iter().all(|&s| !s));
    // One member of the floor exactly, alone: sampled either way.
    assert_eq!(of(&[(16 * MIB, true)], false), [true]);
    assert_eq!(of(&[(16 * MIB, true)], true), [true]);
}

/// Every member's name and checksum verdict, as the engine's own reader
/// gives them for the archive at `path` (a `t`), or its error.
fn verdicts(path: &Path, password: Option<&str>) -> rarkit::Result<Vec<(String, Option<bool>)>> {
    struct Seen(Vec<(String, Option<bool>)>);
    impl rarkit::Sink for Seen {
        type Out = std::io::Sink;
        fn open(
            &mut self,
            _member: &rarkit::MemberInfo<'_>,
        ) -> rarkit::Result<rarkit::Disposition<std::io::Sink>> {
            Ok(rarkit::Disposition::Verify)
        }
        fn close(
            &mut self,
            member: &rarkit::MemberInfo<'_>,
            _out: Option<std::io::Sink>,
            outcome: &rarkit::MemberOutcome,
        ) -> rarkit::Result<()> {
            self.0
                .push((member.name_lossy().into_owned(), outcome.checksum_ok));
            Ok(())
        }
    }
    let file = std::fs::File::open(path).expect("open the archive");
    let sources: Vec<std::sync::Arc<dyn rarkit::RangeSource>> = vec![std::sync::Arc::new(file)];
    let options = rarkit::ReadOptions::default()
        .with_password(password.map(|text| Password::from(text.as_bytes())));
    let mut seen = Seen(Vec::new());
    rarkit::extract(sources, &options, &mut seen, &mut ())?;
    Ok(seen.0)
}

/// **What a reader makes of a cached archive whose output was never
/// closed** (a create killed after its last member, on macOS): every
/// member is there with its bytes, and every stored member's checksum
/// reads as a MISMATCH, because the header fields a stored reader
/// member is corrected with were still held. The same archive closed
/// reads clean, and so does the plain form left unclosed, which is what
/// every other system writes and what macOS wrote before. Stated here so
/// the behaviour is read and not discovered.
#[test]
fn a_cached_archive_left_unclosed_reads_as_this() {
    let dir = std::env::temp_dir().join(format!("rarfast-unclosed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    let opts = stored(None);
    for (held, closed) in [(true, false), (true, true), (false, false)] {
        crate::unbuffered::TEST_HOLDS.with(|h| {
            h.set(Some(if held {
                crate::unbuffered::Holds::Always
            } else {
                crate::unbuffered::Holds::Never
            }))
        });
        let path = dir.join("unclosed.rar");
        let mut out = crate::unbuffered::Output::create(&path, 1 << 20).expect("create");
        let mut bodies = many_members(4, false);
        writer_of(&opts, &mut bodies)
            .finish_seek_read_with(&mut out, &mut ())
            .expect("finish");
        if closed {
            out.close().expect("close");
        }
        drop(out);
        let seen = verdicts(&path, None).expect("the archive is read to its end");
        assert_eq!(seen.len(), 4, "held {held}, closed {closed}: {seen:?}");
        let want = Some(closed || !held);
        assert!(
            seen.iter().all(|(_, ok)| *ok == want),
            "held {held}, closed {closed}: {seen:?}"
        );
    }
    crate::unbuffered::TEST_HOLDS.with(|h| h.set(None));
    let _ = std::fs::remove_dir_all(&dir);
}

/// **An encrypted archive through a cached output with held
/// corrections reads back clean under its password** (`-p`, and `-hp`
/// with the headers enciphered too): salted, so it is judged by the
/// engine's own reader and not by its bytes; its length is the length
/// of the same write into memory.
#[test]
fn an_encrypted_cached_archive_with_held_corrections_reads_clean() {
    crate::unbuffered::TEST_HOLDS.with(|h| h.set(Some(crate::unbuffered::Holds::Always)));
    let dir = std::env::temp_dir().join(format!("rarfast-held-p-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    for headers in [false, true] {
        let mut opts = stored(None);
        opts.shared.password = Some("held".to_owned());
        opts.encrypt_headers = headers;
        let path = dir.join("held-p.rar");
        let mut out = crate::unbuffered::Output::create(&path, 1 << 20).expect("create");
        let mut bodies = many_members(4, false);
        writer_of(&opts, &mut bodies)
            .finish_seek_read_with(&mut out, &mut ())
            .expect("finish");
        assert!(
            out.held_count() >= 4,
            "headers {headers}: {} held",
            out.held_count()
        );
        out.close().expect("close");
        drop(out);
        let mut memory = std::io::Cursor::new(Vec::new());
        let mut bodies = many_members(4, false);
        writer_of(&opts, &mut bodies)
            .finish_seek_read_with(&mut memory, &mut ())
            .expect("finish");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").len(),
            memory.into_inner().len() as u64,
            "headers {headers}: length"
        );
        let seen = verdicts(&path, Some("held")).expect("reads under its password");
        assert_eq!(seen.len(), 4, "headers {headers}: {seen:?}");
        assert!(
            seen.iter().all(|(_, ok)| *ok == Some(true)),
            "headers {headers}: {seen:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A member streamed under a named `-mm`** (its packed size field
/// laid down reserved and corrected where it lies, spec G 3.5) goes
/// through a cached output with that correction held and is, byte for
/// byte, the archive written in memory.
#[test]
fn a_streamed_member_through_a_cached_output_is_the_same_archive() {
    crate::unbuffered::TEST_HOLDS.with(|h| h.set(Some(crate::unbuffered::Holds::Always)));
    let dir = std::env::temp_dir().join(format!("rarfast-held-mm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    // A named `-mm` is the whole process's: name the figure that leaves
    // the engine 64 MiB, which this row was written against.
    let mut opts = Options {
        dictionary: Some(1 << 20),
        ..Options::default()
    };
    opts.memory_cap = Some(mm_for_engine_limit(64 << 20, &opts));
    let text: Vec<u8> = (0..(24usize << 20))
        .map(|i| {
            b"the quick brown fox jumps over the lazy dog, line after line\n"[(i * 7 + i / 61) % 61]
        })
        .collect();
    let bodies = || vec![("big.txt".to_owned(), std::io::Cursor::new(text.clone()))];
    let path = dir.join("held-mm.rar");
    let mut out = crate::unbuffered::Output::create(&path, 1 << 20).expect("create");
    let mut readers = bodies();
    writer_of(&opts, &mut readers)
        .finish_seek_read_with(&mut out, &mut ())
        .expect("finish");
    assert!(
        out.held_count() >= 1,
        "a streamed member made no correction"
    );
    out.close().expect("close");
    drop(out);
    let mut memory = std::io::Cursor::new(Vec::new());
    let mut readers = bodies();
    writer_of(&opts, &mut readers)
        .finish_seek_read_with(&mut memory, &mut ())
        .expect("finish");
    assert!(
        std::fs::read(&path).expect("read") == memory.into_inner(),
        "the streamed archive differs from the one written in memory"
    );
    let seen = verdicts(&path, None).expect("reads");
    assert!(seen.iter().all(|(_, ok)| *ok == Some(true)), "{seen:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
