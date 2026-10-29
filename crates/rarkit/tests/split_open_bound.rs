//! A volume set of MANY volumes is extracted through the concurrent pool
//! without the process running out of file descriptors (1 Oct 2026).
//!
//! The pool takes a member split across volumes over its fragment list
//! (`extract::Split`): the walk crosses to each next volume and sends the
//! worker that fragment's open source. Before the bound of `read::forwarded`
//! the channel was unbounded, so the walk ran to the end of every member
//! in flight and every volume it had crossed stayed open behind it: on
//! macOS, whose default limit is 256 descriptors, `rarfast x` of eight
//! stored members in 581 volumes of 15 MB ended `Too many open files`
//! with three of them written (measured 1 Oct 2026), and a set
//! of more than about a thousand volumes did the same under Linux's 1,024.
//!
//! This test is that failure at small scale: 400 volumes read from real
//! files under a soft limit of 64 descriptors, with writers slow enough
//! that the walk would cross the whole set ahead of them. It fails on the
//! tree before the bound with the system's own error, and it is the only
//! test of its binary, because the limit is the process's.

#![cfg(all(unix, feature = "test-support"))]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberOutcome, MemberSpec, ParallelSink, Password,
    Payload, RangeSource, ReadOptions, Result, Volumes, WriteMethod, WriteOptions, Writer,
};

/// Eight members of 1 MiB and a few bytes, over the pool's offload floor.
const MEMBERS: usize = 8;
const MEMBER: usize = (1 << 20) + 11;
const PASSWORD: &str = "open-bound";
/// Each volume's size, so each member is about fifty fragments.
const PER: u64 = 21_000;
/// The soft limit the set is read under.
const LIMIT: u64 = 64;
/// How long each member's first write takes.
const SLOW: std::time::Duration = std::time::Duration::from_millis(400);

/// Incompressible, deterministic bytes.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn name(at: usize) -> String {
    format!("E{:02}.mkv", at + 1)
}

/// The set's volumes as files of a fresh directory, opened only when the
/// engine asks for them.
struct OnDisk {
    paths: Vec<std::path::PathBuf>,
}

impl Volumes for OnDisk {
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>> {
        let Some(path) = self.paths.get(index as usize) else {
            return Ok(None);
        };
        let file = std::fs::File::open(path)
            .map_err(|e| rarkit::Error::new(rarkit::ErrorKind::Source(e)))?;
        Ok(Some(Arc::new(file)))
    }
}

type Written = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

struct Keep {
    name: String,
    written: Written,
    /// Whether the first write has been made, or is not to be slow.
    begun: bool,
}

impl Write for Keep {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // A slow writer, as a disk is: each member's first write waits long
        // enough for the walk to cross every volume of the set, which is
        // what it did while a real extract wrote gigabytes.
        if !std::mem::replace(&mut self.begun, true) {
            std::thread::sleep(SLOW);
        }
        self.written
            .lock()
            .unwrap()
            .entry(self.name.clone())
            .or_default()
            .extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Sink {
    written: Written,
    closes: Mutex<Vec<(String, Option<bool>)>>,
    verify: bool,
    slow: bool,
}

impl ParallelSink for Sink {
    type Out = Keep;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Keep>> {
        if self.verify {
            return Ok(Disposition::Verify);
        }
        Ok(Disposition::Write(Keep {
            name: String::from_utf8_lossy(member.name).into_owned(),
            written: Arc::clone(&self.written),
            begun: !self.slow,
        }))
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        _out: Option<Keep>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closes.lock().unwrap().push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// Lower the soft descriptor limit to `limit` and answer the hard one.
#[allow(unsafe_code)]
fn lower_soft_limit(limit: u64) {
    let mut now = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `now` is a live, writable `rlimit`, which is all `getrlimit`
    // writes, and `setrlimit` reads it and nothing else of ours.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut now), 0);
        now.rlim_cur = limit as libc::rlim_t;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &now), 0);
    }
}

/// One set, and how it is read.
struct Shape {
    what: &'static str,
    members: usize,
    member: usize,
    compressed: bool,
    solid: bool,
    /// `None` clear, `Some(false)` the members encrypted, `Some(true)` the
    /// headers too.
    encrypted: Option<bool>,
    verify: bool,
    breadth: usize,
    /// Slow writers, so the walk would cross the whole set ahead of them.
    slow: bool,
}

/// Write `shape`'s set to files, read it under the lowered limit through
/// the pool, and hold every member to its true bytes and a good checksum.
/// Answers how many volumes it had.
fn read(shape: &Shape, at: usize) -> usize {
    let names: Vec<String> = (0..shape.members).map(name).collect();
    let truth: Vec<Vec<u8>> = (0..shape.members)
        .map(|m| {
            let seed = 90 + (at * 16 + m) as u64;
            if shape.compressed {
                rarkit_testdata::chatter(seed, shape.member + m)
            } else {
                noise(seed, shape.member + m)
            }
        })
        .collect();
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        method: if shape.compressed {
            WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            }
        } else {
            WriteMethod::Stored
        },
        solid: shape.solid,
        password: shape.encrypted.map(|_| Password::from(PASSWORD)),
        encrypt_headers: shape.encrypted == Some(true),
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in names.iter().zip(&truth) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut volumes).expect("finish");
    let count = volumes.len();
    assert!(
        count as u64 > LIMIT,
        "{}: a set of {count} volumes does not press a limit of {LIMIT}",
        shape.what
    );

    let dir = std::env::temp_dir().join(format!(
        "rarkit-split-open-bound-{}-{at}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let paths: Vec<std::path::PathBuf> = volumes
        .iter()
        .enumerate()
        .map(|(v, bytes)| {
            let path = dir.join(format!("set.part{:04}.rar", v + 1));
            std::fs::write(&path, bytes).expect("a volume written");
            path
        })
        .collect();
    drop(volumes);

    let written: Written = Arc::default();
    let sink = Sink {
        written: Arc::clone(&written),
        closes: Mutex::new(Vec::new()),
        verify: shape.verify,
        slow: shape.slow,
    };
    let options =
        ReadOptions::default().with_password(shape.encrypted.map(|_| Password::from(PASSWORD)));
    lower_soft_limit(LIMIT);
    let outcome = extract_parallel(OnDisk { paths }, &options, &sink, shape.breadth);
    // Before any assertion, so a failure's own message can open what it
    // needs.
    lower_soft_limit(1024);
    let _ = std::fs::remove_dir_all(&dir);

    let report = match outcome {
        Ok(report) => report,
        Err(e) => panic!(
            "{}: {count} volumes under a limit of {LIMIT} descriptors: {e:?}",
            shape.what
        ),
    };
    assert_eq!(report.members, shape.members as u64, "{}", shape.what);
    let closes = sink.closes.lock().unwrap();
    assert_eq!(closes.len(), shape.members, "{}", shape.what);
    for (m, (closed, ok)) in closes.iter().enumerate() {
        assert_eq!(
            closed,
            &name(m),
            "{}: members close in archive order",
            shape.what
        );
        assert_eq!(
            *ok,
            Some(true),
            "{}: {closed} closed with its checksum good",
            shape.what
        );
    }
    if !shape.verify {
        let written = written.lock().unwrap();
        for (m, data) in truth.iter().enumerate() {
            assert!(
                written.get(&name(m)) == Some(data),
                "{}: {} was written whole",
                shape.what,
                name(m)
            );
        }
    }
    count
}

#[test]
fn a_set_of_many_volumes_is_extracted_under_a_small_descriptor_limit() {
    lower_soft_limit(LIMIT);
    let (_, waits_before, bound) = rarkit::probe::open_ahead();
    lower_soft_limit(1024);
    assert_eq!(bound as u64, LIMIT / 2, "the bound is half the soft limit");

    // THE FAILURE: many stored members, each over many volumes, written by
    // slow writers at the pool's breadth. Before the bound this ended with
    // the system's `Too many open files`.
    let pressed = Shape {
        what: "eight stored members, written, breadth 8",
        members: MEMBERS,
        member: MEMBER,
        compressed: false,
        solid: false,
        encrypted: None,
        verify: false,
        breadth: 8,
        slow: true,
    };
    let volumes = read(&pressed, 0);
    assert!(volumes as u64 > 4 * LIMIT, "{volumes} volumes");
    // The bound was what held it: the walk waited at it, and never had
    // more fragments forwarded and unread than it allows. Without these a
    // machine whose workers kept up with the walk would pass for it.
    let (peak, waits, _) = rarkit::probe::open_ahead();
    assert!(waits > waits_before, "the walk never waited at the bound");
    assert!(
        peak as u64 <= LIMIT / 2,
        "{peak} fragments were forwarded and unread at once"
    );

    // THE SHAPES, each read whole and right under the same limit: one
    // member over many volumes; members only verified; a breadth of one;
    // compressed members (split jobs as well); a solid set (the walk's
    // own); encrypted members, their headers clear and encrypted (a stored
    // one is joined on the walk, a compressed one is a split job).
    let quick = |what, members, member, compressed, solid, encrypted, verify, breadth| Shape {
        what,
        members,
        member,
        compressed,
        solid,
        encrypted,
        verify,
        breadth,
        slow: false,
    };
    let shapes = [
        quick(
            "one stored member over many volumes",
            1,
            4 << 20,
            false,
            false,
            None,
            false,
            8,
        ),
        quick(
            "eight stored members, verified",
            MEMBERS,
            MEMBER,
            false,
            false,
            None,
            true,
            8,
        ),
        quick(
            "eight stored members, breadth 1",
            MEMBERS,
            MEMBER,
            false,
            false,
            None,
            false,
            1,
        ),
        quick(
            "compressed members, written",
            6,
            3 << 20,
            true,
            false,
            None,
            false,
            8,
        ),
        quick(
            "compressed members, verified",
            6,
            3 << 20,
            true,
            false,
            None,
            true,
            8,
        ),
        quick(
            "a solid compressed set",
            6,
            3 << 20,
            true,
            true,
            None,
            false,
            8,
        ),
        quick("a solid stored set", 4, MEMBER, false, true, None, false, 8),
        quick(
            "stored members under -p",
            4,
            MEMBER,
            false,
            false,
            Some(false),
            false,
            8,
        ),
        quick(
            "stored members under -hp",
            4,
            MEMBER,
            false,
            false,
            Some(true),
            false,
            8,
        ),
        quick(
            "compressed members under -p",
            6,
            3 << 20,
            true,
            false,
            Some(false),
            false,
            8,
        ),
        quick(
            "compressed members under -hp",
            6,
            3 << 20,
            true,
            false,
            Some(true),
            true,
            8,
        ),
    ];
    for (at, shape) in shapes.iter().enumerate() {
        read(shape, at + 1);
    }
    let (peak, _, _) = rarkit::probe::open_ahead();
    assert!(
        peak as u64 <= LIMIT / 2,
        "{peak} fragments were forwarded and unread at once"
    );

    // THE WALK'S OWN READ ABREAST (`read::across`, 2 Oct 2026): one stored
    // member the wide read takes, checked by the sequential entry, its
    // fragments far smaller than a piece, so one window of pieces spans
    // more volumes than the bound allows open. The walk crosses ahead of
    // its own joins there, and takes its places in the same count.
    let refused_before = rarkit::probe::open_ahead_refusals();
    let volumes = read_abreast(shapes.len() + 1);
    assert!(volumes as u64 > 8 * LIMIT, "{volumes} volumes");
    assert!(
        rarkit::probe::open_ahead_refusals() > refused_before,
        "the read abreast was never held at the bound"
    );
    let (peak, _, _) = rarkit::probe::open_ahead();
    assert!(
        peak as u64 <= LIMIT / 2,
        "{peak} volumes were open ahead of the join at once"
    );
}

/// A sink that only checks, for the sequential entry.
#[derive(Default)]
struct Checked {
    closes: Vec<Option<bool>>,
}

impl rarkit::Sink for Checked {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Verify)
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closes.push(outcome.checksum_ok);
        Ok(())
    }
}

/// One stored member of 17 MiB over volumes of [`PER`] bytes, checked by
/// `rarkit::extract` with its fragments read abreast, under the lowered
/// limit. Answers how many volumes it had.
fn read_abreast(at: usize) -> usize {
    let data = noise(700, (17 << 20) + 5);
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        method: WriteMethod::Stored,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"Full.mkv",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut volumes).expect("finish");
    let count = volumes.len();
    let dir = std::env::temp_dir().join(format!(
        "rarkit-split-open-bound-{}-{at}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let paths: Vec<std::path::PathBuf> = volumes
        .iter()
        .enumerate()
        .map(|(v, bytes)| {
            let path = dir.join(format!("set.part{:04}.rar", v + 1));
            std::fs::write(&path, bytes).expect("a volume written");
            path
        })
        .collect();
    drop(volumes);

    let mut sink = Checked::default();
    // Sixty-four pieces in flight, each a whole volume: twice the bound.
    let mut options = ReadOptions::default().with_workers(Some(64));
    options.memory.read_ahead = 64 << 20;
    rarkit::probe::set_fragments_abreast(Some(true));
    rarkit::probe::reset_fragments_abreast_runs();
    lower_soft_limit(LIMIT);
    let outcome = rarkit::extract(OnDisk { paths }, &options, &mut sink, &mut ());
    lower_soft_limit(1024);
    let runs = rarkit::probe::fragments_abreast_runs();
    rarkit::probe::set_fragments_abreast(None);
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = outcome {
        panic!("read abreast: {count} volumes under a limit of {LIMIT} descriptors: {e:?}");
    }
    assert!(runs >= 1, "nothing was read abreast");
    assert_eq!(sink.closes, vec![Some(true)]);
    count
}
