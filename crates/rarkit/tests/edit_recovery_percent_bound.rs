//! An edit believes the percentage a recovery header STATES no further
//! than the record that is present allows (bug sweep of 8 Oct 2026, item
//! 08).
//!
//! The `RR` service header's type 7 record is one vint, 1 to 1,000 (spec L
//! 3.5.1), and an edit that names no percentage rebuilds the record at the
//! stated one. Taken on its word, one patched byte turned a 1 percent
//! record into a 1,000 percent one: the rewrite of a 60 MB archive wrote
//! 676 MB and held 1.3 GB. The record that lies in the archive is the
//! evidence: a percentage whose record would be longer than that one is
//! not what the archive was written at, and the edit refuses by name, as
//! it does for a record that states none.
//!
//! THE BOUND, stated: an edit that names no percentage writes no more than
//! the source's own length and [`SLACK`] bytes of rebuilt headers, and
//! holds no more than [`HELD_TIMES`] times the source's length.
//!
//! Width and memory: a pool of [`POOL`] threads; the archive is
//! [`MEMBER`] bytes of member and its record, under 3 MiB in all, and the
//! counting allocator is this binary's own (which is why the test has a
//! file of its own).

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rarkit::{
    edit, Archive, HostOs, MemberSpec, Payload, RangeSource, ReadOptions, ServiceKind, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

const POOL: usize = 2;
const MEMBER: usize = 2 << 20;
/// What a rewrite may add to the source's length: the headers it rebuilds.
const SLACK: u64 = 64 << 10;
/// What a rewrite may hold, in source lengths: its copy of the output and
/// the encode's working rows beside it.
const HELD_TIMES: usize = 4;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            let grow = new_size - layout.size();
            let live = LIVE.fetch_add(grow, Ordering::Relaxed) + grow;
            PEAK.fetch_max(live, Ordering::Relaxed);
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One count at a time: the allocator's peak is the process's.
static ONE_COUNT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn peak_of<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = work();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(before))
}

/// An output that keeps a length and no bytes.
#[derive(Default)]
struct Counted {
    len: u64,
}

impl Write for &mut Counted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A stored RAR 5 archive of one [`MEMBER`] byte member with a record of
/// `percent`, from this tree's own writer.
fn archive(percent: u32) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let data: Vec<u8> = (0..MEMBER)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        host_os: HostOs::Unix,
        recovery_percent: Some(percent),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"a.bin",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn read_vint(b: &[u8], mut i: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = b[i];
        i += 1;
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, i);
        }
    }
}

fn write_vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `archive` with the percentage in its `RR` header's type 7 record
/// rewritten to `percent` and the header's sizes and CRC32 stamped again.
/// The record itself is left as it was.
fn with_percentage(archive: &[u8], percent: u64) -> Vec<u8> {
    let mut i = 8;
    loop {
        let (size, body_at) = read_vint(archive, i + 4);
        let end = body_at + size as usize;
        let (kind, at) = read_vint(archive, body_at);
        let (flags, at) = read_vint(archive, at);
        assert!(kind != 5, "no RR service header");
        let (extra, extra_end) = if flags & 1 != 0 {
            read_vint(archive, at)
        } else {
            (0, at)
        };
        let data = if flags & 2 != 0 {
            read_vint(archive, extra_end).0
        } else {
            0
        };
        let extra_start = end - extra as usize;
        if kind == 3 && extra > 0 && archive[extra_start + 1] == 7 {
            let mut record = vec![7u8];
            record.extend(write_vint(percent));
            let mut area = write_vint(record.len() as u64);
            area.extend(record);
            let mut body = archive[body_at..at].to_vec();
            body.extend(write_vint(area.len() as u64));
            body.extend_from_slice(&archive[extra_end..extra_start]);
            body.extend(area);
            let mut header = write_vint(body.len() as u64);
            header.extend(body);
            let mut out = archive[..i].to_vec();
            out.extend_from_slice(&rarkit::checksum::crc32(&header).to_le_bytes());
            out.extend(header);
            out.extend_from_slice(&archive[end..]);
            return out;
        }
        i = end + data as usize;
    }
}

fn open(bytes: Vec<u8>) -> Archive {
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    Archive::open(source, &ReadOptions::default()).expect("the archive opens")
}

fn stated(archive: &Archive) -> Option<u32> {
    archive
        .services()
        .find(|svc| svc.kind == ServiceKind::RecoveryRecord)
        .and_then(|svc| svc.recovery_percent)
}

/// One edit of the archive under test, into a counted output.
type OneEdit<'a> = Box<dyn Fn(&mut Counted) -> rarkit::Result<()> + 'a>;

fn on_the_pool(work: impl FnOnce() + Send) {
    let _one = ONE_COUNT.lock().unwrap_or_else(|e| e.into_inner());
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(work);
}

/// The item's scenario: a 1 percent record whose header was patched to
/// say 1,000. Each of the edits that carry the record (the reference's
/// `k`, `c` and `rn`) keeps the bound, whether it refuses or writes.
#[test]
fn a_patched_percentage_does_not_size_the_rewrite() {
    on_the_pool(|| {
        let honest = archive(1);
        for claimed in [1_000u64, 300, 100, 7] {
            let patched = with_percentage(&honest, claimed);
            let len = patched.len();
            let src = open(patched);
            assert_eq!(stated(&src), Some(claimed as u32), "the patch took");

            let edits: [(&str, OneEdit<'_>); 3] = [
                ("lock", Box::new(|out| edit::lock(&src, out))),
                (
                    "comment",
                    Box::new(|out| edit::set_comment(&src, Some(b"a note"), out).map(|_| ())),
                ),
                (
                    "rename",
                    Box::new(|out| edit::rename(&src, b"a.bin", b"b.bin", out).map(|_| ())),
                ),
            ];
            for (name, run) in &edits {
                let mut out = Counted::default();
                let (outcome, peak) = peak_of(|| run(&mut out));
                assert!(
                    out.len <= len as u64 + SLACK,
                    "{name}, {claimed} percent claimed over a 1 percent record: \
                     wrote {} bytes from a {len} byte archive",
                    out.len
                );
                assert!(
                    peak <= HELD_TIMES * len,
                    "{name}, {claimed} percent claimed over a 1 percent record: \
                     held {peak} bytes over a {len} byte archive"
                );
                // A claim the record cannot bear is a refusal by name, and
                // nothing was written for it.
                let error = outcome.expect_err("a claim past the record is refused");
                assert_eq!(out.len, 0, "{name}: written before the refusal");
                assert!(
                    error.to_string().contains("recovery record"),
                    "{name}: {error}"
                );
            }
        }
    });
}

/// The control: a record that IS what its header states is carried at
/// that percentage, above 100 percent too, and a header that states LESS
/// than the record is believed (the rewrite is then the smaller one).
#[test]
fn a_truthful_percentage_is_still_carried() {
    on_the_pool(|| {
        for percent in [1u32, 5, 100, 300] {
            let bytes = archive(percent);
            let len = bytes.len() as u64;
            let src = open(bytes);
            let mut out = Vec::new();
            edit::lock(&src, &mut out).unwrap_or_else(|e| panic!("{percent} percent: {e}"));
            assert!(out.len() as u64 <= len + SLACK, "{percent} percent");
            let after = open(out);
            assert!(after.is_locked());
            assert_eq!(stated(&after), Some(percent));
        }
        let lowered = with_percentage(&archive(5), 1);
        let len = lowered.len();
        let src = open(lowered);
        let mut out = Vec::new();
        edit::lock(&src, &mut out).expect("a claim under the record is carried");
        assert!(out.len() < len);
        assert_eq!(stated(&open(out)), Some(1));
    });
}
