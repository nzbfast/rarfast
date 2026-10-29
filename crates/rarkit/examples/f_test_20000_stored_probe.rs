//! Where the per-member fixed cost of the 20,000 STORED member TEST legs
//! goes, counted rather than attributed.
//!
//! The two legs this probe serves are `f/test-20000-stored-vsverify` and
//! `f/test-20000-stored-vsnull`: 20,000 RAR 5 stored members of about 160
//! bytes each, walked by `rarkit::extract` on the walking thread with no
//! output written anywhere. Both engines run single threaded on this
//! shape, so the whole of the difference is per-member fixed cost: the
//! header walk, the sink's two calls, and the read and checksum of a
//! member whose body is smaller than one cache line pair.
//!
//! THE INSTRUMENT IS A COUNTER, and that is deliberate. Two earlier findings
//! (self time over a dependency-bound loop does not name
//! the marginal instruction; and, from the stored copy-chain work,
//! attribution is not subtraction either) both say the same thing: the
//! only honest answer to "is this the cost" is to remove the candidate
//! and measure again. So this probe counts what is exactly countable -
//! allocations, source reads, source bytes, and the three dispositions'
//! walls - and every wall it prints is INDICATIVE unless it was taken in
//! a timed hold.
//!
//! The three arms decompose the leg by DISPOSITION, one sink shape each,
//! through the one public entry point:
//!
//! * `skip`   - `Disposition::Skip`: the header walk and the sink's two
//!   calls, with no packed byte read and no checksum run at all.
//! * `verify` - `Disposition::Verify`: `skip` plus the read and the
//!   CRC32. This is `f/test-20000-stored-vsverify`'s rarkit arm exactly.
//! * `write`  - `Disposition::Write`: `verify` plus the writer call per
//!   chunk. This is `f/test-20000-stored-vsnull`'s rarkit arm exactly.
//!
//! `verify - skip` is what reading and checksumming 160 bytes costs;
//! `skip` is everything else, which is where a per-member fixed cost
//! lever has to come from.
//!
//! THERE IS NO ARM FOR THE OLD ENGINE AND THERE MUST NOT BE. Its wall is
//! timed by the gate bench and by nothing else here: attaching a
//! sampler to the oracle's process prints the predecessor's internal
//! symbol names, which this project does not read
//! (learned in the rar4-20000 probe).
//!
//! ```text
//! cargo run --release -p rarkit --example f_test_20000_stored_probe -- [options]
//!     --members N      members in the corpus (default 20000)
//!     --rounds N       timed rounds per arm (default 7)
//!     --loop ARM       skip | verify | write, for ever, so a sampler can attach
//!     --dir PATH       where the corpus lives (default target/bench-f)
//! ```
//!
//! The corpus is built by reference `rar` with the bench's own arguments
//! into the bench's own directory and file name, so a box that has
//! already run `f/test-20000-stored-*` reuses those bytes rather than
//! writing something merely similar.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

// ---- the counting allocator --------------------------------------------
//
// The counts mean something only while `COUNTING` is on, which the probe
// turns on around one arm at a time. Relaxed is right: nothing is ordered
// on these and every arm here is single threaded.

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

struct Counting;

// A counting allocator cannot be written in safe Rust: `GlobalAlloc` is an
// unsafe trait by definition. The crate denies `unsafe_code` and allows it
// on the item instead, which is what every other probe here does.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(
                new_size.saturating_sub(layout.size()) as u64,
                Ordering::Relaxed,
            );
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn counted<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    ALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let out = f();
    COUNTING.store(false, Ordering::Relaxed);
    (
        out,
        ALLOCS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

// ---- a source that counts what the engine asks of it --------------------

/// The bench's in-memory volume, with a call and byte counter around it.
///
/// The engine's reads are what a cursor lever moves, so they are counted
/// here rather than inferred: a window policy that reads the archive twice
/// and one that reads it once differ HERE and nowhere in a wall.
struct CountingSource {
    bytes: Vec<u8>,
    reads: AtomicU64,
    read_bytes: AtomicU64,
}

impl rarkit::RangeSource for CountingSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = rarkit::RangeSource::read_at(&self.bytes, offset, buf)?;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

// ---- the three sink shapes, which are the bench's own -------------------

/// `f/test-20000-stored-vsverify`'s rarkit arm: the `t` command's shape,
/// counting and allocating nothing per member.
struct Counter {
    members: u64,
    directories: u64,
    bytes: u64,
    how: Disposition,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Skip,
    Verify,
    Write,
}

/// The CRC32 writer `f/test-20000-stored-vsnull`'s sink hands over, which
/// is what makes that leg's arm a WRITE rather than a VERIFY.
struct CrcWriter(rarkit::checksum::Crc32);

impl std::io::Write for CrcWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl rarkit::Sink for Counter {
    type Out = CrcWriter;

    fn open(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<CrcWriter>> {
        self.members += 1;
        if member.is_directory {
            self.directories += 1;
            return Ok(rarkit::Disposition::Skip);
        }
        Ok(match self.how {
            Disposition::Skip => rarkit::Disposition::Skip,
            Disposition::Verify => rarkit::Disposition::Verify,
            Disposition::Write => {
                rarkit::Disposition::Write(CrcWriter(rarkit::checksum::Crc32::new()))
            }
        })
    }

    fn close(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
        _out: Option<CrcWriter>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        self.bytes += outcome.bytes;
        Ok(())
    }
}

// ---- the corpus ---------------------------------------------------------

/// The bench's own 20,000 member directory, written once and reused.
///
/// The body is the gate bench's `many_dir` exactly: a member of
/// about 160 bytes whose text names its own index.
fn many_dir(dir: &Path, members: usize) -> std::io::Result<PathBuf> {
    let many = dir.join("many");
    let done = dir.join("many.done");
    if done.exists() {
        return Ok(many);
    }
    std::fs::create_dir_all(&many)?;
    for i in 0..members {
        let body = format!("member {i} of {members}\n").repeat(8);
        std::fs::write(many.join(format!("m{i:05}.txt")), body)?;
    }
    std::fs::write(&done, b"1")?;
    Ok(many)
}

/// The bench's `f_l20ks` archive: `-ma5 -m0` over that directory, written
/// by reference `rar` so the probe reads the LEG's bytes.
fn corpus(dir: &Path, members: usize) -> std::io::Result<Vec<Vec<u8>>> {
    std::fs::create_dir_all(dir)?;
    let many = many_dir(dir, members)?;
    let list = || -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let n = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                n.starts_with("f_l20ks.") && n.ends_with(".rar")
            })
            .collect();
        v.sort();
        v
    };
    if list().is_empty() {
        let ok = Command::new("rar")
            .current_dir(dir)
            .args(["a", "-idq", "-y", "-r", "-ma5", "-m0"])
            .arg("f_l20ks.rar")
            .arg(many.file_name().unwrap_or_default())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err(std::io::Error::other(
                "reference `rar` did not write the corpus; is it on PATH (fleet boxes keep it in ~/bin)",
            ));
        }
    }
    let vols: Vec<Vec<u8>> = list()
        .iter()
        .filter_map(|p| std::fs::read(p).ok())
        .collect();
    if vols.is_empty() {
        return Err(std::io::Error::other(
            "no volume of the corpus could be read",
        ));
    }
    Ok(vols)
}

// ---- the arms -----------------------------------------------------------

/// One pass of one disposition over the corpus, answering the report and
/// the source's own counts.
fn arm(sources: &[Arc<CountingSource>], how: Disposition) -> (u64, u64, u64, u64) {
    for s in sources {
        s.reads.store(0, Ordering::Relaxed);
        s.read_bytes.store(0, Ordering::Relaxed);
    }
    let vols: Vec<Arc<dyn rarkit::RangeSource>> = sources
        .iter()
        .map(|s| s.clone() as Arc<dyn rarkit::RangeSource>)
        .collect();
    let mut sink = Counter {
        members: 0,
        directories: 0,
        bytes: 0,
        how,
    };
    let report = rarkit::extract(vols, &rarkit::ReadOptions::default(), &mut sink, &mut ())
        .expect("the probe corpus extracts");
    let reads = sources
        .iter()
        .map(|s| s.reads.load(Ordering::Relaxed))
        .sum();
    let read_bytes = sources
        .iter()
        .map(|s| s.read_bytes.load(Ordering::Relaxed))
        .sum();
    (report.members, sink.bytes, reads, read_bytes)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN wall"));
    v[v.len() / 2]
}

fn name(how: Disposition) -> &'static str {
    match how {
        Disposition::Skip => "skip",
        Disposition::Verify => "verify",
        Disposition::Write => "write",
    }
}

fn main() {
    let mut members = 20_000usize;
    let mut rounds = 7usize;
    let mut looping: Option<Disposition> = None;
    let mut dir = PathBuf::from("target/bench-f");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--members" => {
                i += 1;
                members = args[i].parse().expect("--members wants a number");
            }
            "--rounds" => {
                i += 1;
                rounds = args[i].parse().expect("--rounds wants a number");
            }
            "--dir" => {
                i += 1;
                dir = PathBuf::from(&args[i]);
            }
            "--loop" => {
                i += 1;
                looping = Some(match args[i].as_str() {
                    "skip" => Disposition::Skip,
                    "verify" => Disposition::Verify,
                    "write" => Disposition::Write,
                    other => panic!("--loop wants skip, verify or write, not {other}"),
                });
            }
            other => panic!("unknown option {other}"),
        }
        i += 1;
    }

    let vols = match corpus(&dir, members) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("corpus: {e}");
            std::process::exit(2);
        }
    };
    let archive_bytes: usize = vols.iter().map(|v| v.len()).sum();
    let sources: Vec<Arc<CountingSource>> = vols
        .into_iter()
        .map(|bytes| {
            Arc::new(CountingSource {
                bytes,
                reads: AtomicU64::new(0),
                read_bytes: AtomicU64::new(0),
            })
        })
        .collect();

    if let Some(how) = looping {
        eprintln!(
            "looping the {} arm; attach a sampler to THIS process",
            name(how)
        );
        loop {
            let _ = arm(&sources, how);
        }
    }

    println!("== the corpus");
    println!("  members declared  {members}");
    println!("  archive bytes     {archive_bytes}");
    println!("  volumes           {}", sources.len());
    println!();
    println!("== per member, {rounds} rounds each, WALLS ARE INDICATIVE unless this ran in a hold");
    println!(
        "{:<8} {:>9} {:>10} {:>9} {:>11} {:>8} {:>12} {:>9}",
        "arm", "ns/member", "wall ms", "allocs", "alloc bytes", "reads", "read bytes", "members"
    );

    let mut per_member: Vec<(Disposition, f64)> = Vec::new();
    for how in [Disposition::Skip, Disposition::Verify, Disposition::Write] {
        // The first pass is not timed: it fills the cursor's buffer and
        // the sink's, and a first-round figure prices those once for ever.
        let (counted_members, _, _, _) = arm(&sources, how);
        let mut walls: Vec<f64> = Vec::new();
        for _ in 0..rounds {
            let start = Instant::now();
            let _ = arm(&sources, how);
            walls.push(start.elapsed().as_secs_f64() * 1e3);
        }
        let wall = median(walls);
        // Allocations are counted on their own pass: the counter is a
        // pair of atomics in the allocator's path and would be inside any
        // wall taken beside it.
        let ((_, _, reads, read_bytes), allocs, alloc_bytes) = counted(|| arm(&sources, how));
        let ns = wall * 1e6 / counted_members.max(1) as f64;
        per_member.push((how, ns));
        println!(
            "{:<8} {:>9.1} {:>10.3} {:>9} {:>11} {:>8} {:>12} {:>9}",
            name(how),
            ns,
            wall,
            allocs,
            alloc_bytes,
            reads,
            read_bytes,
            counted_members
        );
    }

    let skip = per_member[0].1;
    let verify = per_member[1].1;
    let write = per_member[2].1;
    println!();
    println!("== the decomposition, nanoseconds per member");
    println!(
        "  skip                       {skip:>8.1}   header walk, sink open and close, nothing read"
    );
    println!(
        "  verify - skip              {:>8.1}   the read and the CRC32 of about 160 bytes",
        verify - skip
    );
    println!(
        "  write  - verify            {:>8.1}   the writer call per chunk",
        write - verify
    );
    println!();
    println!("  `skip` is the floor a per-member fixed cost lever has to come out of.");
}
