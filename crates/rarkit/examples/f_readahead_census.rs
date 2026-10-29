//! How many calls a many-small walk makes into a FILE source, and how
//! many bytes it asks for.
//!
//! The adaptive cursor read-ahead work counts these on the shipped
//! engine before building anything: a walk over many small members
//! refills its 4 KiB window once per few members, one `pread` each, and
//! the question is how many of those calls a wider window would save and
//! whether a one-member or encrypted archive ever triggers the growth.
//!
//! It is a PROBE and not a gate leg: one sample, no old arm, and a figure
//! from it belongs in prose, never in a ratio table.
//!
//!     cargo run --release --example f_readahead_census -- <archive> [width] [password]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource, ReadOptions};

/// A file that counts every call made into it and the bytes each asked for.
struct Counting {
    file: std::fs::File,
    calls: AtomicU64,
    asked: AtomicU64,
}

impl RangeSource for Counting {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.asked.fetch_add(buf.len() as u64, Ordering::Relaxed);
        self.file.read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        self.file.available()
    }
    fn len(&self) -> Option<u64> {
        RangeSource::len(&self.file)
    }
}

/// A sink that keeps nothing.
struct Null;

impl ParallelSink for Null {
    type Out = std::io::Sink;

    fn open(&self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        _outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        Ok(())
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: f_readahead_census <archive> [width] [password]");
        std::process::exit(2);
    });
    let width: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(1);
    let mut opts = ReadOptions::default();
    if let Some(pw) = args.next() {
        opts = opts.with_password(Some(pw.as_str().into()));
    }
    let src = Arc::new(Counting {
        file: std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}")),
        calls: AtomicU64::new(0),
        asked: AtomicU64::new(0),
    });
    let sources: Vec<Arc<dyn RangeSource>> = vec![src.clone()];
    let report = match rarkit::extract_parallel(sources, &opts, &Null, width) {
        Ok(report) => report,
        Err(e) => {
            println!(
                "{path} width {width}: ERROR {e}; File calls {}, bytes asked {}",
                src.calls.load(Ordering::Relaxed),
                src.asked.load(Ordering::Relaxed)
            );
            return;
        }
    };
    println!(
        "{path} width {width}: {} members, {} bytes out; File calls {}, bytes asked {}, peak working {}",
        report.members,
        report.bytes,
        src.calls.load(Ordering::Relaxed),
        src.asked.load(Ordering::Relaxed),
        report.peak_working_memory
    );
}
