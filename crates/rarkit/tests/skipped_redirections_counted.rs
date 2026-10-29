//! `ExtractReport::members` counts every member the sink was asked about,
//! a redirection the sink SKIPS included, as it counts a skipped file
//! (`Driver::skipped`: a skipped member is counted as a closed one is).
//!
//! Over the committed archives of `tests/redirection/` (reference rar 7.23
//! and genuine Linux rar 4.2.0, `make.sh`): symbolic links, hard links and
//! file copies, RAR 5 and RAR 4, solid and encrypted. Each sink counts its
//! own `open` calls, which is what the report's field says it counts.
//!
//! Width and memory: each run is the sequential entry point at widths 1
//! and 4 and the parallel one at width 4; the archives are under 400 KB
//! and nothing is written, so little memory is needed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rarkit::{extract, Disposition, MemberInfo, Password, RangeSource, ReadOptions, Result, Sink};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/redirection")).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn volumes(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// Which members the sink skips: all of them, or only the redirections
/// (the rest verified, which writes nothing).
#[derive(Clone, Copy, Debug)]
enum Skips {
    Everything,
    Redirections,
}

fn answer(skips: Skips, member: &MemberInfo<'_>) -> Disposition<std::io::Sink> {
    match skips {
        Skips::Everything => Disposition::Skip,
        Skips::Redirections if member.redirection.is_some() || member.is_directory => {
            Disposition::Skip
        }
        Skips::Redirections => Disposition::Verify,
    }
}

/// Counts its `open` calls, and how many of them were redirections.
struct Counting {
    skips: Skips,
    opened: AtomicU64,
    links: AtomicU64,
}

impl Counting {
    fn new(skips: Skips) -> Counting {
        Counting {
            skips,
            opened: AtomicU64::new(0),
            links: AtomicU64::new(0),
        }
    }

    fn open(&self, member: &MemberInfo<'_>) -> Disposition<std::io::Sink> {
        self.opened.fetch_add(1, Ordering::Relaxed);
        if member.redirection.is_some() {
            self.links.fetch_add(1, Ordering::Relaxed);
        }
        answer(self.skips, member)
    }
}

impl Sink for Counting {
    type Out = std::io::Sink;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(Counting::open(self, member))
    }
}

#[cfg(feature = "parallel")]
impl rarkit::ParallelSink for Counting {
    type Out = std::io::Sink;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(Counting::open(self, member))
    }
}

/// Every entry point, each with a fresh sink: the report's members, the
/// sink's opens and how many of those were redirections.
fn every_path(
    bytes: &[u8],
    password: Option<&str>,
    skips: Skips,
) -> Vec<(&'static str, u64, u64, u64)> {
    let options = |width| {
        ReadOptions::default()
            .with_workers(Some(width))
            .with_password(password.map(Password::from))
    };
    let mut runs = Vec::new();
    for (label, width) in [("sequential w1", 1), ("sequential w4", 4)] {
        let mut sink = Counting::new(skips);
        let report = extract(volumes(bytes), &options(width), &mut sink, &mut ())
            .unwrap_or_else(|e| panic!("{label} {skips:?}: {e}"));
        runs.push((
            label,
            report.members,
            sink.opened.into_inner(),
            sink.links.into_inner(),
        ));
    }
    #[cfg(feature = "parallel")]
    {
        let sink = Counting::new(skips);
        let report = rarkit::extract_parallel(volumes(bytes), &options(4), &sink, 4)
            .unwrap_or_else(|e| panic!("parallel {skips:?}: {e}"));
        runs.push((
            "parallel",
            report.members,
            sink.opened.into_inner(),
            sink.links.into_inner(),
        ));
    }
    runs
}

#[test]
fn a_skipped_redirection_is_counted_as_a_skipped_file_is() {
    for (archive, password) in [
        ("links5.rar", None),
        ("copies5.rar", None),
        ("solid5.rar", None),
        ("crypt5.rar", Some("redir")),
        ("links4.rar", None),
    ] {
        for skips in [Skips::Everything, Skips::Redirections] {
            for (label, members, opened, links) in every_path(&fixture(archive), password, skips) {
                assert!(links > 0, "{archive} {label}: no redirection was opened");
                assert_eq!(
                    members, opened,
                    "{archive} {label} {skips:?}: the report counts {members} members, the sink \
                     was asked about {opened}, {links} of them redirections"
                );
            }
        }
    }
}
