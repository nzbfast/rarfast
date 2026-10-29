//! The ENGINE arm of the tool-level round: the same archive, the same
//! files on disk, and none of the dialect.
//!
//! The tool-level gap this binary measures is the difference between
//! what `rarfast x` costs and what the engine costs doing the same work,
//! and that difference is only a number if both are measured as
//! processes. This binary is the second process: it opens the volumes it
//! is given, calls [`rarkit::extract_parallel`] with a sink that creates
//! one plain file per member, and exits. No progress lines, no plan, no
//! archive-order buffering, no path safety, no mtime restore.
//!
//! It is deliberately NOT a correct extractor and must not be used as
//! one: it flattens names to their last component and trusts them. It
//! exists to be timed beside `rarfast` over the same bytes.
//!
//!     engine_arm <archive> <out-dir> [breadth]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, ParallelSink};

struct Files {
    dest: PathBuf,
}

impl ParallelSink for Files {
    type Out = std::fs::File;

    fn open(&self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Self::Out>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        let name = String::from_utf8_lossy(member.name).replace('\\', "/");
        let leaf = name.rsplit('/').next().unwrap_or("out").to_owned();
        match std::fs::File::create(self.dest.join(leaf)) {
            Ok(file) => Ok(Disposition::Write(file)),
            Err(_) => Ok(Disposition::Skip),
        }
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        _outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        drop(out);
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(archive) = args.first() else {
        eprintln!("usage: engine_arm <archive> <out-dir> [breadth]");
        std::process::exit(2);
    };
    let dest = PathBuf::from(args.get(1).map_or("out", String::as_str));
    let breadth: usize = args.get(2).and_then(|n| n.parse().ok()).unwrap_or(8);
    std::fs::create_dir_all(&dest).unwrap();

    let mut sources: Vec<Arc<dyn rarkit::RangeSource>> = Vec::new();
    let mut name = archive.clone();
    loop {
        let Ok(file) = std::fs::File::open(Path::new(&name)) else {
            break;
        };
        sources.push(Arc::new(file));
        match next_volume(&name) {
            Some(next) if Path::new(&next).exists() => name = next,
            _ => break,
        }
    }

    let options = rarkit::ReadOptions::default();
    let sink = Files { dest };
    match rarkit::extract_parallel(sources, &options, &sink, breadth) {
        Ok(report) => {
            let _ = writeln!(std::io::stderr(), "members {}", report.members);
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "error {err}");
            std::process::exit(1);
        }
    }
}

/// `name.partNN.rar` and `name.rNN`, the two schemes the dialect walks.
fn next_volume(path: &str) -> Option<String> {
    rarfast_next_volume(path)
}

fn rarfast_next_volume(path: &str) -> Option<String> {
    let (stem, digits) = split_trailing_digits(path.strip_suffix(".rar")?)?;
    let width = digits.len();
    let next = digits.parse::<u64>().ok()? + 1;
    Some(format!("{stem}{next:0width$}.rar"))
}

fn split_trailing_digits(text: &str) -> Option<(&str, &str)> {
    let end = text.len();
    let start = text
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()?
        .0;
    if start == end {
        return None;
    }
    Some((&text[..start], &text[start..]))
}
