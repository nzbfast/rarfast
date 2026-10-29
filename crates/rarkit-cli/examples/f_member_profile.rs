//! The SEQUENTIAL driver over a many-member archive, alone in a process.
//!
//! It exists because `two_arm` runs rarkit and the old engine in ONE
//! process, so sampling that process samples the old engine too. This
//! binary lives in `rarkit-cli`, whose only rarkit dependency is the
//! library itself, so nothing of any other implementation is linked into
//! it and a symbol-keyed profile of it can only name rarkit's own code.
//!
//! The shape is `f/test-20000-stored-vsverify`'s rarkit arm exactly: the
//! volumes held IN MEMORY, `rarkit::extract` on the calling thread, and
//! a sink that answers `Disposition::Verify` and counts, so no byte is
//! ever written anywhere.
//!
//!     f_member_profile <archive> [rounds]
//!
//! It prints the member count, the byte count and the wall per member,
//! and it loops for `rounds` so that a sampler has a process to attach
//! to. It is NOT a bench: it has one arm and reports no ratio.

use std::sync::Arc;

struct Count {
    members: u64,
    bytes: u64,
}

impl rarkit::Sink for Count {
    type Out = std::io::Sink;

    fn open(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<Self::Out>> {
        self.members += 1;
        if member.is_directory {
            return Ok(rarkit::Disposition::Skip);
        }
        Ok(rarkit::Disposition::Verify)
    }

    fn close(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
        _out: Option<Self::Out>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        self.bytes += outcome.bytes;
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: f_member_profile <archive> [rounds]");
        std::process::exit(2);
    };
    let rounds: usize = args.get(1).and_then(|n| n.parse().ok()).unwrap_or(200);

    let bytes = std::fs::read(path).expect("the archive is readable");
    eprintln!("archive {} bytes, {rounds} rounds", bytes.len());
    let sources: Vec<Arc<dyn rarkit::RangeSource>> = vec![Arc::new(bytes)];

    let options = rarkit::ReadOptions::default();
    let started = std::time::Instant::now();
    let mut members = 0u64;
    for _ in 0..rounds {
        let mut sink = Count {
            members: 0,
            bytes: 0,
        };
        let report = rarkit::extract(sources.clone(), &options, &mut sink, &mut ())
            .expect("the corpus verifies");
        members = report.members;
        std::hint::black_box(sink.bytes);
    }
    let elapsed = started.elapsed();
    let per = elapsed.as_secs_f64() / (rounds as f64) / (members.max(1) as f64);
    eprintln!(
        "members {members}, {rounds} rounds in {:.3} s, {:.1} ns a member",
        elapsed.as_secs_f64(),
        per * 1e9
    );
}
