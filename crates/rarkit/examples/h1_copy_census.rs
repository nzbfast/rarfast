//! WHICH of `Window::copy`'s paths issues the `memmove` calls, counted.
//!
//! The profile of `rar3_text_64m_lz` puts 12.09 percent of rarkit's arm
//! in `_platform_memmove` and 2.77 in its stub. `Window::copy` has two
//! paths that could issue them: the non-overlapping ladder, which is
//! call-free to 64 bytes and a variable `copy_within` above that, and the
//! overlapping chunk loop, which copies a variable length at EVERY chunk.
//! A sampled leaf census cannot separate them. This counts them.
//!
//! Nothing here is timed and nothing here is a wall. Give it a path to a
//! RAR 4 archive; it decodes every RAR 2.9 chain in it with rarkit's own
//! decoder and prints the census.
//!
//!     RARKIT_H1_COPY_CENSUS=1 cargo run --release --features \
//!         copy-census,bench-internals,test-support \
//!         --example h1_copy_census -- <archive.rar>
//!
//! `copy-census` compiles the counters; `bench-internals` is the seam
//! this example reaches them through. The bench turns on the second and
//! never the first, which is what keeps the counting out of the arm it
//! times.
#[path = "../tests/support/rar4lz.rs"]
mod rar4lz;

use rarkit::internals::rar3_lz::{decode_stream, MemberIn};
use rarkit::internals::window_census;

fn main() {
    let path = std::env::args().nth(1).expect("a path to a .rar archive");
    if std::env::var_os("RARKIT_H1_COPY_CENSUS").is_none() {
        eprintln!("RARKIT_H1_COPY_CENSUS is not set, so the counters stay off");
        eprintln!("and every bucket would read zero. Refusing to print a table");
        eprintln!("of zeros that looks like a finding.");
        std::process::exit(2);
    }
    let archive = std::fs::read(&path).expect("the archive");
    window_census::reset();

    let (mut chains, mut bytes) = (0u64, 0u64);
    for chain in rar4lz::chains(&archive) {
        if chain
            .members
            .iter()
            .any(|m| m.version != 29 || m.method == 0x30)
        {
            continue;
        }
        // As the timed arm does: one member of its own is read where it
        // lies, and only a solid chain's spans are staged together.
        let members: Vec<MemberIn> = chain
            .members
            .iter()
            .zip(&chain.spans)
            .map(|(member, span)| MemberIn {
                packed: span.clone(),
                unpacked: member.unpacked,
            })
            .collect();
        let staged;
        let (packed, members) = if chain.members.len() == 1 {
            let span = chain.members[0].data.clone();
            staged = [MemberIn {
                packed: 0..span.len(),
                unpacked: chain.members[0].unpacked,
            }];
            (&archive[span], &staged[..])
        } else {
            (&chain.packed[..], &members[..])
        };
        match decode_stream(packed, members, chain.dictionary, false) {
            Ok((done, _)) => {
                chains += 1;
                bytes += done.iter().map(|member| member.bytes).sum::<u64>();
            }
            Err(error) => println!("chain failed: {error}"),
        }
    }

    println!("archive {path}");
    println!("chains decoded {chains}, bytes out {bytes}");
    let rows = window_census::read();
    let calls: u64 = rows[window_census::OVERLAP_CALLS].1
        + rows[window_census::LADDER_FALLTHROUGH].0
        + rows[window_census::OTHER].0;
    let copies: u64 = rows
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != window_census::OVERLAP_CALLS)
        .map(|(_, r)| r.0)
        .sum();
    println!();
    println!("{:<52} {:>12} {:>16}", "bucket", "copies", "bytes");
    for (i, name) in window_census::BUCKETS.iter().enumerate() {
        let (n, b) = rows[i];
        if i == window_census::OVERLAP_CALLS {
            println!("{name:<52} {n:>12} {b:>16}  (chunks, not copies)");
        } else if copies == 0 {
            println!("{name:<52} {n:>12} {b:>16}      no copies at all");
        } else {
            let share = 100.0 * n as f64 / copies as f64;
            println!("{name:<52} {n:>12} {b:>16}  {share:5.2}% of copies");
        }
    }
    println!();
    println!("copies total {copies}");
    println!(
        "memmove CALLS issued {calls}, which is {:.2} per copy",
        if copies > 0 {
            calls as f64 / copies as f64
        } else {
            0.0
        }
    );
    println!();
    println!("A CALL comes from three places only: every chunk of the");
    println!("overlapping loop, the ladder's fall-through above 64 bytes,");
    println!("and the wrapping or behind-start path. The ladder's fixed and");
    println!("bytewise rungs issue none.");
}
