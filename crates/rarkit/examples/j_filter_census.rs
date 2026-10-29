//! WHICH x86 program the spec J legs carry, counted rather than assumed.
//!
//! The filter-drain work's scan-then-convert x86 pass gains on RAR 5 record
//! TYPE 2, calls and jumps; on type 1, calls alone, its own figure sat
//! inside its corpus's noise and it claims nothing for it. A RAR 3 stream
//! more often carries type 1. So before any ratio is read off
//! `j/rar3/x86-code32` and its twin, this says which program those legs
//! actually frame.
//!
//! If they are type 1, the honest reading of those legs is "the split does
//! not reach here, and here is the count that says so", rather than a
//! disappointing ratio nobody can interpret.
//!
//! A count is a property of the stream, so it reads the same on every box,
//! belongs on the untimed one, and prices nothing.
//!
//! It reads the archives the gate bench caches under
//! `target/bench-h1`; run that bench's `j/rar3/x86-code32` leg once first.

#[path = "../tests/support/rar4lz.rs"]
mod rar4lz;
#[path = "../tests/support/rarwalk.rs"]
mod rarwalk;

use rarkit::internals::rar3_lz::{MemberIn, Runner};

fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h1");
    let legs = [
        ("j/rar3/x86-code32", "j_x86_code32.rar"),
        ("j/rar3/x86-code32-nofilter", "j_x86_code32_nofilter.rar"),
    ];

    println!(
        "{:<28} {:>11} {:>9} {:>7} {:>16} {:>9}",
        "leg", "archive B", "records", "slots", "program", "slot len"
    );

    for (leg, file) in legs {
        let path = dir.join(file);
        let Ok(archive) = std::fs::read(&path) else {
            println!(
                "{leg}: {} is not there. Run \
                 `cargo bench -p rarkit --bench two_arm -- j/rar3/x86-code32` \
                 once to cache it.",
                path.display()
            );
            continue;
        };

        // Driven exactly as `two_arm.rs`'s `rar3_ours` drives it, so the
        // census is of the stream the LEG decodes and not of some other
        // framing of the same bytes.
        let mut runner = Runner::new();
        let mut records_total = 0u64;
        let mut bytes_out = 0usize;
        let mut census: Vec<(&'static str, u32)> = Vec::new();

        for chain in rar4lz::chains(&archive) {
            if chain
                .members
                .iter()
                .any(|m| m.version != 29 || m.method == 0x30)
            {
                continue;
            }
            let staged: Vec<MemberIn> = chain
                .members
                .iter()
                .zip(&chain.spans)
                .map(|(member, span)| MemberIn {
                    packed: span.clone(),
                    unpacked: member.unpacked,
                })
                .collect();
            let single = chain.members.len() == 1;
            let span = chain.members[0].data.clone();
            let one = vec![MemberIn {
                packed: 0..span.len(),
                unpacked: chain.members[0].unpacked,
            }];
            let (packed, members): (&[u8], &[MemberIn]) = if single {
                (&archive[span], &one)
            } else {
                (&chain.packed, &staged)
            };
            let (decoded, records) = runner
                .run(packed, members, chain.dictionary, true)
                .expect("the leg's archive decodes");
            records_total += records;
            bytes_out += decoded.iter().map(|m| m.data.len()).sum::<usize>();
            // Taken AFTER the decode, off slots the definition wrote on the
            // cold path. Nothing here ran inside a measured arm.
            census = runner.filter_census();
        }

        if census.is_empty() {
            println!(
                "{leg:<28} {:>11} {records_total:>9} {:>7} {:>16} {:>9}",
                archive.len(),
                0,
                "none",
                "-"
            );
        }
        for (program, len) in &census {
            println!(
                "{leg:<28} {:>11} {records_total:>9} {:>7} {program:>16} {len:>9}",
                archive.len(),
                census.len(),
            );
        }
        println!("{leg:<28} decoded {bytes_out} bytes");
    }

    println!(
        "\nTYPE 1 is `x86-call`, calls alone. TYPE 2 is `x86-call-jump`.\n\
         The split's measured gain is on type 2; on type 1 it is unclaimed."
    );
}
