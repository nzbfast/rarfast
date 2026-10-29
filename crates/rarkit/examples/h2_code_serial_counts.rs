//! THE SERIAL CODE ROW BY COUNT, rarkit's arm ALONE.
//!
//! `rar5_code_32m_m3_serial` reads LEVEL on an M1 Mac while its unfiltered
//! twin `rar5_code_32m_m3_nofilter_serial` reads WON there, so the question
//! this answers is where the filtered member's extra cost sits: in the
//! filter pass (the ring copy and the x86 transform the serial drain runs
//! inline) or in the serial loop's own shape. It is answered by COUNT, under
//! `/usr/bin/time -l`, which prints a process's instructions retired and
//! cycles elapsed, each mode run at `passes` and at 0 so reading the archive
//! and starting the process fall outside the difference.
//!
//! Only rarkit's own code runs here. The old engine is never started, let
//! alone instrumented.
//!
//! Modes:
//!
//! * `serial <archive> <passes> <arm>`: the `_serial` legs' rarkit arm,
//!   `internals::rar5::extract(archive, false)`, `passes` times, under the
//!   filter pass's subtraction arm (`rar5_lz::filters::arms`): 0 what ships,
//!   1 the transform not run, 2 every record dropped. `0 - 1` is the
//!   transform's price inside the serial decode and `0 - 2` the whole
//!   filter path's.
//! * `pass <archive> <passes> <body>`: every x86 block the archive's own
//!   records frame, copied into a scratch and run through one pass body,
//!   `passes` times over the whole member: body `copy` copies and runs
//!   nothing, and `walking` and `split` name the two carried bodies.
//!   `body - copy` is that body's own price, on exactly the blocks the
//!   decode hands it. The shipped ADAPTIVE body is not reachable through
//!   this seam, and on this corpus it needs no arm of its own: a block at
//!   13 bytes a trigger is under `X86_SPLIT_UPTO`, so the adaptive body
//!   runs the split from its first batch to its last.
//!
//! * `check <archive> 0 -`: walking and split once over every block, which
//!   must agree byte for byte, so the two bodies a count compares are
//!   known to do the same work on this member.
//!
//! Every mode prints one line with the byte total, so a harness can read
//! that the mode ran and did the work it was asked to.
//!
//! Usage: `cargo run --release -p rarkit --example h2_code_serial_counts
//! --features h2-filter-arms,bench-internals,test-support -- MODE ...`

use rarkit::internals::rar5 as h2;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("serial | pass | check");
    let path = args.next().expect("an archive path");
    let passes: usize = args
        .next()
        .and_then(|n| n.parse().ok())
        .expect("a pass count");
    let which = args.next().expect("an arm or a body");
    let archive = std::fs::read(&path).expect("the archive reads");
    match mode.as_str() {
        "serial" => {
            let arm: u8 = which.parse().expect("arm 0, 1 or 2");
            h2::set_filter_arm(arm);
            let mut total = 0u64;
            for _ in 0..passes {
                // The leg's own arm: the members concatenated into one
                // buffer, as `two_arm`'s `h2_ours_arm` does.
                let members = h2::extract(&archive, false).expect("rarkit extracts");
                let mut out = Vec::new();
                for (_, data) in members {
                    if out.is_empty() {
                        out = data;
                    } else {
                        out.extend_from_slice(&data);
                    }
                }
                total += out.len() as u64;
                std::hint::black_box(&out);
            }
            println!("serial {path} arm {arm} passes {passes} bytes {total}");
        }
        "pass" => {
            let blocks = h2::x86_filter_blocks(&archive).expect("the blocks");
            let body: u8 = match which.as_str() {
                "copy" => 255,
                "walking" => 0,
                "split" => 1,
                other => panic!("unknown body {other}"),
            };
            let mut scratch: Vec<u8> = Vec::new();
            let mut total = 0u64;
            for _ in 0..passes {
                for block in &blocks {
                    scratch.clear();
                    scratch.extend_from_slice(&block.data);
                    if body != 255 {
                        h2::rar5_x86_pass(&mut scratch, block.f, block.jump, body);
                    }
                    total += scratch.len() as u64;
                    std::hint::black_box(&scratch);
                }
            }
            println!(
                "pass {path} body {which} blocks {} passes {passes} bytes {total}",
                blocks.len()
            );
        }
        "check" => {
            let blocks = h2::x86_filter_blocks(&archive).expect("the blocks");
            let mut bytes = 0u64;
            let mut jumps = 0usize;
            for block in &blocks {
                let mut walked = block.data.clone();
                h2::rar5_x86_pass(&mut walked, block.f, block.jump, 0);
                let mut split = block.data.clone();
                h2::rar5_x86_pass(&mut split, block.f, block.jump, 1);
                assert!(walked == split, "the two bodies disagree on a block");
                bytes += walked.len() as u64;
                jumps += usize::from(block.jump);
            }
            println!(
                "check {path} blocks {} type2 {jumps} bytes {bytes} agree",
                blocks.len()
            );
        }
        other => panic!("unknown mode {other}"),
    }
}
