//! The x86 scan's arms priced across TRIGGER DENSITY, not at one density.
//!
//! The 22 Sep subtraction priced six arms on the code
//! leg's own corpus and found a sixteen byte NEON compare worth about a
//! quarter. That corpus has ONE density: a trigger every 13.33 bytes. The
//! filter-drain work showed that both instruments share that
//! limitation, and that a second corpus at a different trigger gap is worth
//! more than a third driver at the same one. It is right, and this is that
//! corpus.
//!
//! It matters most for the SHIPPABLE NEON arm. That arm differs from the
//! prototype that produced the 1.2492x in exactly one way: it carries the
//! sparse `memchr` path. At 13.33 bytes a trigger that path is never
//! reached, so the prototype's figure is honest there and silent about
//! everything else. **No equivalence test can catch a missing sparse path**,
//! because it is a performance property and not a correctness one: a scan
//! without it computes the same bytes, just slowly. Only this can.
//!
//! The densities are chosen against the block census in
//! `X86_PROBE_BYTES`'s own comment: 98.4 percent of filtered bytes sit in
//! blocks whose median trigger gap is 64 bytes or less, the byte weighted
//! p90 of that median is 38 and its p99 is 83. Past about 180 is reachable
//! only through `-mce+`, which forces the filter onto data its own detector
//! rejected. So 8 to 64 is where real archives live, 128 to 512 is the
//! `-mce+` tail, and an arm that wins in the first band and collapses in
//! the second is still a good arm as long as somebody has measured where
//! it turns over.
//!
//! GEOMETRIC gaps, not a fixed stride. A fixed stride pins every vector
//! search at one alignment and is worth a factor of 2.4 to a baseline on
//! its own; the 16 Sep probe-width sweep was withdrawn and redrawn for
//! exactly that reason.

use std::time::Instant;

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a wall clock"));
    let half = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[half - 1] + values[half]) / 2.0
    } else {
        values[half]
    }
}

fn mad_percent(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    let centre = median(&mut sorted);
    let mut spread: Vec<f64> = values.iter().map(|v| (v - centre).abs()).collect();
    let mad = median(&mut spread);
    if centre == 0.0 {
        0.0
    } else {
        mad / centre * 100.0
    }
}

/// A block of `len` bytes whose trigger gaps are geometric with mean `gap`.
///
/// Every trigger is followed by four operand bytes drawn from the same
/// stream, so an operand can itself hold a trigger byte, which is the case
/// the five byte skip exists for.
fn block(len: usize, gap: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        // Geometric: keep drawing until a 1-in-gap event.
        loop {
            if gap <= 1 || (next() % gap as u64) == 0 {
                break;
            }
            // Filler that is never a trigger byte.
            out.push(match next() % 6 {
                0 => 0x00,
                1 => 0xff,
                2 => 0x8b,
                3 => 0x48,
                4 => 0x89,
                _ => 0x0f,
            });
            if out.len() >= len {
                break;
            }
        }
        if out.len() >= len {
            break;
        }
        out.push(if next() % 4 == 0 { 0xe9 } else { 0xe8 });
        for _ in 0..4 {
            out.push((next() >> 11) as u8);
        }
    }
    out.truncate(len);
    out
}

fn main() {
    let flag = |name: &str, default: usize| -> usize {
        let mut args = std::env::args();
        while let Some(arg) = args.next() {
            if arg == name {
                if let Some(v) = args.next().and_then(|v| v.parse().ok()) {
                    return v;
                }
            }
        }
        default
    };
    let len: usize = 4 << 20;
    let pairs: usize = flag("--pairs", 9);
    // A SECOND SEED draws a different corpus at the same density, which is
    // the check that a row is about the density and not about one draw.
    let seed: u64 = flag("--seed", 0x2209_2026) as u64;
    let arms: &[(u8, &str)] = &[
        (1, "shipped split, SWAR 8"),
        #[cfg(target_arch = "aarch64")]
        (5, "NEON prototype, NO sparse path"),
        #[cfg(target_arch = "aarch64")]
        (7, "NEON shippable, sparse path kept"),
        (0, "walking"),
    ];
    // THE ORDER IS A PARAMETER, because ascending density on one box makes
    // density and the CLOCK move together. That is read_width.py's own bug:
    // its ascending width sweep turned "slow share falls with width" into
    // "slow share falls with time". The ARMS inside a cell are interleaved
    // round robin, so a within-cell ratio, which is all this table reports,
    // cannot be biased by it. Running the densities DESCENDING as well
    // shows that rather than asserting it: if a row moves when the order
    // reverses, the row was about the clock.
    //
    // `--gaps 13,16,18,20,22,24,28,32` walks a finer set than the default
    // seven. The default cannot resolve a THRESHOLD: `X86_SPLIT_UPTO` is
    // 20 bytes a trigger and the whole band the aarch64 reasoning argues
    // over, 13 to 22, falls inside one interval of the default list. The
    // x86-64 half of that question needs points inside the band, so the
    // list is a parameter and the default is what it always was.
    let mut gaps = match std::env::args()
        .skip_while(|a| a != "--gaps")
        .nth(1)
        .map(|list| {
            list.split(',')
                .map(|part| part.trim().parse::<usize>())
                .collect::<Result<Vec<_>, _>>()
        }) {
        Some(Ok(walk)) if !walk.is_empty() => walk,
        Some(Ok(_)) | Some(Err(_)) => {
            eprintln!("--gaps wants a comma separated list of byte gaps, e.g. 13,16,20,32");
            std::process::exit(2);
        }
        None => vec![8usize, 13, 32, 64, 128, 256, 512],
    };
    if std::env::args().any(|a| a == "--reverse") {
        gaps.reverse();
    }

    println!(
        "{len} byte blocks, geometric gaps, seed {seed:#x}, {pairs} pairs a cell, \
         type 2 (calls and jumps)"
    );
    println!("shipped/arm, so above 1.0 is FASTER than what ships now\n");

    print!("| mean gap | triggers |");
    for (_, name) in arms {
        print!(" {name} |");
    }
    println!();
    print!("|---|---|");
    for _ in arms {
        print!("---|");
    }
    println!();

    for gap in gaps {
        let data = block(len, gap, seed);
        let triggers = data.iter().filter(|&&b| b == 0xe8 || b == 0xe9).count();

        // Correctness before timing, at THIS density: a sparse block walks
        // different code than a dense one in every arm.
        let mut want = data.clone();
        rarkit::internals::rar5::rar5_x86_pass(&mut want, 0, true, 1);
        for &(arm, name) in arms {
            let mut got = data.clone();
            rarkit::internals::rar5::rar5_x86_pass(&mut got, 0, true, arm);
            assert_eq!(want, got, "arm {arm} ({name}) disagrees at mean gap {gap}");
        }

        let time_one = |arm: u8| {
            let mut work = data.clone();
            let start = Instant::now();
            rarkit::internals::rar5::rar5_x86_pass(&mut work, 0, true, arm);
            let took = start.elapsed().as_secs_f64();
            std::hint::black_box(&work);
            took
        };

        let mut walls: Vec<Vec<f64>> = vec![Vec::new(); arms.len()];
        for _ in 0..pairs {
            for (slot, &(arm, _)) in arms.iter().enumerate() {
                walls[slot].push(time_one(arm));
            }
        }
        let shipped = median(&mut walls[0].clone());
        print!("| {gap} | {triggers} |");
        for samples in &walls {
            let wall = median(&mut samples.clone());
            print!(" {:.4}x ({:.2}) |", shipped / wall, mad_percent(samples));
        }
        println!();
    }

    println!(
        "\nReal archives live at a median gap of 64 or less (98.4 percent of \
         filtered bytes,\nby the block census in X86_PROBE_BYTES's comment). \
         Past about 180 is reachable\nonly through -mce+, which forces the \
         filter onto data its own detector rejected."
    );
}
