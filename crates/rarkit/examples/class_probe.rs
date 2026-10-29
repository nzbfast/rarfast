//! A member's CLASS reading, far links a byte (`encode::class`, SPEC-H3
//! 8.1), so the cut-offs the levels ship are numbers read off real inputs.
//!
//! `class_probe [--members] <name>=<file or directory>...` prints, for each
//! input, the reading of its HEAD (the first megabyte, which is what the
//! writer reads) beside the reading of sixteen windows spread across its
//! first 4 MiB, its first 32 MiB and the whole of it (the forms the rule
//! was first counted in). A directory is read as one member, its files
//! joined in sorted path order; with `--members`, every file of a megabyte
//! or more under it is a row of its own.
//!
//! `class_probe --cost <times> <file>` reads the file's head that many
//! times and prints nothing else of use: run it counted at two values of
//! `<times>` and the difference is what one reading costs.

use rarkit::internals::rar20;

fn files_under(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(root)
        .expect("the directory lists")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let kind = std::fs::symlink_metadata(&path).expect("the entry stats");
        if kind.is_dir() {
            files_under(&path, out);
        } else if kind.is_file() {
            out.push(path);
        }
    }
}

fn milli(reading: Option<(u32, u32)>) -> String {
    reading.map_or("-".into(), |(far, _)| {
        format!("{}.{:03}", far / 1000, far % 1000)
    })
}

fn row(name: &str, data: &[u8]) {
    let first = |bytes: usize| rar20::class_far_links_per_mille(&data[..data.len().min(bytes)]);
    let head = first(rar20::CLASS_HEAD_BYTES);
    println!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
        name,
        data.len(),
        milli(head),
        head.map_or("-".into(), |(_, tokens)| format!("0.{tokens:03}")),
        milli(first(4 << 20)),
        milli(first(32 << 20)),
        milli(rar20::class_far_links_per_mille(data)),
        milli(rar20::class_far_links_parsing(
            &data[..data.len().min(rar20::CLASS_HEAD_BYTES)],
            4,
            2,
        )),
        milli(rar20::class_far_links_parsing(
            &data[..data.len().min(rar20::CLASS_HEAD_BYTES)],
            2,
            1,
        )),
    );
}

fn main() {
    let mut members = false;
    let mut inputs = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--members" {
            members = true;
        } else if arg == "--cost" {
            // The reading's own cost: the head of <file> read <times>
            // times, for a counted run (`/usr/bin/time -l`, `perf stat`) at
            // two counts whose difference is the reading and nothing else.
            let times: usize = args
                .next()
                .and_then(|n| n.parse().ok())
                .expect("--cost <times> <file>");
            let data =
                std::fs::read(args.next().expect("--cost <times> <file>")).expect("the file reads");
            let head = &data[..data.len().min(rar20::CLASS_HEAD_BYTES)];
            let mut last = None;
            let mut walls = Vec::with_capacity(times);
            for _ in 0..times {
                let start = std::time::Instant::now();
                last = std::hint::black_box(rar20::class_far_links_per_mille(
                    std::hint::black_box(head),
                ));
                walls.push(start.elapsed().as_secs_f64() * 1e3);
            }
            walls.sort_by(f64::total_cmp);
            println!(
                "{times} readings, the last {last:?}; least {:.3} ms, median {:.3} ms",
                walls.first().copied().unwrap_or(0.0),
                walls.get(times / 2).copied().unwrap_or(0.0)
            );
            return;
        } else if arg == "--cost-wide" {
            // The same count for the reading as the encoder takes it, on
            // <workers> threads, with the wall of one reading (the least
            // and the median of <times>).
            let usage = "--cost-wide <times> <workers> <file>";
            let times: usize = args.next().and_then(|n| n.parse().ok()).expect(usage);
            let workers: usize = args.next().and_then(|n| n.parse().ok()).expect(usage);
            let data = std::fs::read(args.next().expect(usage)).expect("the file reads");
            let head = &data[..data.len().min(rar20::CLASS_HEAD_BYTES)];
            let mut last = None;
            let mut walls = Vec::with_capacity(times);
            for _ in 0..times {
                let start = std::time::Instant::now();
                last = std::hint::black_box(rar20::class_far_links_wide(
                    std::hint::black_box(head),
                    workers,
                ));
                walls.push(start.elapsed().as_secs_f64() * 1e3);
            }
            walls.sort_by(f64::total_cmp);
            println!(
                "{times} readings at {workers} workers, the last {last:?}; least {:.3} ms, median {:.3} ms",
                walls.first().copied().unwrap_or(0.0),
                walls.get(times / 2).copied().unwrap_or(0.0)
            );
            return;
        } else {
            inputs.push(arg);
        }
    }
    if inputs.is_empty() {
        eprintln!("usage: class_probe [--members] <name>=<file or directory>...");
        std::process::exit(2);
    }
    println!("| input | bytes | HEAD: far links a byte | head: tokens a byte | first 4 MiB | first 32 MiB | whole | head, 4 windows parsed | head, 8 windows parsed |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for input in inputs {
        let (name, path) = input.split_once('=').expect("name=path");
        let path = std::path::Path::new(path);
        if !path.is_dir() {
            row(name, &std::fs::read(path).expect("the file reads"));
            continue;
        }
        let mut files = Vec::new();
        files_under(path, &mut files);
        if members {
            for file in files {
                let size = std::fs::metadata(&file).expect("the file stats").len();
                if size >= rar20::CLASS_HEAD_BYTES as u64 {
                    let data = std::fs::read(&file).expect("the file reads");
                    let shown = file.strip_prefix(path).unwrap_or(&file);
                    row(&format!("{name}/{}", shown.display()), &data);
                }
            }
        } else {
            let mut joined = Vec::new();
            for file in files {
                joined.extend(std::fs::read(&file).expect("the file reads"));
            }
            row(name, &joined);
        }
    }
}
