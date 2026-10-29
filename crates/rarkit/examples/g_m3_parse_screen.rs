//! The level 3 small-member screen: every file under
//! a directory encoded as its own RAR 5 member by ONE encoder at a plan
//! spelled out, as a non-solid set's writer encodes it, and the packed
//! total printed with the encode's wall. CPU and instructions are the
//! caller's, from `/usr/bin/time -l` or `perf stat`.
//!
//!     g_m3_parse_screen <dir> <plan> [dictionary] [--check] [--chunk=N]
//!         [--sizes=FILE] [--rar4]
//!
//! A member whose packed bytes are not smaller than its input is counted
//! at its input size, the store the writer would fall back to. `--check`
//! decodes every member again and compares it with its input.
//! `--chunk=N` concatenates the files in name order and cuts the bytes
//! into members of N bytes instead, the member-size sweep. `--sizes=FILE`
//! writes each member's input and packed length, one line each. `--rar4`
//! encodes with the RAR 2.9 encoder instead (no `--check` there). One JSON
//! line on stdout. The files are read before the clock starts.

use rarkit::internals::{rar20, rar5};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the directory reads") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: g_m3_parse_screen <dir> <plan> [dictionary] [--check]");
        std::process::exit(2);
    }
    let check = args.iter().any(|a| a == "--check");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let dir = Path::new(positional[0]);
    let plan = positional[1].as_str();
    let dictionary: u32 = positional
        .get(2)
        .map_or(128 << 10, |d| d.parse().expect("a dictionary in bytes"));
    let mut paths = Vec::new();
    walk(dir, &mut paths);
    paths.sort();
    let inputs: Vec<Vec<u8>> = paths
        .iter()
        .map(|p| std::fs::read(p).expect("a member reads"))
        .collect();
    let chunk: Option<usize> = args
        .iter()
        .find_map(|a| a.strip_prefix("--chunk="))
        .map(|n| n.parse().expect("a chunk in bytes"));
    let joined: Vec<u8> = if chunk.is_some() {
        inputs.concat()
    } else {
        Vec::new()
    };
    let members: Vec<&[u8]> = match chunk {
        Some(n) => joined.chunks(n).collect(),
        None => inputs.iter().map(Vec::as_slice).collect(),
    };
    let clock = Instant::now();
    let rar4 = args.iter().any(|a| a == "--rar4");
    let packed = if rar4 {
        rar20::rar29_encode_each_spelled(&members, plan, dictionary)
    } else {
        rar20::rar5_encode_each_spelled(&members, plan, dictionary)
    }
    .unwrap_or_else(|| panic!("{plan} is not a plan"));
    let wall = clock.elapsed().as_secs_f64();
    let input: usize = members.iter().map(|m| m.len()).sum();
    let packed_sum: usize = packed.iter().map(Vec::len).sum();
    let stored_floor: usize = packed
        .iter()
        .zip(&members)
        .map(|(p, m)| p.len().min(m.len()))
        .sum();
    if check && !rar4 {
        for (p, m) in packed.iter().zip(&members) {
            let back = rar5::decode_member(p, m.len() as u64, u64::from(dictionary), 0, false)
                .expect("decodes");
            assert!(back == *m, "a member decodes to its input");
        }
    }
    if let Some(file) = args.iter().find_map(|a| a.strip_prefix("--sizes=")) {
        let lines: String = packed
            .iter()
            .zip(&members)
            .map(|(p, m)| format!("{} {}\n", m.len(), p.len()))
            .collect();
        std::fs::write(file, lines).expect("the sizes file writes");
    }
    println!(
        "{{\"plan\":\"{plan}\",\"dictionary\":{dictionary},\"members\":{},\"input_bytes\":{input},\"packed_bytes\":{packed_sum},\"with_store\":{stored_floor},\"encode_wall_s\":{wall:.4},\"checked\":{check},\"rar4\":{rar4}}}",
        members.len()
    );
}
