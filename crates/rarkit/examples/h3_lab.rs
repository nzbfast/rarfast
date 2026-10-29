//! Spec H3 part B lab driver: encode one file as a one member archive, so
//! the encoders can be timed CROSS PROCESS against reference `rar` and the
//! result admitted by reference `unrar`.
//!
//! `h3_lab <rar5|rar4|rar5-solid|rar4-solid|rar5-batch|rar4-batch> <level> <dictionary bytes> <input> <output.rar>`
//!
//! `<level>` may instead be a PLAN spelled out as
//! `<lazy|optimal>:<chain|tree>:<depth>:<enough>`, which is how the level
//! ladder's sweeps measure a point that is not on the shipped ladder
//! without rebuilding the crate for every point. The archive such a run
//! writes declares method 3, because the method byte names a level and a
//! spelled plan has none; `unrar` reads the stream and not the byte, so it
//! still admits it, and a size taken this way is comparable with any
//! other.
//!
//! The two `-solid` forms take a DIRECTORY as `<input>` and encode every
//! file under it, sorted by path, as one solid set through one encoder.
//! That is the shape a downloader's poster meets most often and the one
//! shape the single member forms cannot measure: a many small files set,
//! where the history across the member boundary is most of the ratio.
//!
//! `rar5-batch` and `rar4-batch` take the same directory through the
//! BATCHED solid entry, which stages several members and parses them as
//! one wave rather than joining at every member boundary. A 5 KB member
//! is a fifth of a parse block, so a member at a time gives the parse
//! nothing to spread over and the batch is the whole of the `-mt`
//! answer on that shape; the two forms must write the same bytes, which
//! is what `rar5_encode_solid_batched` is a differential arm for.
//!
//! Prints the encode wall (the encoder call alone, not the file I/O), the
//! packed size and the archive size. Peak RSS and CPU are the caller's to
//! take with `/usr/bin/time -l`, which sees the whole process.
//!
//! Two environment knobs, so that the positional arguments keep the shape
//! every caller of this driver already has:
//!
//! - `H3_LAB_THREADS=N` runs the encode on a pool of exactly `N` threads,
//!   which is what `-mt` reaches in the API. The default is rayon's own,
//!   which is every core. API promise 6 says the bytes do not move with
//!   it, and the ladder script checks that by comparing the packed size
//!   across widths on every corpus it sweeps.
//! - `H3_LAB_VERIFY` round trips the packed bytes through this engine's
//!   own decoder, with `H3_LAB_WINDOW` for the window to decode against.

#[path = "../tests/support/rar4build.rs"]
mod rar4build;
#[path = "../tests/support/rar5build.rs"]
mod rar5build;

use rarkit::internals::rar20;
use std::path::PathBuf;
use std::time::Instant;

/// Every file under `directory`, sorted by path: the members of a solid
/// set, in the order the set declares them.
fn members_of(directory: &str) -> Vec<Vec<u8>> {
    fn walk(at: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(std::path::Path::new(directory), &mut paths);
    paths.sort();
    paths
        .iter()
        .filter_map(|path| std::fs::read(path).ok())
        .filter(|bytes| !bytes.is_empty())
        .collect()
}

/// The pool width `H3_LAB_THREADS` asks for, or rayon's own default.
fn run<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    match std::env::var("H3_LAB_THREADS")
        .ok()
        .and_then(|n| n.parse().ok())
    {
        Some(threads) => rar20::on_threads(threads, work),
        None => work(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [format, level, dictionary, input, output] = &args[..] else {
        eprintln!(
            "usage: h3_lab <rar5|rar4|rar5-solid|rar4-solid|rar5-batch|rar4-batch> <level> <dictionary bytes> <input> <output.rar>"
        );
        std::process::exit(2);
    };
    let plan = level.contains(':').then(|| level.clone());
    let level: u8 = if plan.is_some() {
        3
    } else {
        level.parse().expect("a level")
    };
    let dictionary: u32 = dictionary.parse().expect("a dictionary in bytes");
    let exponent = (dictionary.max(131_072) / 131_072).trailing_zeros() as u8;
    let bits = (dictionary.clamp(65_536, 4 << 20) / 65_536).trailing_zeros() as u8;

    let solid = format
        .strip_suffix("-solid")
        .map(|family| (family, false))
        .or_else(|| format.strip_suffix("-batch").map(|family| (family, true)));
    if let Some((family, batched)) = solid {
        let members = members_of(input);
        let borrowed: Vec<&[u8]> = members.iter().map(|m| &m[..]).collect();
        let started = Instant::now();
        let packed = run(|| match (&plan, family, batched) {
            (Some(plan), "rar5", _) => {
                rar20::rar5_encode_solid_spelled(&borrowed, plan, dictionary).expect("a plan")
            }
            (Some(plan), _, _) => {
                rar20::rar29_encode_solid_spelled(&borrowed, plan, dictionary).expect("a plan")
            }
            (None, "rar5", false) => rar20::rar5_encode_solid(&borrowed, level, dictionary),
            (None, "rar5", true) => {
                rar20::rar5_encode_solid_batched(&borrowed, None, level, dictionary)
            }
            (None, _, false) => rar20::rar29_encode_solid(&borrowed, level, dictionary),
            (None, _, true) => {
                rar20::rar29_encode_solid_batched(&borrowed, None, level, dictionary)
            }
        });
        let wall = started.elapsed();
        let total: usize = packed.iter().map(Vec::len).sum();
        let bytes = if family == "rar5" {
            let built: Vec<rar5build::Member> = members
                .iter()
                .zip(&packed)
                .enumerate()
                .map(|(index, (unpacked, packed))| rar5build::Member {
                    name: "MEMBER.BIN",
                    unpacked,
                    packed,
                    dictionary_exponent: exponent,
                    method: level.clamp(1, 5),
                    solid: index > 0,
                })
                .collect();
            rar5build::archive(&built)
        } else {
            let built: Vec<rar4build::Member> = members
                .iter()
                .zip(&packed)
                .enumerate()
                .map(|(index, (unpacked, packed))| rar4build::Member {
                    name: "MEMBER.BIN",
                    unpacked,
                    packed,
                    version: 29,
                    method: 0x30 + level.clamp(1, 5),
                    dictionary_bits: bits,
                    solid: index > 0,
                })
                .collect();
            rar4build::archive(&built)
        };
        println!("wall {:.4} s", wall.as_secs_f64());
        println!(
            "members {}, packed {total} bytes, archive {} bytes",
            members.len(),
            bytes.len()
        );
        std::fs::write(output, bytes).expect("the archive is written");
        return;
    }

    let data = std::fs::read(input).expect("the input reads");
    let started = Instant::now();
    let (packed, bytes) = if format == "rar5" {
        let packed = run(|| match &plan {
            Some(plan) => rar20::rar5_encode_spelled(&data, plan, dictionary).expect("a plan"),
            None => rar20::rar5_encode(&data, level, dictionary),
        });
        let wall = started.elapsed();
        if std::env::var_os("H3_LAB_VERIFY").is_some() {
            let back = rarkit::internals::rar5::decode_member(
                &packed,
                data.len() as u64,
                std::env::var("H3_LAB_WINDOW")
                    .map_or(u64::from(dictionary), |x| x.parse().unwrap()),
                0,
                false,
            );
            match back {
                Ok(back) => {
                    let same = back.iter().zip(&data).take_while(|(a, b)| a == b).count();
                    println!("round trip: {} of {} bytes agree", same, data.len());
                }
                Err(error) => println!("round trip: {error}"),
            }
        }
        let bytes = rar5build::archive(&[rar5build::Member {
            name: "MEMBER.BIN",
            unpacked: &data,
            packed: &packed,
            dictionary_exponent: exponent,
            method: level.clamp(1, 5),
            solid: false,
        }]);
        println!("wall {:.4} s", wall.as_secs_f64());
        (packed.len(), bytes)
    } else {
        let packed = run(|| match &plan {
            Some(plan) => rar20::rar29_encode_spelled(&data, plan, dictionary).expect("a plan"),
            None => rar20::rar29_encode(&data, level, dictionary),
        });
        let wall = started.elapsed();
        let bytes = rar4build::archive(&[rar4build::Member {
            name: "MEMBER.BIN",
            unpacked: &data,
            packed: &packed,
            version: 29,
            method: 0x30 + level.clamp(1, 5),
            dictionary_bits: bits,
            solid: false,
        }]);
        println!("wall {:.4} s", wall.as_secs_f64());
        (packed.len(), bytes)
    };
    println!("packed {packed} bytes, archive {} bytes", bytes.len());
    std::fs::write(output, bytes).expect("the archive is written");
}
