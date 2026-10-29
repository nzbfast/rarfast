//! Build one RAR 4 archive over a directory tree, for a measurement the
//! reference binary can no longer set up: `rar` 7.23 answers
//! `ERROR: Unknown option: ma4` and writes RAR 5 only.
//!
//! `cargo run --release -p rarkit --example rar4_corpus -- <archive> <dir> [-mN] [solid]`

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let archive = args.next().ok_or("usage: rar4_corpus <archive> <dir>")?;
    let root = args.next().ok_or("usage: rar4_corpus <archive> <dir>")?;
    let rest: Vec<String> = args.collect();
    let level = rest
        .iter()
        .find_map(|f| f.strip_prefix("-m"))
        .and_then(|n| n.parse::<u8>().ok())
        .unwrap_or(3);
    let solid = rest.iter().any(|f| f == "solid");

    let root = PathBuf::from(&root);
    let mut files = Vec::new();
    walk(&root, &mut files)?;
    let held: Vec<Vec<u8>> = files
        .iter()
        .map(std::fs::read)
        .collect::<std::io::Result<_>>()?;
    let names: Vec<String> = files
        .iter()
        .map(|p| {
            p.strip_prefix(&root)
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format: rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
        method: if level == 0 {
            rarkit::WriteMethod::Stored
        } else {
            rarkit::WriteMethod::Compressed {
                level,
                dictionary: None,
            }
        },
        solid,
        // The RAR 4 family writes no filter record (spec J, by design).
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..rarkit::WriteOptions::default()
    })?;
    for (name, bytes) in names.iter().zip(&held) {
        writer.add(rarkit::MemberSpec {
            name: name.as_bytes(),
            payload: rarkit::Payload::Bytes(bytes),
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })?;
    }
    let report = writer.finish_into(BufWriter::new(File::create(&archive)?))?;
    println!("{} members, {} bytes", names.len(), report.bytes);
    Ok(())
}
