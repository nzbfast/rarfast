//! Write a RAR 4 stored VOLUME SET from files, for a measurement the
//! reference binary can no longer set up: `rar` 7.23 answers
//! `ERROR: Unknown option: ma4` and writes RAR 5 only, and the two
//! examples beside this one (`store_file`, `rar4_corpus`) write one
//! archive, never a set.
//!
//! It is `rar a -ma4 -m0 -v<size> <archive> <inputs>` in shape: every
//! member stored, each volume FILE capped at the size given, the classic
//! names (`.rar`, `.r00`, `.r01` and on) unless `numbered` is given
//! (`.part01.rar` and on). A directory is walked in name order and its
//! members are named from the directory's own name down, as `rar` does.
//!
//! Nothing is held: each input is opened when the writer reaches it and
//! read once, and each volume is a file the writer can go back over, so a
//! checksum known only after the bytes have passed is patched where it
//! lies. A 13 GB member costs a few megabytes of memory and one pass.
//!
//! The size takes `rar`'s own suffixes: `k`, `m`, `g` are powers of 1024
//! and `K`, `M`, `G` powers of 1000; bare digits are bytes.
//!
//! `cargo run --release -p rarkit --example rar4_volumes -- <archive> <volume size> <file or dir>... [numbered] [solid]`
//!
//! `<archive>` is the first volume's name without its extension or with
//! `.rar`: `out/full` and `out/full.rar` both write `out/full.rar`,
//! `out/full.r00` and on.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const USAGE: &str =
    "usage: rar4_volumes <archive> <volume size> <file or dir>... [numbered] [solid]";

/// One input, opened at its first read and closed at its last, so a tree
/// of many thousands of files never has more than one of them open.
struct Lazy {
    path: PathBuf,
    file: Option<File>,
    done: bool,
}

impl Read for Lazy {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.file.is_none() {
            self.file = Some(File::open(&self.path)?);
        }
        let got = match self.file.as_mut() {
            Some(file) => file.read(buf)?,
            None => 0,
        };
        if got == 0 && !buf.is_empty() {
            self.file = None;
            self.done = true;
        }
        Ok(got)
    }
}

/// The set's files, each created as the writer reaches it and written
/// under a working name until the count that settles the numbered
/// scheme's width is known.
struct Files {
    stem: String,
    written: Vec<PathBuf>,
}

impl Files {
    fn working(&self, index: u32) -> PathBuf {
        PathBuf::from(format!("{}.volume{index}.partial", self.stem))
    }
}

impl rarkit::VolumeOut for Files {
    type W = BufWriter<File>;

    fn volume(&mut self, index: u32) -> rarkit::Result<Self::W> {
        let path = self.working(index);
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        self.written.push(path);
        Ok(BufWriter::with_capacity(1 << 20, file))
    }

    fn finished(&mut self, _index: u32, mut volume: Self::W) -> rarkit::Result<()> {
        volume.flush()?;
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Self::W, at: u64, bytes: &[u8]) -> rarkit::Result<()> {
        volume.seek(SeekFrom::Start(at))?;
        volume.write_all(bytes)?;
        volume.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

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

fn size_of(text: &str) -> Option<u64> {
    let digits = text.trim_end_matches(|c: char| !c.is_ascii_digit());
    let unit: u64 = match &text[digits.len()..] {
        "" | "b" | "B" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        "K" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        _ => return None,
    };
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let archive = args.next().ok_or(USAGE)?;
    let cap = size_of(&args.next().ok_or(USAGE)?).ok_or("the volume size did not parse")?;
    let mut numbered = false;
    let mut solid = false;
    let mut inputs = Vec::new();
    for arg in args {
        match arg.as_str() {
            "numbered" => numbered = true,
            "solid" => solid = true,
            _ => inputs.push(PathBuf::from(arg)),
        }
    }
    if inputs.is_empty() {
        return Err(USAGE.into());
    }

    // (the name recorded, the file to read)
    let mut members: Vec<(String, PathBuf)> = Vec::new();
    for input in &inputs {
        let base = input
            .file_name()
            .ok_or("an input has no file name")?
            .to_string_lossy()
            .into_owned();
        if input.is_dir() {
            let mut files = Vec::new();
            walk(input, &mut files)?;
            for file in files {
                let below = file.strip_prefix(input)?.to_string_lossy().into_owned();
                members.push((format!("{base}/{below}"), file));
            }
        } else {
            members.push((base, input.clone()));
        }
    }

    let naming = if numbered {
        rarkit::VolumeNaming::Numbered
    } else {
        rarkit::VolumeNaming::Classic
    };
    let mut sizes = Vec::with_capacity(members.len());
    let mut times = Vec::with_capacity(members.len());
    for (_, path) in &members {
        let meta = std::fs::metadata(path)?;
        sizes.push(meta.len());
        times.push(
            meta.modified()
                .ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|since| rarkit::Timestamp {
                    unix_seconds: since.as_secs() as i64,
                    nanos: 0,
                }),
        );
    }
    // The classic scheme as this crate names it runs `.rar`, `.r00` to
    // `.r99`: 101 files. A set that would pass that is refused before a
    // byte is written, on the payload alone (the headers only add to it).
    let payload: u64 = sizes.iter().sum();
    if !numbered && payload / cap >= 101 {
        return Err("over 101 volumes at this size: give a larger size, or `numbered`".into());
    }

    let mut readers: Vec<Lazy> = members
        .iter()
        .map(|(_, path)| Lazy {
            path: path.clone(),
            file: None,
            done: false,
        })
        .collect();

    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format: rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
        method: rarkit::WriteMethod::Stored,
        solid,
        volume_file_size: Some(cap),
        volume_naming: naming,
        // The RAR 4 family writes no filter record (spec J, by design).
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..rarkit::WriteOptions::default()
    })?;
    for ((((name, _), reader), size), mtime) in
        members.iter().zip(&mut readers).zip(&sizes).zip(&times)
    {
        writer.add(rarkit::MemberSpec {
            name: name.as_bytes(),
            payload: rarkit::Payload::Reader {
                reader,
                size: *size,
                crc32: None,
            },
            mtime: *mtime,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })?;
    }

    let stem = archive.strip_suffix(".rar").unwrap_or(&archive).to_string();
    let mut out = Files {
        stem: stem.clone(),
        written: Vec::new(),
    };
    let report = writer.finish_volumes(&mut out)?;
    let total = out.written.len() as u32;
    for (index, working) in out.written.iter().enumerate() {
        let name = rarkit::volume_file_name(&stem, index as u32, total, naming);
        std::fs::rename(working, &name)?;
    }
    println!(
        "{} members, {} volumes, {} bytes, {} held, first {}",
        members.len(),
        report.volumes,
        report.bytes,
        report.held_volume_bytes,
        rarkit::volume_file_name(&stem, 0, total, naming)
    );
    Ok(())
}
