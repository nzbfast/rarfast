//! Store one file into one archive, file to file, for the peak RSS figure
//! of spec G 7.2.
//!
//! The two-arm harness measures the writer with its input already in
//! memory and its output thrown away, which is the right shape for a
//! ratio and the wrong one for a comparison with the reference `rar`
//! binary, whose figure includes reading a file and writing one. This
//! example does exactly what `rar a -m0 <archive> <file>` does, so that
//! `/usr/bin/time -l` can be pointed at both and the numbers put beside
//! each other.
//!
//! It states the payload's CRC32 up front, through `checksum::crc32_file`,
//! which is what the API documents as the single-pass shape: the header is
//! complete before the copy starts, so nothing is back-patched and nothing
//! is held. Leaving it out would make the writer hold the archive from the
//! placeholder onwards, because `finish_into` takes a `Write` and a `Write`
//! cannot seek. An entry point that takes `Write + Seek` and patches in
//! place is the obvious answer and is not written yet.
//!
//! `cargo run --release -p rarkit --example store_file -- <archive> <file> [rar4] [-mN]`

use std::fs::File;
use std::io::BufWriter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let archive = args.next().ok_or("usage: store_file <archive> <file>")?;
    let path = args.next().ok_or("usage: store_file <archive> <file>")?;
    let rest: Vec<String> = args.collect();
    let rar4 = rest.iter().any(|flag| flag == "rar4");
    let level = rest
        .iter()
        .find_map(|flag| flag.strip_prefix("-m"))
        .and_then(|n| n.parse::<u8>().ok())
        .unwrap_or(0);

    let (size, crc32) = rarkit::checksum::crc32_file(std::path::Path::new(&path))?;
    let held;
    let mut input = File::open(&path)?;
    let name = std::path::Path::new(&path)
        .file_name()
        .ok_or("the input has no file name")?
        .to_string_lossy()
        .into_owned();

    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format: if rar4 {
            rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40)
        } else {
            rarkit::WriteFormat::Rar5
        },
        method: if level == 0 {
            rarkit::WriteMethod::Stored
        } else {
            rarkit::WriteMethod::Compressed {
                level,
                dictionary: None,
            }
        },
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..rarkit::WriteOptions::default()
    })?;
    // A compressed member goes in as a slice, because spec H3's encoder
    // entry takes a member's whole input; a stored one streams.
    let payload = if level == 0 {
        rarkit::Payload::Reader {
            reader: &mut input,
            size,
            crc32: Some(crc32),
        }
    } else {
        held = std::fs::read(&path)?;
        rarkit::Payload::Bytes(&held)
    };
    writer.add(rarkit::MemberSpec {
        name: name.as_bytes(),
        payload,
        mtime: None,
        attributes: 0o100644,
        host_os: rarkit::HostOs::Unix,
        is_directory: false,
    })?;
    let report = writer.finish_into(BufWriter::new(File::create(&archive)?))?;
    println!("{} bytes, {} held", report.bytes, report.held_volume_bytes);
    Ok(())
}
