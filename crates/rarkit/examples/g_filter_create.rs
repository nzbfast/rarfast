//! Create one RAR 5 archive through the public API with the filter policy
//! spelled out, for spec G 3.8.2's size and wall counts
//! (the filter count script).
//!
//! The CLI's create takes `WriteOptions`' default policy and has no switch
//! for it, so this is how a run writes the same members with
//! `FilterPolicy::Detect` and with `Off` from one binary.
//!
//!     cargo run --release --example g_filter_create -- on 3 out.rar a.bin b.wav
//!     cargo run --release --example g_filter_create -- off 3 --solid out.rar dir/*
//!     cargo run --release --example g_filter_create -- on 3 --md 4194304 out.rar a.wav
//!
//! Members are read whole and named by their file name alone. It prints
//! nothing on success; time it from outside (`/usr/bin/time`), which is
//! what gives the CPU seconds and the peak RSS beside the wall.

use rarkit::{FilterPolicy, HostOs, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "usage: g_filter_create on|off LEVEL [--solid] [--md BYTES] OUT.rar FILE...";
    let filters = match args.next().as_deref() {
        Some("on") => FilterPolicy::Detect,
        Some("off") => FilterPolicy::Off,
        _ => panic!("{usage}"),
    };
    let level: u8 = args.next().and_then(|l| l.parse().ok()).expect(usage);
    let mut rest: Vec<String> = args.collect();
    let solid = rest.first().is_some_and(|a| a == "--solid");
    if solid {
        rest.remove(0);
    }
    // The dictionary, when a count wants one other than the level's
    // default (the filter layout work's `-md4m` rows).
    let dictionary = if rest.first().is_some_and(|a| a == "--md") {
        rest.remove(0);
        Some(rest.remove(0).parse::<u64>().expect(usage))
    } else {
        None
    };
    assert!(rest.len() >= 2, "{usage}");
    let out = rest.remove(0);
    let data: Vec<(String, Vec<u8>)> = rest
        .iter()
        .map(|path| {
            let name = std::path::Path::new(path)
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            (
                name,
                std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}")),
            )
        })
        .collect();
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed { level, dictionary },
        filters,
        solid,
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, bytes) in &data {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0o644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let file = std::fs::File::create(&out).unwrap_or_else(|e| panic!("{out}: {e}"));
    writer
        .finish_into(std::io::BufWriter::new(file))
        .expect("finish");
}
