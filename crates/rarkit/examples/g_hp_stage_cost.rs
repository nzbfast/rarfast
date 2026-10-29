//! What each stage of an `-hp` STORED member costs on its own, one thread,
//! in the 2 MiB chunks the writer's read-ahead moves: the AES-256-CBC encrypt,
//! a copy, the CRC32 and BLAKE2sp of the plaintext, and a file's write and
//! read through the page cache. Each is timed over the same bytes, best of
//! three, and printed in GB/s.
//!
//!     cargo run --release --example g_hp_stage_cost -- <scratch dir> [MiB]

use std::io::{Read, Write};
use std::time::Instant;

const CHUNK: usize = 2 << 20;

fn best_of(label: &str, bytes: usize, mut run: impl FnMut()) {
    let mut best = f64::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        run();
        best = best.min(start.elapsed().as_secs_f64());
    }
    println!(
        "{label:<22} {:>7.3} s  {:>6.2} GB/s",
        best,
        bytes as f64 / best / 1e9
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("a scratch directory"));
    let mib: usize = args.next().map_or(1024, |text| text.parse().expect("MiB"));
    let len = mib << 20;

    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let plain: Vec<u8> = (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as u8
        })
        .collect();
    let mut out = vec![0u8; CHUNK];

    let keys =
        rarkit::internals::crypto::Rar5Keys::derive(b"stage", &[7; 16], 15, None).expect("the key");
    best_of("aes256-cbc encrypt", len, || {
        let mut cipher = rarkit::internals::crypto::Aes256Enc::new(&keys, &[9; 16]);
        for chunk in plain.chunks(CHUNK) {
            cipher
                .encrypt_from(chunk, &mut out[..chunk.len()])
                .expect("encrypt");
        }
    });
    best_of("copy", len, || {
        for chunk in plain.chunks(CHUNK) {
            out[..chunk.len()].copy_from_slice(chunk);
        }
        std::hint::black_box(&out);
    });
    best_of("crc32", len, || {
        std::hint::black_box(rarkit::checksum::crc32(&plain));
    });
    best_of("blake2sp one thread", len, || {
        std::hint::black_box(rarkit::internals::recovery::blake2sp(&plain));
    });

    let path = dir.join("g_hp_stage_cost.bin");
    best_of("file write", len, || {
        let mut file = std::fs::File::create(&path).expect("create");
        for chunk in plain.chunks(CHUNK) {
            file.write_all(chunk).expect("write");
        }
    });
    best_of("file read", len, || {
        let mut file = std::fs::File::open(&path).expect("open");
        loop {
            let read = file.read(&mut out).expect("read");
            if read == 0 {
                break;
            }
        }
    });
    let _ = std::fs::remove_file(&path);
}
