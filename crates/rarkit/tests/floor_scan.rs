//! The floor scan: how a parse block the incompressible sample calls empty
//! is parsed at levels 1 and 2 (`encode::lz::floor_scan`).
//!
//! A block with nothing in it to find is written as literals, except where
//! the finder, asked at every sixteenth position, answers with a match of
//! 32 bytes or more, which is extended back and taken. Level 3 scans too
//! by default, and level 4 since its default plan went to the chains
//! (1 Oct 2026); level 5, and level 4 under its tree options, keep the
//! lazy floor. What this file holds to account, at every
//! level so that both floors are covered:
//!
//! - the streams are admitted: rarkit's own decoders and reference
//!   `unrar` give the input back, RAR 5 and the RAR 2.9 method alike;
//! - the long duplicate the scan is FOR is still found inside bytes the
//!   sample calls empty, which a literals-only floor, the first form
//!   counted, did not do;
//! - neither floor moves a byte with the thread count (API promise 6).

mod support {
    pub mod rar4build;
    pub mod rar5build;
}

use rarkit::internals::rar20;
use std::io::Write;
use std::process::Command;

/// 1 MiB: RAR 5's exponent 3 over 128 KiB, and RAR 4's dictionary bits 4.
const DICTIONARY: u32 = 1 << 20;
const RAR5_EXPONENT: u8 = 3;
const RAR4_DICTIONARY_BITS: u8 = 4;

/// Where the duplicate is copied from and to, and how long it is: far
/// enough apart that no parse block holds both ends, near enough that the
/// dictionary reaches.
const COPY_FROM: usize = 200 << 10;
const COPY_TO: usize = 900 << 10;
const COPY_BYTES: usize = 96 << 10;

/// xorshift64* output: bytes every sampled block of which reads as empty.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// 1.5 MiB of noise holding one 96 KiB duplicate of its own earlier bytes,
/// at an offset that is not a multiple of the scan's stride, so that the
/// match is found at an asked position inside it and extended back.
fn noise_with_a_duplicate() -> Vec<u8> {
    let mut data = noise(1536 << 10, 0x2026_0930);
    let at = COPY_TO + 7;
    let copy = data[COPY_FROM..COPY_FROM + COPY_BYTES].to_vec();
    data[at..at + COPY_BYTES].copy_from_slice(&copy);
    data
}

fn have_unrar() -> bool {
    Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|found| found.status.success())
        .unwrap_or(false)
}

/// Hand `bytes`, an archive holding `MEMBER.BIN`, to reference `unrar` and
/// compare what comes out with `input`.
fn unrar_gives_back(what: &str, bytes: &[u8], input: &[u8]) {
    let dir = std::env::temp_dir().join(format!("rarkit-floor-scan-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::File::create(dir.join("test.rar"))
        .expect("the archive")
        .write_all(bytes)
        .expect("written");
    let run = Command::new("unrar")
        .args(["x", "-y", "test.rar"])
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    // unrar reports a checksum error on stderr and may still exit 0, so
    // both streams are read, and the bytes are compared either way.
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && !stderr.to_lowercase().contains("error"),
        "{what}: unrar refused the archive\n{}\n{stderr}",
        String::from_utf8_lossy(&run.stdout)
    );
    let out = std::fs::read(dir.join("MEMBER.BIN")).expect("the extracted member");
    assert!(out == input, "{what}: unrar gave back different bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_rar5_scan_is_admitted_and_keeps_the_long_duplicate() {
    use rarkit::internals::rar5;
    let input = noise_with_a_duplicate();
    for level in 1u8..=5 {
        let packed = rar20::rar5_encode(&input, level, DICTIONARY);
        for parallel in [false, true] {
            let out = rar5::decode_member(
                &packed,
                input.len() as u64,
                u64::from(DICTIONARY),
                0,
                parallel,
            )
            .unwrap_or_else(|e| panic!("level {level} parallel {parallel}: {e}"));
            assert!(
                out == input,
                "level {level} parallel {parallel}: wrong bytes"
            );
        }
        // Noise packs to about its own size or a little over, so a stream
        // that did not take the duplicate could not come out even half of
        // it under the input's length.
        assert!(
            packed.len() + COPY_BYTES / 2 < input.len(),
            "level {level}: {} packed bytes from {}, so the {COPY_BYTES} byte \
             duplicate was not taken",
            packed.len(),
            input.len()
        );
        if have_unrar() {
            let bytes = support::rar5build::archive(&[support::rar5build::Member {
                name: "MEMBER.BIN",
                unpacked: &input,
                packed: &packed,
                dictionary_exponent: RAR5_EXPONENT,
                method: level,
                solid: false,
            }]);
            unrar_gives_back(&format!("rar5-m{level}"), &bytes, &input);
        } else {
            eprintln!("reference unrar is not on PATH: RAR 5 level {level} not admitted");
        }
    }
}

#[test]
fn the_rar29_scan_is_admitted_and_keeps_the_long_duplicate() {
    use rarkit::internals::rar3_lz::{decode_stream, MemberIn};
    let input = noise_with_a_duplicate();
    for level in 1u8..=5 {
        let packed = rar20::rar29_encode(&input, level, DICTIONARY);
        let members = [MemberIn {
            packed: 0..packed.len(),
            unpacked: input.len() as u64,
        }];
        let (out, _) = decode_stream(&packed, &members, DICTIONARY, true)
            .unwrap_or_else(|e| panic!("level {level}: {e}"));
        assert!(out[0].data == input, "level {level}: wrong bytes");
        assert!(
            packed.len() + COPY_BYTES / 2 < input.len(),
            "level {level}: {} packed bytes from {}, so the duplicate was not taken",
            packed.len(),
            input.len()
        );
        if have_unrar() {
            let bytes = support::rar4build::archive(&[support::rar4build::Member {
                name: "MEMBER.BIN",
                unpacked: &input,
                packed: &packed,
                version: 29,
                method: 0x30 + level,
                dictionary_bits: RAR4_DICTIONARY_BITS,
                solid: false,
            }]);
            unrar_gives_back(&format!("rar29-m{level}"), &bytes, &input);
        } else {
            eprintln!("reference unrar is not on PATH: RAR 2.9 level {level} not admitted");
        }
    }
}

#[test]
fn the_scan_moves_no_byte_with_the_thread_count() {
    let input = noise_with_a_duplicate();
    for level in [1u8, 3, 5] {
        let first = rar20::on_threads(1, || rar20::rar5_encode(&input, level, DICTIONARY));
        let old = rar20::on_threads(1, || rar20::rar29_encode(&input, level, DICTIONARY));
        for threads in [2usize, 6] {
            let again =
                rar20::on_threads(threads, || rar20::rar5_encode(&input, level, DICTIONARY));
            assert!(
                again == first,
                "RAR 5 level {level}: {threads} threads moved a byte"
            );
            let again =
                rar20::on_threads(threads, || rar20::rar29_encode(&input, level, DICTIONARY));
            assert!(
                again == old,
                "RAR 2.9 level {level}: {threads} threads moved a byte"
            );
        }
    }
}

// ---- the spec's member, through the writer ----------------------------------

/// SPEC-G 3.8.3's acceptance member for the floor scan: a NON-SOLID member
/// of 524,288 bytes of noise holding a 96 KiB copy of its own earlier
/// bytes. At that size 3.8.3's store rule does not sample it (under 1 MiB)
/// and it is not a lone member (over 262,144 bytes), so both of its parse
/// blocks reach the encoder's own incompressible sample, which reads noise
/// as empty; the copy sits wholly in the second block, 284 KiB after its
/// source in the first.
fn the_specs_member() -> Vec<u8> {
    let mut data = noise(524_288, 0x0930_2026);
    let (from, to) = (16 << 10, (300 << 10) + 7);
    let copy = data[from..from + COPY_BYTES].to_vec();
    data[to..to + COPY_BYTES].copy_from_slice(&copy);
    data
}

/// Collects every member's bytes, failing on a checksum that does not hold.
#[derive(Default)]
struct Collect {
    got: Vec<Vec<u8>>,
}

impl rarkit::Sink for Collect {
    type Out = Vec<u8>;
    fn open(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<Self::Out>> {
        Ok(rarkit::Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_ne!(outcome.checksum_ok, Some(false), "a checksum failed");
        self.got.push(out.unwrap_or_default());
        Ok(())
    }
}

/// Write `input` as the one member of an archive of `format` at `level`,
/// at encoder width `workers`, with the level 3 floor option as given.
fn write_member(
    input: &[u8],
    format: rarkit::WriteFormat,
    level: u8,
    workers: Option<usize>,
    level3_floor_lazy: bool,
) -> Vec<u8> {
    write_with(input, format, level, workers, |options| {
        options.level3_floor_lazy = level3_floor_lazy;
    })
}

/// [`write_member`] with any of the writer's options set by `tune`.
fn write_with(
    input: &[u8],
    format: rarkit::WriteFormat,
    level: u8,
    workers: Option<usize>,
    tune: impl FnOnce(&mut rarkit::WriteOptions),
) -> Vec<u8> {
    use rarkit::{
        FilterPolicy, MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer,
    };
    let mut options = WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        filters: match format {
            WriteFormat::Rar5 => FilterPolicy::Detect,
            WriteFormat::Rar4(_) => FilterPolicy::Off,
        },
        workers,
        ..WriteOptions::default()
    };
    tune(&mut options);
    let mut writer = Writer::new(options).expect("representable options");
    writer
        .add(MemberSpec {
            name: b"MEMBER.BIN",
            payload: Payload::Bytes(input),
            mtime: None,
            // Readable once unrar has extracted it (a Unix mode).
            attributes: 0o100_644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).expect("finish");
    bytes
}

/// A name for one format and level, fit for a directory.
fn cell(format: rarkit::WriteFormat, level: u8) -> String {
    format!("{format:?}-m{level}")
        .replace(['(', ')'], "")
        .to_lowercase()
}

#[test]
fn the_specs_member_is_written_admitted_and_keeps_its_duplicate() {
    use rarkit::{Rar4Version, ReadOptions, WriteFormat};
    let input = the_specs_member();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        for level in 1u8..=5 {
            let what = cell(format, level);
            let bytes = write_member(&input, format, level, Some(1), false);
            // The same bytes at any width (API promise 2.6), the spec's
            // second acceptance test.
            for workers in [Some(4), None] {
                assert!(
                    write_member(&input, format, level, workers, false) == bytes,
                    "{what}: workers {workers:?} wrote different bytes from one"
                );
            }

            // Headers are a few dozen bytes, so an archive that did not take
            // the copy could not come out even half of it under the input.
            assert!(
                bytes.len() + COPY_BYTES / 2 < input.len(),
                "{what}: a {} byte archive from {} bytes, so the copy was not taken",
                bytes.len(),
                input.len()
            );
            let mut sink = Collect::default();
            let sources =
                vec![std::sync::Arc::new(bytes.clone()) as std::sync::Arc<dyn rarkit::RangeSource>];
            rarkit::extract(sources, &ReadOptions::default(), &mut sink, &mut ())
                .unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(
                sink.got == [input.clone()],
                "{what}: rarkit gave back different bytes"
            );
            if have_unrar() {
                unrar_gives_back(&format!("writer-{what}"), &bytes, &input);
            } else {
                eprintln!("reference unrar is not on PATH: {what} not admitted");
            }
        }
    }
}

/// SHA-256 of the spec's member written at LEVEL 3 before its floor scan (an
/// earlier revision, level 3 on the floor's lazy parse), RAR 5 and the RAR
/// 2.9 method: what `level3_floor_lazy = true` must write byte for byte.
/// Taken from the bench build's `RARKIT_FLOOR_PARSE=lazy` arm, which the
/// store-decision work held byte identical to main in six cells
/// (30 Sep 2026).
const LEVEL3_BEFORE_SCAN: [(&str, &str); 2] = [
    (
        "rar5-m3",
        "2c7e0e0bb791dbf37d990698870d30d65b686219560d0128bab4f712d8808389",
    ),
    (
        "rar4v29-m3",
        "ed5d51bdc71a2f3991ffdaf3bc3ae2d9dde97eee4a58a172362aa5348b5f3ffe",
    ),
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn the_option_restores_level_3_and_moves_no_other_level() {
    // Spec G 3.8.3's third acceptance test: at level 3 the
    // floored block of the spec's member is written by the scan, so the
    // archive differs from the one `level3_floor_lazy = true` writes, and
    // that one is level 3's archive before the scan; at levels 1, 2, 4
    // and 5 the option moves no byte.
    use rarkit::{Rar4Version, WriteFormat};
    let input = the_specs_member();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        for level in 1u8..=5 {
            let what = cell(format, level);
            let scan = write_member(&input, format, level, None, false);
            let lazy = write_member(&input, format, level, None, true);
            if level == 3 && std::env::var_os("FLOOR_SCAN_PRINT_PINS").is_some() {
                eprintln!(
                    "PIN {what} option-off {} option-on {}",
                    sha256_hex(&scan),
                    sha256_hex(&lazy)
                );
                // Printing the pins, not judging them: a bench build's
                // RARKIT_FLOOR_PARSE=lazy arm writes level 3 lazily with the
                // option off too, which is how the pins are cross-checked.
                continue;
            }
            if level == 3 {
                assert!(
                    scan != lazy,
                    "{what}: the option moved no byte, so the scan never ran"
                );
                let pinned = LEVEL3_BEFORE_SCAN
                    .iter()
                    .find(|(name, _)| *name == what)
                    .map(|(_, sha)| *sha)
                    .expect("a pinned digest");
                assert_eq!(
                    sha256_hex(&lazy),
                    pinned,
                    "{what}: the option does not write level 3's archive from before the floor scan"
                );
            } else {
                assert!(
                    scan == lazy,
                    "{what}: the option moved a byte outside level 3"
                );
            }
        }
    }
}

#[test]
fn level_4_scans_an_empty_block_by_default_and_its_tree_keeps_the_lazy_floor() {
    // SPEC-H3 8.1 acceptance test 11 and spec G 3.8.3's fourth, THE FLOOR
    // AT LEVEL 4: since level 4's default plan went to level 3's chains (1
    // Oct 2026) the floored blocks of the spec's member are written by the
    // floor SCAN, exactly as level 3 writes them, so the archive is as long
    // as the one level 3 writes under `level3_deep` (the same plan, the
    // same scan) and not as long as that plan's lazy floor writes;
    // `level4_tree` and `level4_optimal` keep the lazy floor over the tree,
    // and their archives differ from the default's; `level3_floor_lazy`
    // moves no level 4 byte under any of the three.
    use rarkit::{Rar4Version, ReadOptions, WriteFormat};
    let input = the_specs_member();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        let what = cell(format, 4);
        let level4 = |tree: bool, optimal: bool, floor_lazy: bool| {
            write_with(&input, format, 4, None, |options| {
                options.level4_tree = tree;
                options.level4_optimal = optimal;
                options.level3_floor_lazy = floor_lazy;
            })
        };
        let level3_deep = |floor_lazy: bool| {
            write_with(&input, format, 3, None, |options| {
                options.level3_deep = true;
                options.level3_floor_lazy = floor_lazy;
            })
        };
        let scan = level4(false, false, false);
        assert_eq!(
            scan.len(),
            level3_deep(false).len(),
            "{what}: default level 4 is level 3's plan at 64 links, floor scan and all"
        );
        assert_ne!(
            scan.len(),
            level3_deep(true).len(),
            "{what}: the lazy floor writes this member differently, so the scan ran"
        );
        let tree = level4(true, false, false);
        let optimal = level4(false, true, false);
        assert!(scan != tree, "{what}: the tree option keeps the lazy floor");
        assert!(scan != optimal, "{what}: the optimal option too");
        assert!(
            level4(true, true, false) == optimal,
            "{what}: with both options on, the optimal one wins"
        );
        for (name, tree_on, optimal_on, default) in [
            ("default", false, false, &scan),
            ("level4_tree", true, false, &tree),
            ("level4_optimal", false, true, &optimal),
        ] {
            assert!(
                level4(tree_on, optimal_on, true) == *default,
                "{what}, {name}: level3_floor_lazy moved a level 4 byte"
            );
            let mut sink = Collect::default();
            let sources = vec![
                std::sync::Arc::new(default.clone()) as std::sync::Arc<dyn rarkit::RangeSource>
            ];
            rarkit::extract(sources, &ReadOptions::default(), &mut sink, &mut ())
                .unwrap_or_else(|e| panic!("{what}, {name}: {e}"));
            assert!(
                sink.got == [input.clone()],
                "{what}, {name}: rarkit gave back different bytes"
            );
            if have_unrar() {
                unrar_gives_back(&format!("level4-{name}-{what}"), default, &input);
            }
        }
    }
}
