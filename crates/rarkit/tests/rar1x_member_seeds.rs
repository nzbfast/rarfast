//! The seed corpus of the fuzz target `fuzz:rar1x_member`, held to the
//! genuine archives it was cut from.
//!
//! A seed is one member of a RAR 1.40.2 archive of `fixtures/legacy` in
//! the target's own input shape: three bytes of little endian declared
//! size, a zero flags byte, and the member's packed bytes exactly as the
//! DOS writer left them. `fuzz/seeds/rar1x_member` holds them, because a
//! campaign's `corpus/` is not kept, and this test fails if a seed there
//! is not byte for byte what the fixture gives, if one is missing, or if
//! there is a file there that no fixture member accounts for.
//!
//! Regenerate with
//! `cargo test -p rarkit --test rar1x_member_seeds -- --ignored`, which
//! is `#[ignore]` because it writes into the source tree.
//!
//! One thread throughout. The largest thing held is one archive of under
//! 100 KiB and one seed of under 35 KiB; the decode at the end runs the
//! fuzz body, whose memory is the decoder's 64 KiB history and at most
//! 90,000 bytes of output.
#![cfg(feature = "bench-internals")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use rarkit::{Archive, BlockKind, Method, ReadOptions};

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// The archives the seeds come from, and which members of each: every
/// compressed member of the `-m5` archive, and the three text members of
/// the `-m1` one, whose packed bytes differ from their `-m5` forms.
const SOURCES: [(&str, Option<&[&str]>); 2] = [
    ("d140_m5", None),
    (
        "d140_m1",
        Some(&["SUB/NESTED/DEEP.TXT", "SUB/SIB.TXT", "HELLO.TXT"]),
    ),
];

/// Every seed as `(file name, bytes)`, or `None` when the fixture corpus
/// is not in this checkout.
fn seeds() -> Option<BTreeMap<String, Vec<u8>>> {
    let mut all = BTreeMap::new();
    for (id, only) in SOURCES {
        let path = root().join(format!("fixtures/legacy/archives/{id}.rar"));
        let bytes = std::fs::read(&path).ok()?;
        let archive = Archive::open_path(&path, &ReadOptions::default()).expect("opens");
        let files: Vec<_> = archive
            .blocks()
            .filter(|block| block.kind == BlockKind::File)
            .collect();
        assert_eq!(files.len(), archive.members().len(), "{id}");
        for (member, block) in archive.members().zip(files) {
            let name = member.name_lossy().into_owned();
            let wanted = only.is_none_or(|names| names.contains(&name.as_str()));
            let compressed = matches!(member.method, Method::Compressed { .. });
            if !wanted || !compressed || member.is_directory || member.packed_size == 0 {
                continue;
            }
            // A file block's extent is its header and then its data, so
            // the packed bytes are the last `packed_size` of it.
            let end = block.range.end as usize;
            let packed = &bytes[end - member.packed_size as usize..end];
            let declared = member.unpacked_size.expect("a RAR 1.4 header has one");
            assert!(declared < 1 << 20, "{id} {name}: past the target's 1 MiB");
            let mut seed = (declared as u32).to_le_bytes()[..3].to_vec();
            seed.push(0);
            seed.extend_from_slice(packed);
            let file = format!("{id}__{}", name.replace(['/', '.'], "_"));
            assert!(
                all.insert(file, seed).is_none(),
                "{id} {name}: a name twice"
            );
        }
    }
    Some(all)
}

fn seed_dir() -> PathBuf {
    root().join("fuzz/seeds/rar1x_member")
}

#[test]
fn the_committed_seeds_are_the_genuine_members_and_nothing_else() {
    let Some(seeds) = seeds() else {
        eprintln!("fixtures/legacy is not in this checkout: nothing compared");
        return;
    };
    assert_eq!(seeds.len(), 10, "{:?}", seeds.keys());
    let mut on_disk: Vec<String> = std::fs::read_dir(seed_dir())
        .expect("fuzz/seeds/rar1x_member is part of the checkout")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    on_disk.sort();
    assert_eq!(on_disk, seeds.keys().cloned().collect::<Vec<_>>());
    for (file, seed) in &seeds {
        let held = std::fs::read(seed_dir().join(file)).expect("a seed");
        assert!(held == *seed, "{file} is not what the fixture gives");
        // The target's own body, on the bytes the target would hand it:
        // a seed that the harness refuses or that panics is no seed.
        rarkit::internals::rar15::fuzz_decode(seed);
    }
}

#[test]
#[ignore = "writes fuzz/seeds/rar1x_member into the source tree"]
fn emit_seeds() {
    let seeds = seeds().expect("fixtures/legacy is in this checkout");
    std::fs::create_dir_all(seed_dir()).expect("the directory");
    for (file, seed) in &seeds {
        std::fs::write(seed_dir().join(file), seed).expect("written");
    }
}
