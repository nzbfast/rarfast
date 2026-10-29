//! Fast level 1 through the public `Writer`: level 1 is the fast parse (hash
//! chains keyed on six bytes, one link, the four held distances first, a
//! static price, entropy blocks cut every 64 KiB), and
//! `WriteOptions::level1_priced` writes level 1 as it was before the
//! change, byte for byte. The option reaches level 1 only: levels 2 to 5
//! write what they wrote before the change whether it is set or not.
//!
//! **How "as it was" is held.** [`BEFORE_FAST_PARSE`] pins the SHA-256 of every
//! cell's archive as an earlier revision wrote it, the commit this
//! change was cut from (taken there by this file's own `write`, with
//! `LEVEL1_PARSE_PRINT_PINS=1`). The option's level 1 must match its pin,
//! and so must levels 2 to 5 with the option off and on, in both archive
//! formats, solid and not.
//!
//! Which parse a block took is pinned at the encoder (`encode::tests`);
//! what is pinned here is what reaches the writer, and that the fast parse
//! is the one a solid set, a member read a window at a time and a block
//! the incompressible sample sends to the floor scan all take.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, Payload, RangeSource,
    Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};
use std::io::Cursor;
use std::sync::Arc;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Fixed width records that differ from the one before in a byte or two:
/// the shape the held distances are for.
fn records(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut record = [0u8; 24];
    for byte in &mut record {
        *byte = xorshift(&mut state) as u8;
    }
    let mut out = Vec::with_capacity(len + record.len());
    while out.len() < len {
        let at = (xorshift(&mut state) % record.len() as u64) as usize;
        record[at] = xorshift(&mut state) as u8;
        out.extend_from_slice(&record);
    }
    out.truncate(len);
    out
}

/// Bytes with nothing in them to find.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| (xorshift(&mut state) >> 24) as u8)
        .collect()
}

/// The members every cell writes: one past a parse block whose middle the
/// incompressible sample sends to the floor, a small one, one of records,
/// two of one period, and three whose lengths leave four, five and six bytes after their last
/// six byte key.
fn members() -> Vec<Vec<u8>> {
    let mut mixed = rarkit_testdata::chatter(1, 420_000);
    mixed.extend_from_slice(&noise(600_000, 2));
    mixed.extend_from_slice(&rarkit_testdata::chatter(3, 380_000));
    vec![
        mixed,
        rarkit_testdata::chatter(4, 20_000),
        records(300_000, 5),
        // One distance held for the whole member: the held arm's longest
        // length, which the RAR 2.9 method caps a byte under the fresh
        // arm's.
        vec![0u8; 300_000],
        (0..300_000).map(|i| (i % 7) as u8 * 31).collect(),
        rarkit_testdata::chatter(6, 70_003),
        rarkit_testdata::chatter(6, 70_004),
        rarkit_testdata::chatter(6, 70_005),
    ]
}

#[derive(Clone, Copy)]
struct Cell {
    format: WriteFormat,
    level: u8,
    solid: bool,
    priced: bool,
    workers: Option<usize>,
}

impl Cell {
    fn name(self) -> String {
        let format = match self.format {
            WriteFormat::Rar5 => "rar5",
            WriteFormat::Rar4(_) => "rar4v29",
        };
        let solid = if self.solid { "s" } else { "" };
        format!("{format}-m{}{solid}", self.level)
    }

    fn options(self) -> WriteOptions {
        WriteOptions {
            format: self.format,
            method: WriteMethod::Compressed {
                level: self.level,
                dictionary: None,
            },
            solid: self.solid,
            // The RAR 4 family writes no filter record (SPEC-J).
            filters: match self.format {
                WriteFormat::Rar5 => FilterPolicy::Detect,
                WriteFormat::Rar4(_) => FilterPolicy::Off,
            },
            level1_priced: self.priced,
            // The solid default dictionary (10 Oct 2026) is not this file's
            // subject: its solid cells keep the 2 MiB their pins were taken
            // at. `solid_default_dictionary` holds the default.
            solid_dictionary_2mib: true,
            entropy: Entropy::Seeded([5; 32]),
            workers: self.workers,
            ..WriteOptions::default()
        }
    }
}

fn write(members: &[Vec<u8>], cell: Cell) -> Vec<u8> {
    let mut writer = Writer::new(cell.options()).expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.bin").into_bytes())
        .collect();
    for (bytes, name) in members.iter().zip(&names) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("write");
    out
}

/// One member through `Payload::Reader`, which takes the windowed walk.
fn write_windowed(data: &[u8], cell: Cell) -> Vec<u8> {
    let mut reader = Cursor::new(data);
    let mut writer = Writer::new(cell.options()).expect("options");
    writer
        .add(MemberSpec {
            name: b"m0.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size: data.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("write");
    out
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(what: &str, archive: &[u8], members: &[Vec<u8>]) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        sink.0 == members,
        "{what}: the archive reads back as its members"
    );
}

fn have_unrar() -> bool {
    std::process::Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|found| found.status.success())
        .unwrap_or(false)
}

/// Hand `archive` to reference `unrar t`. It reports a checksum error on
/// stderr and may still exit 0, so both are read.
fn unrar_admits(what: &str, archive: &[u8]) {
    let dir = std::env::temp_dir().join(format!("rarkit-level1-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::write(dir.join("test.rar"), archive).expect("the archive");
    let run = std::process::Command::new("unrar")
        .args(["t", "test.rar"])
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success() && stderr.trim().is_empty() && stdout.contains("All OK"),
        "{what}: unrar refused the archive\n{stdout}\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// SHA-256 of [`members`] written by [`write`] at an earlier revision,
/// the parent of the fast parse's change, at each level, in each format, solid
/// and not: what levels 2 to 5 must still write, and what
/// `level1_priced = true` must write at level 1.
///
/// The two SOLID level 4 cells (`rar5-m4s`, `rar4v29-m4s`) were re-taken on
/// 1 Oct 2026 at the land of level 4's solid two-slot plan (SPEC-H3 8.1), which moves
/// a solid level 4 member's bytes and nothing else here. All eight level
/// 4 and level 5 cells were re-taken again that day when level 4's
/// default plan went to the chains at 64 links and level 5's lazy tree
/// plan took the backward extension (SPEC-H3 8.1): the twelve
/// cells of levels 1 to 3 are as taken at that earlier revision.
///
/// The four level 5 rows were re-taken once more that day, by the same
/// print, at the land of LEVEL 5 BY CLASS (SPEC-H3 8.1): these
/// members read under the cut-off or are a solid run, so level 5 writes
/// them over the chains at 80 links, 72 in a solid run; the rows of levels
/// 2 to 4 were printed beside them and had not moved.
///
/// The two RAR 5 level 3 rows (`rar5-m3`, `rar5-m3s`) were re-taken by the
/// same print on 14 Oct 2026 at the thin scan (FROM-STUDIO 389 C), which
/// parses a block the sample reads thin at level 3 of RAR 5; every other
/// row printed the same. Both rows were taken again on 17 Oct 2026 where
/// the thin scan met the empty stride (FROM-STUDIO 514 D).
const BEFORE_FAST_PARSE: [(&str, &str); 20] = [
    (
        "rar5-m1",
        "0c0c0949ecbb646c28407cc4076f035ed0795fde60eed64b755e32437d12f07a",
    ),
    (
        "rar5-m2",
        "37c9a8153656393a773d1bf6fc160948d181b6522b4f3b40e88fcdfeed15a0c3",
    ),
    (
        "rar5-m3",
        "168f4f46d818ed0809bb7911bcceaf14189e311df0a890f5a2093e7081dbb40d",
    ),
    (
        "rar5-m4",
        "bafc27162583df80de522472e43ec911e109b8749fe2f4c05ae109e703a5c3ac",
    ),
    (
        "rar5-m5",
        "ebf48f4b3cfe361317e418ffe7604eda0b7159c1975eee30b9adbfa40b586c35",
    ),
    (
        "rar5-m1s",
        "ad04a1b043e12637378ece0b322f147cae66056e97b51211aaed14c01336106d",
    ),
    (
        "rar5-m2s",
        "fbaf7183ebeb946cd8f71aaad7b2f833ef5c7a5e8075d4a3d8b63a64392eac77",
    ),
    (
        "rar5-m3s",
        "c1fbaef39765319b1b8194134f8ad81699f7ded99462f15fa39cce28f1f1be13",
    ),
    (
        "rar5-m4s",
        "b3acf1632690bd230d712db828d7441b3d694cccd67a6d6303ad6992c081e3c7",
    ),
    (
        "rar5-m5s",
        "ebc2a09e169fa90f27f4bbee04d47b66af59c008b9bee067cfbf3d0aad7d0890",
    ),
    (
        "rar4v29-m1",
        "f72fb59fd90e0e51a66ba56847557cc6b7818908f8a8daea7031c4e9a94ee9bf",
    ),
    (
        "rar4v29-m2",
        "3edd6e07bdceaf91cea1268487fe3a5d1ce9fe4049703229e227fdb647397245",
    ),
    (
        "rar4v29-m3",
        "c8753644332e969352d73a7680b260eb7b67833c346b86f7ef82526adab6bddd",
    ),
    (
        "rar4v29-m4",
        "7b0550798710e434ac166f974bd86a5ca0260c49e3be75a7e79cd9fcb693a427",
    ),
    (
        "rar4v29-m5",
        "f2b1c2456f42e7b0960fd771cf974d11108bb540cec03bf8e21aa120c69eb5a0",
    ),
    (
        "rar4v29-m1s",
        "c91d17b9165e2273cdedc42bca5191db01571ff126bd40ab070ec105eeebf6c1",
    ),
    (
        "rar4v29-m2s",
        "98b399c2415f3a2ac0f0a87303a33f22a01e638e943317a334b5ef49a313f375",
    ),
    (
        "rar4v29-m3s",
        "38b740181687a979d71dba6046ae4fc327054883e86304f4fc2651bf85264b2c",
    ),
    (
        "rar4v29-m4s",
        "10f30692910ef5045b280e66d27ffdff334e49e114246353983f333649c525a2",
    ),
    (
        "rar4v29-m5s",
        "d3cc5fe1c2baf67c874a19f4b5926310bfc0fce8350cb5b4b0ecbb86fa66514f",
    ),
];

const FORMATS: [WriteFormat; 2] = [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)];

#[test]
fn the_option_writes_level_1_as_it_was_and_levels_2_to_5_do_not_move() {
    assert!(!WriteOptions::default().level1_priced);
    let members = members();
    let print = std::env::var_os("LEVEL1_PARSE_PRINT_PINS").is_some();
    let unrar = have_unrar();
    if !unrar {
        eprintln!("reference unrar is not on PATH: no archive here is admitted by it");
    }
    for format in FORMATS {
        let mut sizes = Vec::new();
        for solid in [false, true] {
            for level in 1u8..=5 {
                let cell = Cell {
                    format,
                    level,
                    solid,
                    priced: false,
                    workers: Some(4),
                };
                let what = cell.name();
                let fast = write(&members, cell);
                let priced = write(
                    &members,
                    Cell {
                        priced: true,
                        ..cell
                    },
                );
                if print {
                    // Printing the pins, not judging them: run at the
                    // parent, where the option does not exist, with the
                    // option's line taken out of `Cell::options`.
                    eprintln!("PIN (\"{what}\", \"{}\"),", sha256_hex(&fast));
                    continue;
                }
                let pinned = BEFORE_FAST_PARSE
                    .iter()
                    .find(|(name, _)| *name == what)
                    .map(|(_, sha)| *sha)
                    .expect("a pinned digest");
                assert_eq!(
                    sha256_hex(&priced),
                    pinned,
                    "{what}: with the option, not the archive of before the fast parse"
                );
                reads_back(&what, &fast, &members);
                if level == 1 {
                    assert!(
                        fast != priced,
                        "{what}: the option moved no byte, so the fast parse never ran"
                    );
                    reads_back(&what, &priced, &members);
                    if unrar {
                        unrar_admits(&what, &fast);
                    }
                } else {
                    assert!(
                        fast == priced,
                        "{what}: the option moved a byte outside level 1"
                    );
                }
                if !solid {
                    sizes.push(fast.len());
                }
            }
        }
        if !print {
            assert!(
                sizes.windows(2).all(|pair| pair[0] >= pair[1]),
                "{format:?}: a higher level must not compress worse: {sizes:?}"
            );
        }
    }
}

#[test]
fn the_fast_level_1_writes_the_same_bytes_at_any_width() {
    // API promise 2.6: the parse is a function of a block's bytes and of
    // the links, and the blind cut of the tokens alone.
    let members = members();
    for format in FORMATS {
        for solid in [false, true] {
            let cell = Cell {
                format,
                level: 1,
                solid,
                priced: false,
                workers: Some(1),
            };
            let one = write(&members, cell);
            for workers in [Some(2), Some(7), None] {
                assert!(
                    write(&members, Cell { workers, ..cell }) == one,
                    "{}: workers {workers:?} wrote different bytes from one",
                    cell.name()
                );
            }
        }
    }
}

#[test]
fn a_windowed_member_takes_the_fast_parse_and_reads_back() {
    // A member from a reader is encoded a window of the dictionary at a
    // time over a carried index (spec G 3.7.3): the same plan, so the same
    // parse, and the option reaches it the same way.
    let mut data = rarkit_testdata::chatter(11, 3_000_000);
    data.extend_from_slice(&records(1_500_000, 12));
    data.extend_from_slice(&noise(700_000, 13));
    data.extend_from_slice(&rarkit_testdata::chatter(14, 900_001));
    for format in FORMATS {
        let cell = Cell {
            format,
            level: 1,
            solid: false,
            priced: false,
            workers: Some(4),
        };
        let what = format!("{} windowed", cell.name());
        let fast = write_windowed(&data, cell);
        let priced = write_windowed(
            &data,
            Cell {
                priced: true,
                ..cell
            },
        );
        assert!(fast != priced, "{what}: the option moved no byte");
        assert!(
            write_windowed(
                &data,
                Cell {
                    workers: Some(1),
                    ..cell
                }
            ) == fast,
            "{what}: one worker wrote different bytes from four"
        );
        reads_back(&what, &fast, std::slice::from_ref(&data));
        reads_back(&what, &priced, std::slice::from_ref(&data));
        if have_unrar() {
            unrar_admits(&what, &fast);
        }
    }
}
