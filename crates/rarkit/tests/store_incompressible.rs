//! Spec G 3.8.3: a member that will not compress is written STORED, on the
//! evidence of samples taken before it is compressed.
//!
//! The rule was counted and set on 28 Sep 2026 and
//! `src/write/store.rs` carries it: a compressed, non-solid member of at
//! least 1 MiB; 16 samples of 64 KiB, each centred in one of 16 equal
//! segments of the whole member (bytes in memory) or of its first 32 MiB (a
//! reader, held until the decision); packed at the floor effort; stored
//! when at least 12 of the 16 pack to 99.5 percent of their bytes or more
//! for a member of 128 MiB and more (four may compress: decided
//! 1 Oct 2026, from a 12.9 GB member whose
//! opening packs), and at least 15 for a smaller member and under
//! `WriteOptions::store_one_miss`, which is the rule as it was set on 28
//! Sep (the size gate is of the same day, from these
//! counts: on bin4g eight members under 5 MiB, and on real asset
//! catalogues six of 37 to 60 MiB, that pack to 45 to 80 percent whole
//! were stored on samples that cannot see long range).
//!
//! Each row below is one clause of that rule, and the last pins the one
//! failure it is known to have, so that it stays a known property.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.

use std::io::Read;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, Method, Payload, RangeSource, ReadOptions,
    Result, Sink, VolumeOut, WriteFormat, WriteMethod, WriteOptions, WriteReport, Writer,
};

/// One member as read back: its name, its method and its bytes.
struct Read1 {
    name: Vec<u8>,
    method: Method,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Collect {
    members: Vec<Read1>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push(Read1 {
            name: member.name.to_vec(),
            method: member.method,
            bytes: Vec::new(),
        });
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.bytes = bytes;
        }
        Ok(())
    }
}

fn read_back(volumes: &[Vec<u8>]) -> Vec<Read1> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

/// A volume output that can patch, which is the one the CLI hands over.
#[derive(Default)]
struct Volumes {
    kept: Vec<Vec<u8>>,
}

impl VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> Result<()> {
        self.kept.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// Bytes with no structure: an xorshift stream, which packs to a little
/// MORE than itself at any level.
struct Keystream(u64);

impl Keystream {
    fn new(seed: u64) -> Keystream {
        Keystream(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1)
    }

    fn take(seed: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        Keystream::new(seed).fill(&mut out);
        out
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = (self.0 >> 24) as u8;
        }
    }
}

/// A reader over bytes held elsewhere, so that the writer sees a READER
/// and not a slice.
struct Over<'a>(&'a [u8]);

impl Read for Over<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// A reader that makes its keystream up as it is read, `left` bytes of
/// it, so that a member far larger than the test wants to hold can be
/// written.
struct Streamed {
    keys: Keystream,
    left: u64,
}

impl Read for Streamed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        self.keys.fill(&mut buf[..n]);
        self.left -= n as u64;
        Ok(n)
    }
}

fn options(format: WriteFormat, solid: bool, volume: Option<u64>) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid,
        volume_size: volume,
        filters: rarkit::FilterPolicy::Off,
        ..WriteOptions::default()
    }
}

/// Write `members` (name, bytes, whether to hand them over as a reader).
fn write(options: WriteOptions, members: &[(&[u8], &[u8], bool)]) -> (Vec<Vec<u8>>, WriteReport) {
    let volume = options.volume_size.is_some();
    let mut readers: Vec<Over<'_>> = members.iter().map(|m| Over(m.1)).collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, bytes, as_reader), reader) in members.iter().zip(readers.iter_mut()) {
        let payload = if *as_reader {
            Payload::Reader {
                reader,
                size: <[u8]>::len(bytes) as u64,
                crc32: None,
            }
        } else {
            Payload::Bytes(bytes)
        };
        writer
            .add(MemberSpec {
                name,
                payload,
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    if volume {
        let mut out = Volumes::default();
        let report = writer.finish_volumes(&mut out).expect("finish");
        (out.kept, report)
    } else {
        // One archive over an output that can seek, which is the CLI's.
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek(&mut out).expect("finish");
        (vec![out.into_inner()], report)
    }
}

/// `options` under `WriteOptions::store_one_miss`: the rule before 1 Oct
/// 2026, one sample of the sixteen allowed to compress.
fn one_miss(options: WriteOptions) -> WriteOptions {
    WriteOptions {
        store_one_miss: true,
        ..options
    }
}

fn stored(member: &Read1) -> bool {
    matches!(member.method, Method::Stored)
}

const FORMATS: [WriteFormat; 2] = [
    WriteFormat::Rar5,
    WriteFormat::Rar4(rarkit::Rar4Version::V29),
];

/// The rule's two outcomes, for both families and both payload shapes: an
/// incompressible member of 2 MiB is stored and a text one is compressed,
/// and each reads back to its own bytes.
#[test]
fn incompressible_members_are_stored_and_text_is_compressed() {
    let noise = Keystream::take(1, 2 << 20);
    let words = rarkit_testdata::chatter(2, 2 << 20);
    for format in FORMATS {
        for as_reader in [false, true] {
            let (volumes, _) = write(
                options(format, false, None),
                &[
                    (b"noise.bin", &noise, as_reader),
                    (b"words.txt", &words, as_reader),
                ],
            );
            let back = read_back(&volumes);
            assert_eq!(back.len(), 2);
            assert!(
                stored(&back[0]),
                "{format:?} reader={as_reader}: noise was compressed"
            );
            assert!(
                !stored(&back[1]),
                "{format:?} reader={as_reader}: text was stored"
            );
            assert_eq!(back[0].bytes, noise);
            assert_eq!(back[1].bytes, words);
            assert_eq!(back[0].name, b"noise.bin");
        }
    }
}

/// A stored member costs its own bytes and nothing more, where the level 3
/// encode of the same bytes costs more than they do.
#[test]
fn a_stored_member_is_smaller_than_the_encode_it_replaces() {
    let noise = Keystream::take(3, 2 << 20);
    let (volumes, _) = write(
        options(WriteFormat::Rar5, false, None),
        &[(b"n", &noise, false)],
    );
    let archive: usize = volumes.iter().map(Vec::len).sum();
    assert!(
        archive < noise.len() + 200,
        "{archive} bytes for a {} byte member",
        noise.len()
    );
}

/// Below 1 MiB, and in a SOLID run with `solid_store` off, the rule takes
/// no samples at all, so the member is compressed as it was before the
/// rule. (`tests/solid_store.rs` holds the rule inside a solid set.)
#[test]
fn small_and_solid_members_are_not_sampled() {
    let small = Keystream::take(4, (1 << 20) - 1);
    let (volumes, _) = write(
        options(WriteFormat::Rar5, false, None),
        &[(b"s", &small, false)],
    );
    assert!(
        !stored(&read_back(&volumes)[0]),
        "a member under 1 MiB was stored"
    );

    let big = Keystream::take(5, 2 << 20);
    let (volumes, _) = write(
        WriteOptions {
            solid_store: false,
            ..options(WriteFormat::Rar5, true, None)
        },
        &[(b"b", &big, false)],
    );
    let back = read_back(&volumes);
    assert!(!stored(&back[0]), "a solid member was stored");
    assert_eq!(back[0].bytes, big);
}

/// A big member's compressible opening is outvoted: in a member of 128 MiB
/// and more four of the sixteen segments may compress and the member is
/// still stored. Five may not. Under the option, and in a member UNDER 128
/// MiB whatever the option, one may, which is what stores a big member
/// whose first and last bytes are an index, and two may not.
#[test]
fn four_compressible_segments_are_outvoted_from_128_mib_and_five_are_not() {
    // (the member's size, the option) and how many compressible segments
    // still store it.
    for (len, option, most) in [
        (GATE, false, 4usize),
        (GATE, true, 1),
        (4 << 20, false, 1),
        (4 << 20, true, 1),
    ] {
        let segment = len / 16;
        let mut member = Keystream::take(6, len);
        // Text over the first `n` whole segments, one member at a time.
        let mut covered = 0;
        for n in [1usize, 2, 4, 5] {
            member[covered * segment..n * segment].copy_from_slice(&rarkit_testdata::chatter(
                7 + n as u64,
                (n - covered) * segment,
            ));
            covered = n;
            let mut o = options_at(WriteFormat::Rar5, 1, false);
            o.store_one_miss = option;
            let (volumes, _) = write(o, &[(b"m", &member, false)]);
            let back = read_back(&volumes);
            assert_eq!(
                stored(&back[0]),
                n <= most,
                "{len} bytes, store_one_miss={option}: {n} compressible segments in sixteen"
            );
            assert!(back[0].bytes == member);
        }
    }
}

/// The verdict is a property of the bytes: the same member gives the same
/// archive at any encoder width.
#[test]
fn the_verdict_does_not_move_with_the_width() {
    let noise = Keystream::take(10, 2 << 20);
    let words = rarkit_testdata::chatter(11, 2 << 20);
    let mut seen = None;
    for workers in [1, 2, 8] {
        let mut o = options(WriteFormat::Rar5, false, None);
        o.workers = Some(workers);
        let (volumes, _) = write(o, &[(b"n", &noise, true), (b"w", &words, false)]);
        match &seen {
            None => seen = Some(volumes),
            Some(first) => assert_eq!(first, &volumes, "workers={workers} moved a byte"),
        }
    }
}

/// A stored member over a patchable volume set holds nothing that
/// follows it: the report's peak is the same for a 40 MiB and a 120 MiB
/// incompressible READER member, where holding either whole would follow
/// it. What is held is the 32 MiB prefix, once.
#[test]
fn a_stored_reader_member_over_patchable_volumes_is_flat() {
    let mut peaks = Vec::new();
    for mib in [40u64, 120] {
        let mut writer =
            Writer::new(options(WriteFormat::Rar5, false, Some(16 << 20))).expect("options");
        let mut reader = Streamed {
            keys: Keystream::new(12),
            left: mib << 20,
        };
        writer
            .add(MemberSpec {
                name: b"full.mkv",
                payload: Payload::Reader {
                    reader: &mut reader,
                    size: mib << 20,
                    crc32: None,
                },
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut out = Volumes::default();
        let report = writer.finish_volumes(&mut out).expect("finish");
        let back = read_back(&out.kept);
        assert!(stored(&back[0]), "{mib} MiB of keystream was compressed");
        assert_eq!(back[0].bytes.len() as u64, mib << 20);
        let mut again = vec![0u8; (mib << 20) as usize];
        Keystream::new(12).fill(&mut again);
        assert!(back[0].bytes == again, "{mib} MiB read back to other bytes");
        peaks.push(report.peak_working_memory);
    }
    assert!(
        peaks[1] <= peaks[0] + (1 << 20),
        "a stored reader member's peak followed it: {} for 40 MiB, {} for 120 MiB",
        peaks[0],
        peaks[1]
    );
    // What it may hold at once, named term by term: the held prefix (at
    // most 32 MiB, pulled to its last sample), the stored path's
    // read-ahead pool (the stored create path's `read_ahead`: at most six
    // buffers of 2 MiB) and the copy buffer (1 MiB), with 2 MiB for
    // headers and the member table. None of them follows the member.
    const PREFIX: u64 = 32 << 20;
    const READ_AHEAD: u64 = 6 * (2 << 20);
    const COPY: u64 = 1 << 20;
    assert!(
        peaks[1] < PREFIX + READ_AHEAD + COPY + (2 << 20),
        "a stored reader member held {} bytes, more than a prefix, the read-ahead pool and a \
         copy buffer",
        peaks[1]
    );
}

/// THE KNOWN FAILURE of a source read once, pinned. A reader is judged on
/// its first 32 MiB, so an incompressible head that long in front of text
/// is STORED, where the same bytes handed over in memory are judged across
/// the whole member and compressed. Spec G 3.8.3 states it. A source that
/// can SEEK does not have it (`Payload::Seekable`, the last rows of this
/// file); a reader keeps it, being read once.
#[test]
fn an_incompressible_head_as_long_as_the_prefix_is_stored_from_a_reader_only() {
    let mut member = Keystream::take(13, 32 << 20);
    member.extend_from_slice(&rarkit_testdata::chatter(14, 32 << 20));
    let (volumes, _) = write(
        options(WriteFormat::Rar5, false, None),
        &[(b"reader", &member, true), (b"bytes", &member, false)],
    );
    let back = read_back(&volumes);
    assert!(
        stored(&back[0]),
        "the reader member's 32 MiB head did not decide it"
    );
    assert!(
        !stored(&back[1]),
        "the in-memory member was not judged across its whole length"
    );
    assert_eq!(back[0].bytes, member);
    assert_eq!(back[1].bytes, member);
}

// ---- spec G 3.8.3's own acceptance list, tests 1 to 8 -------------------

const MIB: usize = 1 << 20;

/// Source-like lines, which compress about as code does.
fn code(len: usize, seed: u64) -> Vec<u8> {
    let tokens = [
        "fn ", "let ", "mut ", "self", ".len()", " = ", "(", ")", "{\n", "}\n", "if ", "else ",
        "return ", "match ", "=> ", "Some(", "None", "Ok(", "Err(", "u64", "usize", ";\n", ", ",
        "    ", "for ", " in ", "0..", "&", "&mut ", "impl ", "pub ", "struct ",
    ];
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(tokens[(state >> 40) as usize % tokens.len()].as_bytes());
    }
    out.truncate(len);
    out
}

fn options_at(format: WriteFormat, level: u8, solid: bool) -> WriteOptions {
    WriteOptions {
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        ..options(format, solid, None)
    }
}

/// `options` with level 1's default dictionary held at the 2 MiB it was
/// when [`BEFORE_FOUR_MISSES`] was taken (`level1_dictionary_2mib`: since
/// 1 Oct 2026 a non-solid RAR 5 level 1 defaults to 4 MiB), and level 3's
/// likewise (`level3_dictionary_2mib`: since 9 Oct 2026 a non-solid RAR 5
/// level 3 defaults to 16 MiB under one far link). They reach no other
/// level and no RAR 4 archive.
fn at_2_mib(options: WriteOptions) -> WriteOptions {
    WriteOptions {
        level1_dictionary_2mib: true,
        level3_dictionary_2mib: true,
        ..options
    }
}

/// Where spec G 3.8.3 centres sample `k` of a span of `len` bytes.
fn sample_at(len: usize, k: usize) -> usize {
    let start = k * len / 16;
    start + ((k + 1) * len / 16 - start - (64 << 10)) / 2
}

/// Reference `unrar t` over one archive, where `unrar` is on PATH; the
/// row says which it did.
fn unrar_tests(archive: &[u8], label: &str) {
    if std::process::Command::new("unrar").output().is_err() {
        eprintln!("{label}: SKIPPED the unrar t arm: unrar is not on PATH");
        return;
    }
    let dir = std::env::temp_dir().join(format!("rarkit-store383-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.rar", label.replace(['/', ' '], "-")));
    std::fs::write(&path, archive).unwrap();
    let status = std::process::Command::new("unrar")
        .arg("t")
        .arg("-idq")
        .arg(&path)
        .status()
        .unwrap();
    std::fs::remove_file(&path).ok();
    assert!(
        status.success(),
        "{label}: reference unrar t refused the archive"
    );
}

/// Test 1: an incompressible member of exactly 1 MiB, and one of 64 MiB,
/// at -m1, -m3 and -m5, is STORED, passes `unrar t` and extracts.
#[test]
fn spec_383_test_1_random_members_of_1_and_64_mib_are_stored_at_every_level() {
    for len in [MIB, 64 * MIB] {
        let data = Keystream::take(21, len);
        for level in [1, 3, 5] {
            let (volumes, _) = write(
                options_at(WriteFormat::Rar5, level, false),
                &[(b"random.bin", &data, false)],
            );
            let back = read_back(&volumes);
            assert!(stored(&back[0]), "{len} B at -m{level} was compressed");
            assert!(
                back[0].bytes == data,
                "{len} B at -m{level} extracted to other bytes"
            );
            unrar_tests(&volumes[0], &format!("t1-{len}-m{level}"));
        }
    }
}

/// Test 2: one byte under 1 MiB is never sampled, and the compressor
/// writes it.
#[test]
fn spec_383_test_2_one_byte_under_1_mib_is_compressed() {
    let data = Keystream::take(22, MIB - 1);
    let (volumes, _) = write(
        options_at(WriteFormat::Rar5, 3, false),
        &[(b"r", &data, false)],
    );
    let back = read_back(&volumes);
    assert!(
        !stored(&back[0]),
        "a 1,048,575 byte member was sampled and stored"
    );
    assert!(back[0].bytes == data);
}

/// Test 3: text and code of 64 MiB are never stored.
#[test]
fn spec_383_test_3_text_and_code_of_64_mib_are_never_stored() {
    let words = rarkit_testdata::chatter(23, 64 * MIB);
    let source = code(64 * MIB, 24);
    let (volumes, _) = write(
        options_at(WriteFormat::Rar5, 1, false),
        &[(b"words.txt", &words, true), (b"code.rs", &source, true)],
    );
    let back = read_back(&volumes);
    assert!(!stored(&back[0]), "64 MiB of text was stored");
    assert!(!stored(&back[1]), "64 MiB of code was stored");
    assert!(back[0].bytes == words && back[1].bytes == source);
}

/// Noise of `len` bytes with text over the centred samples of segments
/// `compressible` of its first `span` bytes, so that exactly that many of
/// the sixteen samples compress and every other one is noise. The span is
/// the whole member for bytes in memory and the first 32 MiB for a reader.
fn with_samples_in(seed: u64, len: usize, span: usize, compressible: &[usize]) -> Vec<u8> {
    let mut member = Keystream::take(seed, len);
    for &k in compressible {
        member[sample_at(span, k)..][..64 << 10]
            .copy_from_slice(&rarkit_testdata::chatter(seed + k as u64, 64 << 10));
    }
    member
}

/// [`with_samples_in`] over the whole member: a payload of bytes.
fn with_compressible_samples(seed: u64, len: usize, compressible: &[usize]) -> Vec<u8> {
    with_samples_in(seed, len, len, compressible)
}

/// The store rule's size gate: four misses from here, one below.
const GATE: usize = 128 * MIB;
/// What a reader member is judged on.
const PREFIX: usize = 32 * MIB;

/// Test 4, as the rule stands since 1 Oct 2026: a member of 128 MiB with
/// exactly 12 incompressible samples of 16 is STORED by default and
/// compressed under the option; 11 of 16 is compressed either way; 15 of
/// 16 is stored either way and 14 of 16 only by default. Compressible
/// bytes only in the first and last 32 KiB still store, because the
/// samples are centred. Bytes in both families, and a reader, which is
/// judged on its first 32 MiB.
#[test]
fn spec_383_test_4_twelve_of_sixteen_stores_by_default_and_not_under_the_option() {
    // (name, the samples that compress, stored by default, under the option)
    let rows: [(&str, &[usize], bool, bool); 4] = [
        ("fifteen", &[7], true, true),
        ("fourteen", &[7, 12], true, false),
        ("twelve", &[0, 1, 7, 12], true, false),
        ("eleven", &[0, 1, 7, 12, 15], false, false),
    ];
    let shapes = [
        (WriteFormat::Rar5, false),
        (WriteFormat::Rar4(rarkit::Rar4Version::V29), false),
        (WriteFormat::Rar5, true),
    ];
    for (format, as_reader) in shapes {
        let span = if as_reader { PREFIX } else { GATE };
        for (name, compressible, by_default, under_option) in rows {
            // The discriminating rows in every shape; 15 of 16 once.
            if name == "fifteen" && (as_reader || !matches!(format, WriteFormat::Rar5)) {
                continue;
            }
            let member = with_samples_in(25, GATE, span, compressible);
            for option in [false, true] {
                let mut o = options_at(format, 1, false);
                o.store_one_miss = option;
                let (volumes, _) = write(o, &[(name.as_bytes(), &member, as_reader)]);
                let back = read_back(&volumes);
                let want = if option { under_option } else { by_default };
                assert_eq!(
                    stored(&back[0]),
                    want,
                    "{format:?} reader={as_reader} store_one_miss={option}: {name}"
                );
                assert!(back[0].bytes == member);
            }
        }
    }
    let mut ends = Keystream::take(25, GATE);
    ends[..32 << 10].fill(0);
    ends[GATE - (32 << 10)..].fill(0);
    let (volumes, _) = write(
        options_at(WriteFormat::Rar5, 1, false),
        &[(b"ends", &ends, false)],
    );
    assert!(
        stored(&read_back(&volumes)[0]),
        "compressible first and last 32 KiB kept the member compressed"
    );
}

/// The gate's edge, to the byte: one byte under 128 MiB a member with 12
/// incompressible samples of 16 is COMPRESSED, as before 1 Oct 2026, and
/// the option moves no byte of its archive; at 128 MiB it is stored, and
/// the option compresses it. Bytes and a reader alike.
#[test]
fn four_misses_begin_at_exactly_128_mib() {
    for (len, stores) in [(GATE - 1, false), (GATE, true)] {
        for as_reader in [false, true] {
            let span = if as_reader { PREFIX } else { len };
            let twelve = with_samples_in(28, len, span, &[2, 5, 8, 11]);
            let members: [(&[u8], &[u8], bool); 1] = [(b"twelve", &twelve, as_reader)];
            let (by_default, _) = write(options_at(WriteFormat::Rar5, 1, false), &members);
            let total: usize = by_default.iter().map(Vec::len).sum();
            // A stored member is its own bytes and a header; a compressed
            // one gives back most of its four text samples.
            assert_eq!(
                total > len,
                stores,
                "{len} bytes, reader={as_reader}: {total} bytes of archive"
            );
            let (under, _) = write(one_miss(options_at(WriteFormat::Rar5, 1, false)), &members);
            assert_eq!(
                under == by_default,
                !stores,
                "{len} bytes, reader={as_reader}: the option and the default"
            );
            let back = read_back(&by_default);
            assert_eq!(stored(&back[0]), stores, "{len} bytes, reader={as_reader}");
            assert!(back[0].bytes == twelve);
        }
    }
}

/// SHA-256 of [`boundary_members`] written by the PARENT of the commit
/// that moved the rule (an earlier revision, one miss allowed at every
/// size), at every level and in both families, and of [`big_member`] at
/// levels 1 and 3 (`-big`): what `store_one_miss = true` must write byte
/// for byte. Printed there by this same test under
/// `STORE_RULE_PRINT_PINS`, with the option's line taken out. The level 1
/// RAR 5 rows were written in the 2 MiB default dictionary of that day,
/// so they are compared under [`at_2_mib`]; no pin was re-taken when the
/// default moved. The four level 4 and level 5 rows were re-taken, by the
/// same print, at
/// SPEC-H3 8.1's ladder land of 1 Oct 2026: level 4's
/// default plan went to the chains at 64 links and level 5's lazy tree
/// plan took the backward extension:
/// those rows moved with the levels' plans, not with the store rule, and
/// the rows of levels 1 to 3 and the `-big` rows are the parent's.
///
/// The two level 5 rows were re-taken once more that day, by the same
/// print, at the land of LEVEL 5 BY CLASS (SPEC-H3 8.1): these
/// members read under the cut-off or are a solid run, so level 5 writes
/// them over the chains at 80 links, 72 in a solid run; every other row
/// was printed beside them and had not moved.
///
/// The two RAR 5 level 3 rows (`rar5-m3`, `rar5-m3-big`) were re-taken by
/// the same print on 14 Oct 2026 at the thin scan (FROM-STUDIO 389 C),
/// which parses a block the sample reads thin at level 3 of RAR 5; every
/// other row printed the same. Both rows were taken again on 17 Oct 2026
/// where the thin scan met the empty stride (FROM-STUDIO 514 D).
const BEFORE_FOUR_MISSES: [(&str, &str); 14] = [
    (
        "rar5-m1",
        "aaa08d6b33e4e8795cb7ff4ede8337301aeef67ff964aeb58c01e39bd75c7530",
    ),
    (
        "rar5-m2",
        "8a9932592cc79fb4287783e04f4dc52b475454a8574c559e0152a4f90fa8de3f",
    ),
    (
        "rar5-m3",
        "d070e011aa70b213264ec49d10a5048a25ddabda67cfc38a4084906070c95bb1",
    ),
    (
        "rar5-m4",
        "d2240e2a4ca099824a6daa43d3d8ab62fc4c0b9631cfc4490c947c09303f1c5b",
    ),
    (
        "rar5-m5",
        "cddfb61e25a37480f831985c6044e2b8f99085fd28c3e1ca62f9436b822f01f6",
    ),
    (
        "rar4v29-m1",
        "9daa4181f259ad48ce6c8b20b97d6112a4e0b5891c872b9ffda58cde3c312ec1",
    ),
    (
        "rar4v29-m2",
        "89961b654be2e684ec3fb67505549a216a81f7d4f8a6e1840794c05a27cbd9ed",
    ),
    (
        "rar4v29-m3",
        "f1120efb93a5ceddc5b1d1bc70d087d9fcd28ffaef0ed66e8058005017772dd7",
    ),
    (
        "rar4v29-m4",
        "d4b764bd412d9c10d6139a9532f6fe906fd1f651db2016a755f8dce1e55b7e11",
    ),
    (
        "rar4v29-m5",
        "e0f4037daa7bceb7eb400c07eac5dee7712f516a2d68406b3e87607cc6a15bd7",
    ),
    (
        "rar5-m1-big",
        "980e779e172d8704ed9c2873784de3114c41fbbec8c400e5336ced100d53c283",
    ),
    (
        "rar5-m3-big",
        "63adb1a3d3f6df29d8e265c2c81c071a46d4fed9f95733849be0d80c87ebc4d0",
    ),
    (
        "rar4v29-m1-big",
        "0b632f0b82086e13f6be92231fc2dcd2f766f809a965a3978d37a9cfa2d4aa8e",
    ),
    (
        "rar4v29-m3-big",
        "a5fc46fab58906954b783d94856cf454bb6100f2d582f43869121ccc4a914c37",
    ),
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Members on both sides of the one-miss bar, all under the size gate:
/// noise of 2 MiB with 0, 1, 2, 4 and 5 samples that compress, and text;
/// the four-sample one again as a reader.
fn boundary_members() -> Vec<(Vec<u8>, Vec<u8>, bool)> {
    let len = 2 * MIB;
    let mut members: Vec<(Vec<u8>, Vec<u8>, bool)> = [
        ("n0", &[][..]),
        ("n1", &[3]),
        ("n2", &[3, 9]),
        ("n4", &[0, 1, 3, 9]),
        ("n5", &[0, 1, 3, 9, 14]),
    ]
    .iter()
    .map(|(name, compressible)| {
        (
            name.as_bytes().to_vec(),
            with_compressible_samples(40, len, compressible),
            false,
        )
    })
    .collect();
    members.push((b"text".to_vec(), rarkit_testdata::chatter(41, len), false));
    members.push((b"n4-reader".to_vec(), members[3].1.clone(), true));
    members
}

/// The member the two rules part on: noise of 128 MiB with four samples
/// that compress.
fn big_member() -> Vec<u8> {
    with_compressible_samples(42, GATE, &[0, 1, 3, 9])
}

fn pin_of(what: &str) -> &'static str {
    BEFORE_FOUR_MISSES
        .iter()
        .find(|(name, _)| *name == what)
        .map(|(_, sha)| *sha)
        .expect("a pinned digest")
}

fn family_of(format: WriteFormat) -> &'static str {
    if matches!(format, WriteFormat::Rar5) {
        "rar5"
    } else {
        "rar4v29"
    }
}

/// Every member under 128 MiB is written as the parent wrote it, option
/// or not, at every level and in both families: one miss is still its
/// rule.
#[test]
fn members_under_the_gate_are_the_parents_archives_at_every_level() {
    let owned = boundary_members();
    let members: Vec<(&[u8], &[u8], bool)> = owned
        .iter()
        .map(|(name, bytes, as_reader)| (name.as_slice(), bytes.as_slice(), *as_reader))
        .collect();
    for format in FORMATS {
        for level in 1u8..=5 {
            let what = format!("{}-m{level}", family_of(format));
            let (under, _) = write(one_miss(options_at(format, level, false)), &members);
            let (before, _) = write(
                at_2_mib(one_miss(options_at(format, level, false))),
                &members,
            );
            if std::env::var_os("STORE_RULE_PRINT_PINS").is_some() {
                eprintln!("PIN (\"{what}\", \"{}\"),", sha256_hex(&before[0]));
                continue;
            }
            assert_eq!(
                sha256_hex(&before[0]),
                pin_of(&what),
                "{what}: the option does not write the archive from before four misses"
            );
            let (by_default, _) = write(options_at(format, level, false), &members);
            assert!(
                by_default == under,
                "{what}: the default moved a byte of a member under 128 MiB"
            );
            let back = read_back(&by_default);
            // n0, n1, n2, n4, n5, text, n4 as a reader.
            assert_eq!(
                back.iter().map(stored).collect::<Vec<bool>>(),
                [true, true, false, false, false, false, false],
                "{what}"
            );
            for (read, written) in back.iter().zip(&members) {
                assert!(read.bytes == written.1, "{what}");
            }
        }
    }
}

/// `options` under `WriteOptions::store_packed_samples`: every sample
/// packed in full by the encoder and its output measured, the rule's
/// sampler until 1 Oct 2026, where the default counts the length.
fn packed_samples(options: WriteOptions) -> WriteOptions {
    WriteOptions {
        store_packed_samples: true,
        ..options
    }
}

/// Noise of 2 MiB in which every one of the sixteen samples holds `zeros`
/// zero bytes: each sample packs to about its length less those bytes, so
/// the members of [`at_the_bar`] carry their samples across the 99.5
/// percent bar (328 bytes of a sample) a few bytes at a time.
fn with_zeros_in_every_sample(seed: u64, zeros: usize) -> Vec<u8> {
    let len = 2 * MIB;
    let mut member = Keystream::take(seed, len);
    for k in 0..16 {
        member[sample_at(len, k) + 1000..][..zeros].fill(0);
    }
    member
}

/// Members whose verdicts are decided by a few bytes of a sample's packed
/// length: where a length counted one byte off the packed one would move
/// a member between stored and compressed.
fn at_the_bar() -> Vec<(Vec<u8>, Vec<u8>, bool)> {
    (300..=420)
        .step_by(8)
        .map(|zeros| {
            (
                format!("z{zeros}").into_bytes(),
                with_zeros_in_every_sample(50 + zeros as u64, zeros),
                zeros % 16 == 4,
            )
        })
        .collect()
}

/// `WriteOptions::store_packed_samples` moves NO BYTE: the counted length
/// is the packed length, so every verdict is the same and so is every
/// archive, on members on both sides of the bar and on members whose
/// samples sit within a few bytes of it, as bytes and as a reader, in
/// both families, in a solid set (whose votes are taken across the pool
/// by judges the run keeps) and outside one. And the members at the bar
/// really are on both sides of it, so the equality is held where a
/// verdict is decided.
#[test]
fn packing_the_samples_in_full_writes_the_same_archive() {
    let mut owned = boundary_members();
    owned.extend(at_the_bar());
    let members: Vec<(&[u8], &[u8], bool)> = owned
        .iter()
        .map(|(name, bytes, as_reader)| (name.as_slice(), bytes.as_slice(), *as_reader))
        .collect();
    for format in FORMATS {
        for solid in [false, true] {
            for level in [1u8, 3, 5] {
                let what = format!("{}-m{level}-solid:{solid}", family_of(format));
                let (counted, _) = write(options_at(format, level, solid), &members);
                let (packed, _) = write(packed_samples(options_at(format, level, solid)), &members);
                assert!(
                    counted == packed,
                    "{what}: the counted samples moved a byte"
                );
                let (counted_one, _) = write(one_miss(options_at(format, level, solid)), &members);
                let (packed_one, _) = write(
                    packed_samples(one_miss(options_at(format, level, solid))),
                    &members,
                );
                assert!(counted_one == packed_one, "{what}, one miss");
                if level == 3 {
                    let back = read_back(&counted);
                    let mut at_bar: Vec<(&[u8], bool)> = back
                        .iter()
                        .filter(|member| member.name.starts_with(b"z"))
                        .map(|member| (member.name.as_slice(), stored(member)))
                        .collect();
                    at_bar.sort();
                    assert_eq!(at_bar.len(), 16, "{what}");
                    assert!(
                        at_bar.first().is_some_and(|m| m.1) && at_bar.last().is_some_and(|m| !m.1),
                        "{what}: the members at the bar are not on both sides of it: {at_bar:?}"
                    );
                    for read in &back {
                        let written = members
                            .iter()
                            .find(|member| member.0 == read.name.as_slice())
                            .expect("a member written");
                        assert!(read.bytes == written.1, "{what}");
                    }
                }
            }
        }
    }
}

/// The option gives the rule before 1 Oct 2026 back BYTE FOR BYTE above
/// the gate too: a member of 128 MiB with four samples that compress is
/// stored by default, and under the option its archive is the parent's,
/// in both families (levels 1 and 3: the verdict is taken before the
/// level is looked at, and the counts on real corpora hold the option to
/// the parent's bytes at every level).
#[test]
fn the_option_writes_the_archive_from_before_four_misses_above_the_gate() {
    let big = big_member();
    let members: [(&[u8], &[u8], bool); 1] = [(b"big4", &big, false)];
    for format in FORMATS {
        for level in [1u8, 3] {
            let what = format!("{}-m{level}-big", family_of(format));
            let (under, _) = write(
                at_2_mib(one_miss(options_at(format, level, false))),
                &members,
            );
            if std::env::var_os("STORE_RULE_PRINT_PINS").is_some() {
                eprintln!("PIN (\"{what}\", \"{}\"),", sha256_hex(&under[0]));
                continue;
            }
            assert_eq!(
                sha256_hex(&under[0]),
                pin_of(&what),
                "{what}: the option does not write the archive from before four misses"
            );
            assert!(
                under[0].len() < GATE,
                "{what}: the option stored the member"
            );
            let (by_default, _) = write(options_at(format, level, false), &members);
            let back = read_back(&by_default);
            assert!(stored(&back[0]), "{what}: 12 of 16 did not store");
            assert!(back[0].bytes == big, "{what}");
        }
    }
}

/// A reader that counts what it gives, so a row can say it was read once.
struct Counted<'a> {
    bytes: &'a [u8],
    given: u64,
}

impl Read for Counted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.bytes.read(buf)?;
        self.given += n as u64;
        Ok(n)
    }
}

/// Test 5: a 64 MiB reader whose first 32 MiB are incompressible and the
/// rest text is STORED on its first 32 MiB, one whose first 32 MiB are
/// text is compressed, and in both the reader is read once and the member
/// extracts to the input.
#[test]
fn spec_383_test_5_a_reader_is_judged_on_its_first_32_mib() {
    let mut head_random = Keystream::take(28, 32 * MIB);
    head_random.extend_from_slice(&rarkit_testdata::chatter(29, 32 * MIB));
    let mut head_text = rarkit_testdata::chatter(30, 32 * MIB);
    head_text.extend_from_slice(&Keystream::take(31, 32 * MIB));
    for (label, data, want_stored) in [
        ("random head", &head_random, true),
        ("text head", &head_text, false),
    ] {
        let mut reader = Counted {
            bytes: data,
            given: 0,
        };
        let mut writer = Writer::new(options_at(WriteFormat::Rar5, 1, false)).expect("options");
        writer
            .add(MemberSpec {
                name: b"m.bin",
                payload: Payload::Reader {
                    reader: &mut reader,
                    size: data.len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut out = std::io::Cursor::new(Vec::new());
        writer.finish_seek(&mut out).expect("finish");
        assert_eq!(
            reader.given,
            data.len() as u64,
            "{label}: the reader was not read once"
        );
        let back = read_back(&[out.into_inner()]);
        assert_eq!(stored(&back[0]), want_stored, "{label}: the verdict");
        assert!(back[0].bytes == *data, "{label}: extracted to other bytes");
    }
}

/// Test 6, as it reads since 1 Oct 2026: an incompressible member of a
/// SOLID set of at least 1 MiB IS stored by the rule, whatever its size,
/// and one under 1 MiB is never sampled; with `solid_store` off no solid
/// member is stored. (`tests/solid_store.rs` holds the rest of the test:
/// the chain across the stored member, the references, the widths.)
#[test]
fn spec_383_test_6_a_solid_member_is_stored_unless_the_option_is_off() {
    for len in [2 * MIB, 64 * MIB] {
        let data = Keystream::take(32, len);
        let small = Keystream::take(33, MIB - 1);
        for solid_store in [true, false] {
            let (volumes, _) = write(
                WriteOptions {
                    solid_store,
                    ..options_at(WriteFormat::Rar5, 1, true)
                },
                &[(b"s", &data, false), (b"t", &small, false)],
            );
            let back = read_back(&volumes);
            assert_eq!(
                stored(&back[0]),
                solid_store,
                "a {len} byte solid member, solid_store {solid_store}"
            );
            assert!(!stored(&back[1]), "a solid member under 1 MiB was stored");
            assert!(back[0].bytes == data && back[1].bytes == small);
        }
    }
}

/// Test 7: a `Stored` archive is what it was, every member method 0; and
/// the REFERENCE layout is out of the rule. That layout writes stored
/// members only (`Writer::new` refuses it for a compressed one, where byte
/// identity is not claimed), so the rule, which samples only a member the
/// options would compress, never reaches it: a 64 MiB incompressible member
/// in it is written as it always was.
#[test]
fn spec_383_test_7_stored_archives_and_the_reference_layout_are_untouched() {
    let data = Keystream::take(33, 64 * MIB);
    let words = rarkit_testdata::chatter(34, 2 * MIB);
    let stored_options = WriteOptions {
        method: WriteMethod::Stored,
        ..options(WriteFormat::Rar5, false, None)
    };
    let (volumes, _) = write(
        stored_options,
        &[(b"r", &data, false), (b"w", &words, false)],
    );
    let back = read_back(&volumes);
    assert!(stored(&back[0]) && stored(&back[1]));
    let archive: usize = volumes.iter().map(Vec::len).sum();
    assert!(archive < data.len() + words.len() + 400);

    let reference = |method| WriteOptions {
        layout: rarkit::Layout::Reference { quick_open: true },
        method,
        ..options(WriteFormat::Rar5, false, None)
    };
    assert!(
        Writer::new(reference(WriteMethod::Compressed {
            level: 1,
            dictionary: None
        }))
        .is_err(),
        "the reference layout took a compressed member, which would bring it into the rule"
    );
    let (volumes, _) = write(reference(WriteMethod::Stored), &[(b"r", &data, false)]);
    let back = read_back(&volumes);
    assert!(stored(&back[0]));
    assert!(back[0].bytes == data);
}

/// Test 8: the same 64 MiB incompressible member is STORED in a RAR 5
/// archive and a RAR 4 family one alike, and 64 MiB of text is compressed
/// in both.
#[test]
fn spec_383_test_8_both_families_judge_alike() {
    let data = Keystream::take(35, 64 * MIB);
    let words = rarkit_testdata::chatter(36, 64 * MIB);
    for format in FORMATS {
        let (volumes, _) = write(
            options_at(format, 1, false),
            &[(b"random.bin", &data, false), (b"words.txt", &words, true)],
        );
        let back = read_back(&volumes);
        assert!(
            stored(&back[0]),
            "{format:?}: 64 MiB of random bytes was compressed"
        );
        assert!(!stored(&back[1]), "{format:?}: 64 MiB of text was stored");
        assert!(back[0].bytes == data && back[1].bytes == words);
    }
}

/// **The worker team pulls a reader member whole, and the verdict is
/// taken from what it pulled.** The team encodes a non-solid run's members
/// ahead of the writer, and a READER member it takes is pulled whole as the
/// batch is planned; its reader then has nothing left. So spec G 3.8.3's
/// verdict for such a member is taken there, from the pulled bytes (the
/// whole member, and so the reader's whole span), never from the reader
/// again; a member the samples STORE leaves the batch and the writer
/// writes it stored from those bytes. Small members planned in front of it
/// must not drop what is held for it. Found merging with the non-solid
/// small-member work, whose team takes members of several parse blocks
/// ("the bytes ran out early" in create_gate), 28 Sep 2026.
#[test]
fn a_member_the_team_pulls_whole_is_judged_on_its_pulled_bytes() {
    let small: Vec<Vec<u8>> = (0..4)
        .map(|i| rarkit_testdata::chatter((40 + i) as u64, 90_000))
        .collect();
    let noise = Keystream::take(44, 3 * MIB / 2);
    let words = rarkit_testdata::chatter(45, 3 * MIB / 2);
    for as_reader in [true, false] {
        let members: Vec<(&[u8], &[u8], bool)> = vec![
            (b"a.txt", &small[0], as_reader),
            (b"b.txt", &small[1], as_reader),
            (b"noise.bin", &noise, as_reader),
            (b"c.txt", &small[2], as_reader),
            (b"words.txt", &words, as_reader),
            (b"d.txt", &small[3], as_reader),
        ];
        rarkit::internals::writers::reset_team_prepared();
        let (volumes, _) = write(options_at(WriteFormat::Rar5, 3, false), &members);
        let prepared = rarkit::internals::writers::team_prepared();
        let back = read_back(&volumes);
        assert_eq!(
            back.len(),
            members.len(),
            "reader={as_reader}: member count"
        );
        for (got, (name, data, _)) in back.iter().zip(&members) {
            assert_eq!(got.name, *name, "reader={as_reader}: order");
            assert!(
                got.bytes == *data,
                "reader={as_reader}: {:?} read back",
                got.name
            );
        }
        assert!(
            stored(&back[2]),
            "reader={as_reader}: the noise member was compressed"
        );
        assert!(
            !stored(&back[4]),
            "reader={as_reader}: the text member was stored"
        );
        eprintln!("reader={as_reader}: the team prepared {prepared} members");
    }
}

// ---- a source that can SEEK: the vote across the whole member -----------
//
// `Payload::Seekable`: a member of
// 4 GiB and more whose source can seek is sampled where its sixteen
// samples lie across the WHOLE member, before the run plans anything, and
// then read exactly once. Under 4 GiB it is a reader in every respect.
// The rows below are that sentence, clause by clause. A test cannot hand
// over 4 GiB, so each row that reaches the vote lowers the floor for its
// own thread ([`Floor`]) to just over the 32 MiB a reader is judged on.

/// This thread's floor for the whole-member vote, put back when dropped.
struct Floor;

impl Floor {
    fn at(from: u64) -> Floor {
        rarkit::internals::writers::set_whole_vote_from(Some(from));
        Floor
    }

    /// Just over the prefix: every member a reader's head does not span.
    fn low() -> Floor {
        Floor::at(PREFIX as u64 + 1)
    }
}

impl Drop for Floor {
    fn drop(&mut self) {
        rarkit::internals::writers::set_whole_vote_from(None);
    }
}

/// What a [`Sought`] source was asked, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Asked {
    /// Where it stands.
    Where,
    /// A seek to this offset of the source.
    Seek(u64),
    /// A read at this offset that gave this many bytes.
    Read(u64, usize),
}

/// A source that can seek, over bytes held elsewhere, that records what
/// it is asked and can be made to fail in the ways a file does.
struct Sought<'a> {
    bytes: &'a [u8],
    at: u64,
    asked: Vec<Asked>,
    /// It cannot say where it stands.
    no_position: bool,
    /// The seek with this index (the first is 0) fails, and every later
    /// one.
    seeks_fail_from: Option<usize>,
    /// The source ends here, short of `bytes`: a file that shrank.
    ends_at: Option<u64>,
}

impl<'a> Sought<'a> {
    fn over(bytes: &'a [u8]) -> Sought<'a> {
        Sought {
            bytes,
            at: 0,
            asked: Vec::new(),
            no_position: false,
            seeks_fail_from: None,
            ends_at: None,
        }
    }

    fn seeks(&self) -> Vec<u64> {
        self.asked
            .iter()
            .filter_map(|asked| match asked {
                Asked::Seek(to) => Some(*to),
                _ => None,
            })
            .collect()
    }

    /// The reads that follow the last seek: the member's own read.
    fn reads_after_the_look(&self) -> Vec<(u64, usize)> {
        let from = self
            .asked
            .iter()
            .rposition(|asked| matches!(asked, Asked::Seek(_)))
            .map_or(0, |last| last + 1);
        self.asked[from..]
            .iter()
            .filter_map(|asked| match asked {
                Asked::Read(at, len) => Some((*at, *len)),
                _ => None,
            })
            .collect()
    }

    /// How many bytes were read before the last seek: the look.
    fn looked_at(&self) -> u64 {
        let until = self
            .asked
            .iter()
            .rposition(|asked| matches!(asked, Asked::Seek(_)))
            .unwrap_or(0);
        self.asked[..until]
            .iter()
            .map(|asked| match asked {
                Asked::Read(_, len) => *len as u64,
                _ => 0,
            })
            .sum()
    }
}

impl Read for Sought<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let end = self
            .ends_at
            .unwrap_or(self.bytes.len() as u64)
            .min(self.bytes.len() as u64);
        let left = end.saturating_sub(self.at) as usize;
        let n = buf.len().min(left);
        let at = self.at as usize;
        buf[..n].copy_from_slice(&self.bytes[at..at + n]);
        if n > 0 {
            self.asked.push(Asked::Read(self.at, n));
        }
        self.at += n as u64;
        Ok(n)
    }
}

impl std::io::Seek for Sought<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let refused = || std::io::Error::from(std::io::ErrorKind::Unsupported);
        match to {
            std::io::SeekFrom::Current(0) => {
                if self.no_position {
                    return Err(refused());
                }
                self.asked.push(Asked::Where);
            }
            std::io::SeekFrom::Start(at) => {
                let index = self.seeks().len();
                if self.seeks_fail_from.is_some_and(|from| index >= from) {
                    return Err(refused());
                }
                self.asked.push(Asked::Seek(at));
                self.at = at;
            }
            other => panic!("the writer seeks from the start only, not {other:?}"),
        }
        Ok(self.at)
    }
}

/// How a row hands a member's bytes over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum As {
    Bytes,
    Reader,
    Seekable,
}

/// [`write`] with each member handed over as the row says, a seekable one
/// through a [`Sought`] source standing at its start.
fn write_as(options: WriteOptions, members: &[(&[u8], &[u8], As)]) -> (Vec<Vec<u8>>, WriteReport) {
    let (volumes, report, _) = write_sought(options, members);
    (volumes, report)
}

/// [`write_as`], and what each seekable member's source was asked.
fn write_sought(
    options: WriteOptions,
    members: &[(&[u8], &[u8], As)],
) -> (Vec<Vec<u8>>, WriteReport, Vec<Vec<Asked>>) {
    let volume = options.volume_size.is_some();
    let mut readers: Vec<Over<'_>> = members.iter().map(|m| Over(m.1)).collect();
    let mut sought: Vec<Sought<'_>> = members.iter().map(|m| Sought::over(m.1)).collect();
    let (volumes, report) = {
        let mut writer = Writer::new(options).expect("options");
        for (((name, bytes, how), reader), source) in members
            .iter()
            .zip(readers.iter_mut())
            .zip(sought.iter_mut())
        {
            let size = <[u8]>::len(bytes) as u64;
            let payload = match how {
                As::Bytes => Payload::Bytes(bytes),
                As::Reader => Payload::Reader {
                    reader,
                    size,
                    crc32: None,
                },
                As::Seekable => Payload::Seekable {
                    reader: source,
                    size,
                    crc32: None,
                },
            };
            writer
                .add(MemberSpec {
                    name,
                    payload,
                    mtime: None,
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        if volume {
            let mut out = Volumes::default();
            let report = writer.finish_volumes(&mut out).expect("finish");
            (out.kept, report)
        } else {
            let mut out = std::io::Cursor::new(Vec::new());
            let report = writer.finish_seek(&mut out).expect("finish");
            (vec![out.into_inner()], report)
        }
    };
    let asked = sought.into_iter().map(|source| source.asked).collect();
    (volumes, report, asked)
}

/// One member through one [`Sought`] source the row has prepared: the
/// writer's answer, and the source back to be read.
fn write_one<'a>(
    options: WriteOptions,
    mut source: Sought<'a>,
    size: u64,
) -> (Result<Vec<u8>>, Sought<'a>) {
    let outcome = {
        let mut writer = Writer::new(options).expect("options");
        writer
            .add(MemberSpec {
                name: b"m.bin",
                payload: Payload::Seekable {
                    reader: &mut source,
                    size,
                    crc32: None,
                },
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut out = std::io::Cursor::new(Vec::new());
        writer.finish_seek(&mut out).map(|_| out.into_inner())
    };
    (outcome, source)
}

/// 32 MiB of noise in front of 6 MiB of text: the member a reader's head
/// stores whole. Across the whole of it the last three samples lie in the
/// text (segments of 2.375 MiB: the thirteenth sample begins 32 KiB past
/// the noise), and it is compressed.
fn noise_then_text(seed: u64) -> Vec<u8> {
    let mut member = Keystream::take(seed, PREFIX);
    member.extend_from_slice(&rarkit_testdata::chatter(seed + 1, 6 * MIB));
    member
}

/// 3.25 MiB of text in front of noise, 40 MiB in all: a reader's head has
/// two samples in the text (they begin 0.97 and 2.97 MiB in) and
/// compresses the member; across the whole of it one sample is (the
/// second begins 3.72 MiB in), and it is stored.
fn text_then_noise(seed: u64) -> Vec<u8> {
    let mut member = rarkit_testdata::chatter(seed, 13 * MIB / 4);
    member.extend_from_slice(&Keystream::take(seed + 1, 40 * MIB - 13 * MIB / 4));
    member
}

/// The clause this variant exists for. A member whose head will not
/// compress and whose body does is COMPRESSED from a source that can seek,
/// as the same bytes in memory are, where a reader's 32 MiB head stores
/// it; and one whose head compresses in front of a body that does not is
/// STORED, where a reader's head sent it through the compressor. Both
/// families; every member reads back to its bytes.
#[test]
fn a_source_that_seeks_is_judged_across_the_whole_member() {
    let _floor = Floor::low();
    let head_noise = noise_then_text(50);
    let head_text = text_then_noise(52);
    for format in FORMATS {
        for (label, data, reader_stores, whole_stores) in [
            ("noise then text", &head_noise, true, false),
            ("text then noise", &head_text, false, true),
        ] {
            let (volumes, _) = write_as(
                options_at(format, 1, false),
                &[
                    (b"reader", data, As::Reader),
                    (b"seekable", data, As::Seekable),
                    (b"bytes", data, As::Bytes),
                ],
            );
            let back = read_back(&volumes);
            assert_eq!(
                stored(&back[0]),
                reader_stores,
                "{format:?} {label}: a reader's head"
            );
            assert_eq!(
                stored(&back[1]),
                whole_stores,
                "{format:?} {label}: the source that can seek"
            );
            assert_eq!(
                stored(&back[2]),
                whole_stores,
                "{format:?} {label}: the bytes in memory"
            );
            for member in &back {
                assert!(member.bytes == *data, "{format:?} {label}: read back");
            }
            unrar_tests(&volumes[0], &format!("seekable {format:?} {label}"));
        }
    }
}

/// Where the whole member says what its head says, a source that can seek
/// writes the archive a reader writes, byte for byte: noise (stored) and
/// text (compressed), over the prefix, at levels 1, 3 and 5 in RAR 5 and at
/// level 3 in RAR 4.
#[test]
fn where_the_verdict_is_the_heads_the_archive_is_the_readers() {
    let _floor = Floor::low();
    let noise = Keystream::take(54, 48 * MIB);
    let words = rarkit_testdata::chatter(55, 33 * MIB);
    for format in FORMATS {
        for level in [1, 3, 5] {
            if format != WriteFormat::Rar5 && level != 3 {
                continue;
            }
            let archive = |how| {
                write_as(
                    options_at(format, level, false),
                    &[(b"noise.bin", &noise, how), (b"words.txt", &words, how)],
                )
                .0
            };
            let (reader, seekable) = (archive(As::Reader), archive(As::Seekable));
            assert!(
                reader == seekable,
                "{format:?} -m{level}: a source that can seek moved a byte"
            );
            if level == 3 {
                let back = read_back(&seekable);
                assert!(
                    stored(&back[0]) && !stored(&back[1]),
                    "{format:?}: verdicts"
                );
            }
        }
    }
}

/// At or under 32 MiB a reader's samples already span the member, so a
/// source that can seek is NEVER sought there, is not even asked where it
/// stands, and writes a reader's archive: 1 MiB, 2 MiB and exactly 32
/// MiB, of noise, of text and of noise in front of text.
#[test]
fn a_member_within_the_prefix_is_never_sought() {
    let _floor = Floor::low();
    for len in [MIB, 2 * MIB, PREFIX] {
        let mut mixed = Keystream::take(56, len / 2);
        mixed.extend_from_slice(&rarkit_testdata::chatter(57, len - len / 2));
        for data in [
            Keystream::take(58, len),
            rarkit_testdata::chatter(59, len),
            mixed,
        ] {
            let (reader, _) = write_as(
                options_at(WriteFormat::Rar5, 1, false),
                &[(b"m", &data, As::Reader)],
            );
            let (seekable, _, asked) = write_sought(
                options_at(WriteFormat::Rar5, 1, false),
                &[(b"m", &data, As::Seekable)],
            );
            assert!(reader == seekable, "len {len}: a byte moved");
            assert!(
                asked[0].iter().all(|a| matches!(a, Asked::Read(..))),
                "len {len}: the source was sought or asked where it stands"
            );
        }
    }
}

/// What the look costs and what follows it. A member the rule STORES is
/// read at its sixteen samples, each by one seek to where `sample_starts`
/// places it over the whole member, 64 KiB each, in rising order; one it
/// compresses is read no further than the sample that settles it (the
/// second that compresses under 128 MiB, the fifth from there). The source
/// is then returned to the member's start and read exactly once, in order,
/// to its end.
#[test]
fn the_look_reads_the_samples_where_they_lie_and_then_the_member_once() {
    let _floor = Floor::low();
    const SAMPLE: usize = 64 << 10;
    let noise = Keystream::take(60, 64 * MIB);
    let words = rarkit_testdata::chatter(61, 64 * MIB);
    // 128 MiB of noise whose first five samples are text: the fifth
    // settles it.
    let five = with_compressible_samples(62, GATE, &[0, 1, 2, 3, 4]);
    for (label, data, samples) in [
        ("noise", &noise, 16usize),
        ("text", &words, 2),
        ("five of sixteen at 128 MiB", &five, 5),
    ] {
        let len = data.len();
        let (outcome, source) = write_one(
            options_at(WriteFormat::Rar5, 1, false),
            Sought::over(data),
            len as u64,
        );
        let archive = outcome.expect("finish");
        assert_eq!(
            source.asked[0],
            Asked::Where,
            "{label}: asked first where it stands"
        );
        let mut want: Vec<u64> = (0..samples).map(|k| sample_at(len, k) as u64).collect();
        want.push(0);
        assert_eq!(source.seeks(), want, "{label}: the seeks");
        assert_eq!(
            source.looked_at(),
            (samples * SAMPLE) as u64,
            "{label}: the bytes of the look"
        );
        let mut next = 0u64;
        for (at, read) in source.reads_after_the_look() {
            assert_eq!(at, next, "{label}: the member was not read in order");
            next += read as u64;
        }
        assert_eq!(next, len as u64, "{label}: the member was not read once");
        let back = read_back(&[archive]);
        assert_eq!(stored(&back[0]), samples == 16, "{label}: the verdict");
        assert!(back[0].bytes == *data, "{label}: read back");
    }
}

/// The member is the `size` bytes from where the source STANDS to its end,
/// and that need not be the source's start: the samples are sought from
/// there, the source is returned there, and the bytes before it are not
/// the member's.
#[test]
fn a_source_that_stands_past_its_start_is_sampled_from_where_it_stands() {
    let _floor = Floor::low();
    const BEFORE: usize = 3 * MIB + 17;
    let member = noise_then_text(63);
    let mut file = rarkit_testdata::chatter(64, BEFORE);
    file.extend_from_slice(&member);
    let mut source = Sought::over(&file);
    source.at = BEFORE as u64;
    let (outcome, source) = write_one(
        options_at(WriteFormat::Rar5, 1, false),
        source,
        member.len() as u64,
    );
    let archive = outcome.expect("finish");
    let seeks = source.seeks();
    assert_eq!(
        seeks[0],
        (BEFORE + sample_at(member.len(), 0)) as u64,
        "the first sample"
    );
    assert_eq!(seeks.last(), Some(&(BEFORE as u64)), "the return");
    assert!(
        seeks.iter().all(|at| *at >= BEFORE as u64),
        "a seek before the member"
    );
    let back = read_back(&[archive]);
    assert!(!stored(&back[0]), "noise in front of text was stored");
    assert!(back[0].bytes == member, "read back");
}

/// A source that will not seek after all is a READER: one that cannot say
/// where it stands, and one whose first seek fails, are each judged on
/// their head and write the archive a reader writes, nothing read before
/// the member's own read.
#[test]
fn a_source_that_will_not_seek_is_read_as_a_reader() {
    let _floor = Floor::low();
    let member = noise_then_text(66);
    let (reader, _) = write_as(
        options_at(WriteFormat::Rar5, 1, false),
        &[(b"m.bin", &member, As::Reader)],
    );
    for no_position in [true, false] {
        let mut source = Sought::over(&member);
        source.no_position = no_position;
        source.seeks_fail_from = Some(0);
        let (outcome, source) = write_one(
            options_at(WriteFormat::Rar5, 1, false),
            source,
            member.len() as u64,
        );
        assert!(
            outcome.expect("finish") == reader[0],
            "no_position={no_position}: not the reader's archive"
        );
        assert!(source.seeks().is_empty(), "no_position={no_position}");
        let mut next = 0u64;
        for asked in &source.asked {
            if let Asked::Read(at, read) = asked {
                assert_eq!(*at, next, "no_position={no_position}: read out of order");
                next += *read as u64;
            }
        }
        assert_eq!(next, member.len() as u64, "no_position={no_position}");
    }
}

/// Once a sample has been read the source is no longer where it stood, so
/// a LATER seek that fails is an error and not a fallback: a failure
/// between two samples, and a failure of the return to the start.
#[test]
fn a_seek_that_fails_after_the_first_is_an_error() {
    let _floor = Floor::low();
    let noise = Keystream::take(67, 40 * MIB);
    for failing in [1usize, 7, 16] {
        let mut source = Sought::over(&noise);
        source.seeks_fail_from = Some(failing);
        let (outcome, _) = write_one(
            options_at(WriteFormat::Rar5, 1, false),
            source,
            noise.len() as u64,
        );
        let error = outcome
            .err()
            .unwrap_or_else(|| panic!("seek {failing} failed and the write went on"));
        assert_eq!(
            error.member(),
            Some(&b"m.bin"[..]),
            "seek {failing}: the member is not named"
        );
    }
}

/// A source that changes under the writer is read as any reader is. One
/// that ends inside a sample is `Truncated` at the look; one that the look
/// found whole and that ends early at the read is `Truncated` there.
#[test]
fn a_source_that_shrinks_is_truncated() {
    let _floor = Floor::low();
    let noise = Keystream::take(68, 40 * MIB);
    let words = rarkit_testdata::chatter(69, 40 * MIB);
    // The last sample of the noise is cut 1000 bytes in; the text is cut
    // 1000 bytes short of its end, past every sample its vote reads.
    let in_the_last_sample = sample_at(noise.len(), 15) as u64 + 1000;
    for (label, data, ends_at) in [
        ("at the look", &noise, in_the_last_sample),
        ("at the read", &words, words.len() as u64 - 1000),
    ] {
        let mut source = Sought::over(data);
        source.ends_at = Some(ends_at);
        let (outcome, source) = write_one(
            options_at(WriteFormat::Rar5, 1, false),
            source,
            data.len() as u64,
        );
        let error = outcome.err().unwrap_or_else(|| panic!("{label}: written"));
        assert!(
            matches!(error.kind(), rarkit::ErrorKind::Truncated),
            "{label}: {error}"
        );
        // The look names the member it failed on. (A reader that ends
        // early under the read is the control's own path, and is as it was.)
        if label == "at the look" {
            assert_eq!(
                error.member(),
                Some(&b"m.bin"[..]),
                "{label}: the member is not named"
            );
        }
        // Noise reads all sixteen samples and the last passes the end;
        // text is settled by its second sample and fails at the read.
        let at_the_look = source.seeks().last() != Some(&0);
        assert_eq!(
            at_the_look,
            label == "at the look",
            "{label}: where it failed"
        );
    }
}

/// The set shapes: SOLID, a VOLUME set, a solid volume set, any width, a
/// named memory ceiling, and the samples packed in full. In each a source
/// that can seek gives the whole member's verdict (noise in front of text
/// compresses, text in front of noise is stored, where the set stores at
/// all), every member reads back, and the plain and the solid archive do
/// not move with the width.
#[test]
fn the_whole_member_verdict_holds_in_every_set_shape() {
    let _floor = Floor::low();
    let small = rarkit_testdata::chatter(70, 2 * MIB);
    let head_noise = noise_then_text(71);
    let head_text = text_then_noise(73);
    let noise = Keystream::take(75, 34 * MIB);
    let members: Vec<(&[u8], &[u8], As)> = vec![
        (b"small.txt", &small, As::Seekable),
        (b"head-noise.bin", &head_noise, As::Seekable),
        (b"noise.bin", &noise, As::Seekable),
        (b"head-text.bin", &head_text, As::Seekable),
    ];
    type Shape = (&'static str, fn() -> WriteOptions);
    let shapes: [Shape; 7] = [
        ("plain", || options_at(WriteFormat::Rar5, 1, false)),
        ("solid", || options_at(WriteFormat::Rar5, 1, true)),
        ("volumes", || WriteOptions {
            volume_size: Some(24 << 20),
            ..options_at(WriteFormat::Rar5, 1, false)
        }),
        ("solid volumes", || WriteOptions {
            volume_size: Some(24 << 20),
            ..options_at(WriteFormat::Rar5, 1, true)
        }),
        ("a named ceiling", || WriteOptions {
            memory: rarkit::MemoryPolicy::from_limit(1 << 30),
            ..options_at(WriteFormat::Rar5, 1, false)
        }),
        ("packed samples", || {
            packed_samples(options_at(WriteFormat::Rar5, 1, false))
        }),
        ("rar4 solid", || {
            options_at(WriteFormat::Rar4(rarkit::Rar4Version::V29), 1, true)
        }),
    ];
    for (label, shape) in shapes {
        let mut seen: Option<Vec<Vec<u8>>> = None;
        let widths: &[Option<usize>] = if label == "plain" || label == "solid" {
            &[Some(1), Some(4)]
        } else {
            &[None]
        };
        for &workers in widths {
            let mut o = shape();
            o.workers = workers;
            let (volumes, _) = write_as(o, &members);
            match &seen {
                None => {
                    // A solid set is written in its own order: by name.
                    let back = read_back(&volumes);
                    assert_eq!(back.len(), members.len(), "{label}: member count");
                    let verdicts = [false, false, true, true];
                    for ((name, data, _), want_stored) in members.iter().zip(verdicts) {
                        let got = back
                            .iter()
                            .find(|got| got.name == *name)
                            .unwrap_or_else(|| panic!("{label}: a member is missing"));
                        assert!(got.bytes == *data, "{label}: {:?} read back", got.name);
                        assert_eq!(
                            stored(got),
                            want_stored,
                            "{label}: the verdict of {}",
                            String::from_utf8_lossy(name)
                        );
                    }
                    seen = Some(volumes);
                }
                Some(first) => assert!(
                    first == &volumes,
                    "{label}: workers={workers:?} moved a byte"
                ),
            }
        }
    }
}

/// A member the rule stores from a source that can seek holds no head: the
/// look keeps one sample, so the stated peak is no more than a reader's of
/// the same member, which holds its 32 MiB prefix.
#[test]
fn a_stored_seekable_member_states_no_more_than_a_readers() {
    let _floor = Floor::low();
    let noise = Keystream::take(76, 40 * MIB);
    let peak = |how| {
        write_as(
            options_at(WriteFormat::Rar5, 1, false),
            &[(b"noise.bin", &noise, how)],
        )
        .1
        .peak_working_memory
    };
    let (reader, seekable) = (peak(As::Reader), peak(As::Seekable));
    assert!(
        seekable <= reader,
        "a source that can seek stated {seekable}, a reader {reader}"
    );
}

/// Noise of `len` bytes whose whole-member samples `marginal` each hold
/// 900 zero bytes, so that each packs to about 98.7 percent (a miss,
/// barely), and whose samples `words` are text.
fn with_marginal_samples(seed: u64, len: usize, marginal: &[usize], words: &[usize]) -> Vec<u8> {
    let mut member = with_compressible_samples(seed, len, words);
    for &k in marginal {
        member[sample_at(len, k) + 4096..][..900].fill(0);
    }
    member
}

/// The whole-member vote's FLOOR. From 128 MiB, where four samples may
/// compress, a member whose misses pass four is still STORED while the
/// samples taken pack together to 99 percent or more: six samples at
/// about 98.7 percent do not send a big member through the compressor, and the
/// vote reads on to the last sample to say so. A sample that brings the
/// sum under the floor settles it there. Under 128 MiB, and under
/// `store_one_miss`, there is no floor: the second miss decides.
#[test]
fn misses_that_hardly_compress_do_not_compress_a_member_from_128_mib() {
    let _floor = Floor::low();
    let last = |source: &Sought<'_>| source.seeks().len() - 1;
    // Six marginal misses and nothing else: stored, all sixteen read.
    let marginal = with_marginal_samples(80, GATE, &[1, 3, 5, 7, 9, 11], &[]);
    let (outcome, source) = write_one(
        options_at(WriteFormat::Rar5, 1, false),
        Sought::over(&marginal),
        GATE as u64,
    );
    let back = read_back(&[outcome.expect("finish")]);
    assert!(
        stored(&back[0]),
        "six samples at 98.7 percent compressed it"
    );
    assert_eq!(
        last(&source),
        16,
        "the vote did not read on to the last sample"
    );
    assert!(back[0].bytes == marginal, "read back");

    // The rule as it stood until 1 Oct, which the option gives back: the
    // second miss decides, floor or no floor.
    let (outcome, source) = write_one(
        one_miss(options_at(WriteFormat::Rar5, 1, false)),
        Sought::over(&marginal),
        GATE as u64,
    );
    let back = read_back(&[outcome.expect("finish")]);
    assert!(
        !stored(&back[0]),
        "the option did not give the old rule back"
    );
    assert_eq!(
        last(&source),
        4,
        "settled at the second miss, the fourth sample"
    );

    // Five marginal misses among clean samples, and then text: at the
    // fifth miss (the ninth sample) the nine together still pack over the
    // floor, and the text, the tenth, is the first sample at which they
    // do not.
    let then_text = with_marginal_samples(81, GATE, &[0, 2, 4, 6, 8], &[9]);
    let (outcome, source) = write_one(
        options_at(WriteFormat::Rar5, 1, false),
        Sought::over(&then_text),
        GATE as u64,
    );
    let back = read_back(&[outcome.expect("finish")]);
    assert!(!stored(&back[0]), "a sample of text did not settle it");
    assert_eq!(last(&source), 10, "settled at the tenth sample");
    assert!(back[0].bytes == then_text, "read back");

    // One byte under 128 MiB: one miss is allowed and there is no floor.
    let under = with_marginal_samples(82, GATE - 1, &[1, 3, 5, 7, 9, 11], &[]);
    let (outcome, source) = write_one(
        options_at(WriteFormat::Rar5, 1, false),
        Sought::over(&under),
        (GATE - 1) as u64,
    );
    let back = read_back(&[outcome.expect("finish")]);
    assert!(!stored(&back[0]), "a floor was asked under 128 MiB");
    assert_eq!(last(&source), 4, "settled at the second miss");
}

/// The floor itself. With no dial set, a member under 4 GiB from a source
/// that can seek is a READER in every respect: never sought, not even
/// asked where it stands, judged on its first 32 MiB (so noise in front of
/// text is stored, as a reader's is), and its archive is a reader's byte
/// for byte. And the floor is INCLUSIVE: a member exactly at it is voted
/// on across its whole length, one byte under it is not.
#[test]
fn under_the_floor_a_source_that_seeks_is_a_reader() {
    let member = noise_then_text(90);
    // The shipped floor: 38 MiB is far under it.
    let (reader, _) = write_as(
        options_at(WriteFormat::Rar5, 1, false),
        &[(b"m.bin", &member, As::Reader)],
    );
    let (seekable, _, asked) = write_sought(
        options_at(WriteFormat::Rar5, 1, false),
        &[(b"m.bin", &member, As::Seekable)],
    );
    assert!(reader == seekable, "under 4 GiB a byte moved");
    assert!(
        asked[0].iter().all(|a| matches!(a, Asked::Read(..))),
        "under 4 GiB the source was sought or asked where it stands"
    );
    assert!(
        stored(&read_back(&seekable)[0]),
        "a reader's head stores it"
    );

    // The floor at the member's own size takes it; one byte over does not.
    let len = member.len() as u64;
    for (from, sought) in [(len, true), (len + 1, false)] {
        let _floor = Floor::at(from);
        let (outcome, source) = write_one(
            options_at(WriteFormat::Rar5, 1, false),
            Sought::over(&member),
            len,
        );
        let back = read_back(&[outcome.expect("finish")]);
        assert_eq!(!source.seeks().is_empty(), sought, "a floor of {from}");
        assert_eq!(stored(&back[0]), !sought, "a floor of {from}: the verdict");
        assert!(back[0].bytes == member, "a floor of {from}: read back");
    }
}
