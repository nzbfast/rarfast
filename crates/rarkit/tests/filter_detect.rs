//! Spec G 3.8.2: `FilterPolicy::Detect` on the RAR 5 writer, and spec H3
//! section 6.6: the filter record the encoder writes for it.
//!
//! Three verdicts, in the order spec H3 6.1 ranks them:
//!
//! - reference `unrar` 7.23 TESTS and EXTRACTS every archive here byte for
//!   byte, where it is on PATH (the verdict that matters: a writer and a
//!   reader that agree with each other and not with the format is the
//!   defect that section exists to catch);
//! - rarkit's own reader gives every member back byte for byte;
//! - the filter actually FIRES where a transform pays (the archive is
//!   smaller than the same write with `FilterPolicy::Off`), and on data
//!   where none pays the archive is BYTE IDENTICAL to the `Off` one, which
//!   is the proof that detection that finds nothing changes nothing.
//!
//! The corpora are generated from a seed, so every failure reproduces.

use std::io::Write as _;
use std::process::Command;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, Payload,
    RangeSource, ReadOptions, Sink, WriteMethod, WriteOptions, Writer,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        // xorshift64*, enough for test corpora.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }
}

/// ARM-like code: 32-bit words, a third of them BL instructions to a
/// small set of absolute targets, counted in words from their own
/// position as a linker writes them.
fn arm_code(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let words = len / 4;
    let targets: Vec<u32> = (0..48).map(|_| rng.next() % words as u32).collect();
    let fillers: Vec<u32> = (0..64)
        .map(|_| rng.next() & 0x0fff_ffff | 0xe000_0000)
        .collect();
    let mut out = Vec::with_capacity(len);
    for index in 0..words as u32 {
        let word = if rng.next().is_multiple_of(3) {
            let target = targets[(rng.next() % targets.len() as u32) as usize];
            0xeb00_0000 | (target.wrapping_sub(index) & 0x00ff_ffff)
        } else {
            fillers[(rng.next() % fillers.len() as u32) as usize]
        };
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

/// Interleaved 16-bit PCM, `channels` channels of slow tones with a
/// little noise: the shape the delta filter exists for.
fn pcm(len: usize, channels: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut phase = vec![0i32; channels];
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        for (c, phase) in phase.iter_mut().enumerate() {
            *phase = (*phase + 3 + c as i32 * 2) % 2048;
            let triangle = if *phase < 1024 { *phase } else { 2048 - *phase };
            let level = (triangle - 512) * 24 + (rng.next() % 64) as i32 - 32;
            out.extend_from_slice(&(level as i16).to_le_bytes());
        }
    }
    out.truncate(len);
    out
}

/// A raw RGB image of smooth gradients with a little noise.
fn rgb(width: usize, height: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        for x in 0..width {
            let noise = (rng.next() % 5) as usize;
            out.push(((x * 255 / width) + noise) as u8);
            out.push(((y * 255 / height) + noise) as u8);
            out.push((((x + y) * 127 / (width + height)) + noise) as u8);
        }
    }
    out
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..len).map(|_| rng.next() as u8).collect()
}

fn options(level: u8, filters: FilterPolicy, solid: bool) -> WriteOptions {
    WriteOptions {
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        filters,
        solid,
        ..WriteOptions::default()
    }
}

/// Write `members` with `options`; `readers` sends every member through
/// `Payload::Reader`, which takes the windowed path.
fn write(options: WriteOptions, members: &[(String, Vec<u8>)], readers: bool) -> Vec<u8> {
    let mut cursors: Vec<std::io::Cursor<&[u8]>> = members
        .iter()
        .map(|(_, data)| std::io::Cursor::new(&data[..]))
        .collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, data), cursor) in members.iter().zip(cursors.iter_mut()) {
        let payload = if readers {
            Payload::Reader {
                reader: cursor,
                size: data.len() as u64,
                crc32: None,
            }
        } else {
            Payload::Bytes(data)
        };
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload,
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1.extend_from_slice(&bytes);
        }
        Ok(())
    }
}

struct NoProgress;

impl rarkit::Progress for NoProgress {}

/// rarkit's own reader gives every member back, matched BY NAME: a solid
/// compressed set is written in the by-type order `WriteOptions::order`
/// chooses, not the order the members were added in.
fn reads_back(archive: &[u8], members: &[(String, Vec<u8>)], what: &str) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut NoProgress)
        .unwrap_or_else(|e| panic!("{what}: rarkit could not read it back: {e}"));
    assert_eq!(sink.members.len(), members.len(), "{what}: member count");
    for (name, data) in members {
        let got = sink
            .members
            .iter()
            .find(|(got_name, _)| got_name[..] == *name.as_bytes())
            .unwrap_or_else(|| panic!("{what}: {name} is missing"));
        assert!(&got.1 == data, "{what}: {name} came back different");
    }
}

fn unrar() -> bool {
    Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Reference `unrar` tests the archive and extracts every member byte for
/// byte. Returns false, and says so, where unrar is not on PATH.
fn unrar_admits(archive: &[u8], members: &[(String, Vec<u8>)], what: &str) -> bool {
    if !unrar() {
        eprintln!("reference unrar is not on PATH: {what} not admitted");
        return false;
    }
    let dir = std::env::temp_dir().join(format!(
        "rarkit-filter-detect-{}-{}",
        what.replace(|c: char| !c.is_ascii_alphanumeric(), "-"),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    let path = dir.join("test.rar");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(archive))
        .expect("the archive");
    for verb in ["t", "x"] {
        let run = Command::new("unrar")
            .args([verb, "-y", "-idq"])
            .arg(&path)
            .current_dir(&dir)
            .output()
            .expect("unrar runs");
        assert!(
            run.status.success(),
            "{what}: unrar {verb} refused it\n{}\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
    for (name, data) in members {
        let got = std::fs::read(dir.join(name)).expect("an extracted member");
        assert!(&got == data, "{what}: unrar extracted {name} differently");
    }
    let _ = std::fs::remove_dir_all(&dir);
    true
}

/// Every verdict for one set of members under one shape.
fn check(
    what: &str,
    members: &[(String, Vec<u8>)],
    level: u8,
    solid: bool,
    readers: bool,
) -> (usize, usize) {
    let detect = write(
        options(level, FilterPolicy::Detect, solid),
        members,
        readers,
    );
    let off = write(options(level, FilterPolicy::Off, solid), members, readers);
    reads_back(&detect, members, what);
    unrar_admits(&detect, members, what);
    (detect.len(), off.len())
}

fn one(name: &str, data: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    vec![(name.to_string(), data)]
}

#[test]
fn x86_code_is_filtered_and_round_trips() {
    for level in [2, 3, 5] {
        let members = one("code.bin", rarkit_testdata::machine_like(0x86, 1 << 20));
        let (detect, off) = check(&format!("x86-m{level}"), &members, level, false, false);
        assert!(
            detect * 100 < off * 97,
            "x86 at level {level}: {detect} against {off} unfiltered"
        );
    }
}

#[test]
fn arm_code_is_filtered_and_round_trips() {
    let members = one("code.arm", arm_code(1 << 20, 0xa4));
    let (detect, off) = check("arm-m3", &members, 3, false, false);
    assert!(
        detect * 100 < off * 97,
        "arm: {detect} against {off} unfiltered"
    );
}

#[test]
fn audio_and_images_take_a_delta_and_round_trip() {
    for (what, data) in [
        ("pcm-stereo", pcm(1 << 20, 2, 7)),
        ("pcm-six", pcm(3 << 19, 6, 8)),
        ("rgb", rgb(640, 480, 9)),
    ] {
        let members = one("media.raw", data);
        let (detect, off) = check(what, &members, 3, false, false);
        assert!(
            detect * 100 < off * 97,
            "{what}: {detect} against {off} unfiltered"
        );
    }
}

#[test]
fn where_no_filter_pays_the_archive_is_the_unfiltered_one() {
    for (what, data) in [
        ("text", rarkit_testdata::chatter(3, 1 << 20)),
        ("noise", noise(1 << 20, 4)),
    ] {
        let members = one("plain.dat", data);
        let detect = write(options(3, FilterPolicy::Detect, false), &members, false);
        let off = write(options(3, FilterPolicy::Off, false), &members, false);
        assert!(
            detect == off,
            "{what}: detection that found nothing changed the archive"
        );
        reads_back(&detect, &members, what);
    }
}

#[test]
fn a_filtered_member_round_trips_in_every_shape() {
    // Longer than one window at the default dictionary, so a reader
    // payload is encoded a window at a time and a span's transform is
    // measured from its member offset, not its window's.
    let long = rarkit_testdata::machine_like(0x5a, 5 << 20);
    let members = vec![
        ("a.txt".to_string(), rarkit_testdata::chatter(1, 300 << 10)),
        ("b.exe".to_string(), long.clone()),
        ("c.wav".to_string(), pcm(700 << 10, 2, 2)),
        ("d.arm".to_string(), arm_code(200 << 10, 3)),
    ];
    for (solid, readers) in [(false, false), (false, true), (true, false), (true, true)] {
        let what = format!("shapes-solid{solid}-readers{readers}");
        let (detect, off) = check(&what, &members, 3, solid, readers);
        assert!(detect < off, "{what}: {detect} against {off} unfiltered");
    }
}

#[test]
fn many_small_filtered_members_round_trip() {
    // A non-solid set of small members is encoded by the worker team.
    let members: Vec<(String, Vec<u8>)> = (0..40)
        .map(|index| {
            let data = match index % 3 {
                0 => rarkit_testdata::machine_like(index, 20 << 10),
                1 => pcm(24 << 10, 2, index),
                _ => rarkit_testdata::chatter(index, 10 << 10),
            };
            (format!("m{index:02}.bin"), data)
        })
        .collect();
    check("small-team", &members, 3, false, false);
    check("small-solid", &members, 3, true, false);
}

#[test]
fn a_tiny_member_and_a_ragged_tail_round_trip() {
    for len in [1, 5, 600, 16 << 10, (256 << 10) + 3, (512 << 10) - 1] {
        let members = one("t.bin", rarkit_testdata::machine_like(len as u64, len));
        check(&format!("ragged-{len}"), &members, 3, false, false);
    }
}

#[test]
fn detection_is_deterministic() {
    let members = vec![
        (
            "b.exe".to_string(),
            rarkit_testdata::machine_like(11, 2 << 20),
        ),
        ("c.wav".to_string(), pcm(1 << 20, 4, 12)),
    ];
    let first = write(options(3, FilterPolicy::Detect, false), &members, false);
    for _ in 0..3 {
        assert!(
            write(options(3, FilterPolicy::Detect, false), &members, false) == first,
            "the same input gave different archives"
        );
    }
}

#[test]
fn six_channel_and_24_bit_audio_are_found_by_the_lag_screen() {
    // 24-bit stereo wants a delta of 6 and six channels of 16 bits one of
    // 12; stage one's deltas of 1, 2 and 4 lose to the unfiltered bytes on
    // both, so only the lag screen reaches them.
    for (what, data) in [
        ("wav24", pcm24(1 << 20, 2, 31)),
        ("six16", pcm_noisy(3 << 19, 6, 32)),
    ] {
        let members = one("audio.raw", data);
        let (detect, off) = check(what, &members, 3, false, false);
        assert!(
            detect * 100 < off * 95,
            "{what}: {detect} against {off} unfiltered"
        );
    }
}

/// 24-bit PCM, slow tones plus noise in the low byte.
fn pcm24(len: usize, channels: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(len + 8);
    let mut n = 0i64;
    while out.len() < len {
        for c in 0..channels as i64 {
            let phase = (n * (5 + 2 * c)) % 4096;
            let triangle = if phase < 2048 { phase } else { 4096 - phase };
            let sample = (triangle - 1024) * 3000 + i64::from(rng.next() % 512) - 256;
            out.extend_from_slice(&(sample as i32).to_le_bytes()[..3]);
        }
        n += 1;
    }
    out.truncate(len);
    out
}

/// 16-bit PCM whose low bytes are noise, so neighbouring bytes of a frame
/// do not predict each other and only the same channel's previous sample
/// does.
fn pcm_noisy(len: usize, channels: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(len + 16);
    let mut n = 0i32;
    while out.len() < len {
        for c in 0..channels as i32 {
            let phase = (n * (3 + 5 * c)) % 2048;
            let triangle = if phase < 1024 { phase } else { 2048 - phase };
            let sample =
                (triangle - 512) * 40 * (c + 1) / channels as i32 + (rng.next() % 256) as i32 - 128;
            out.extend_from_slice(&(sample as i16).to_le_bytes());
        }
        n += 1;
    }
    out.truncate(len);
    out
}

#[test]
fn level_one_writes_no_filter() {
    // Decided 27 Sep 2026, "like rar": level 1 filters nothing,
    // so every member there is the unfiltered archive, byte for byte,
    // media and code included.
    for (what, data) in [
        ("pcm", pcm(1 << 20, 2, 41)),
        ("rgb", rgb(320, 240, 42)),
        ("x86", rarkit_testdata::machine_like(43, 1 << 20)),
    ] {
        let members = one("m.bin", data);
        let detect = write(options(1, FilterPolicy::Detect, false), &members, false);
        let off = write(options(1, FilterPolicy::Off, false), &members, false);
        assert!(detect == off, "{what}: level 1 filtered something");
    }
}

#[test]
fn filtered_members_at_the_default_dictionary_hand_their_transforms_away() {
    // The short ring form of the tape path's drain (SPEC-H2 3.6; the
    // filter layout work, 28 Sep 2026). The default dictionary, 2 MiB,
    // has a ring under four drain batches, which until then ran every
    // transform on the apply thread. Its members must now hand their
    // transforms to the pool, and come back byte for byte on the tape
    // path, on the serial path and through the public read.
    for (what, data) in [
        ("six16", pcm_noisy(4 << 20, 6, 61)),
        ("x86", rarkit_testdata::machine_like(62, 4 << 20)),
        ("stereo", pcm(3 << 20, 2, 63)),
    ] {
        let members = one("m.bin", data);
        let archive = write(options(3, FilterPolicy::Detect, false), &members, false);
        let off = write(options(3, FilterPolicy::Off, false), &members, false);
        assert!(archive.len() < off.len(), "{what}: no filter fired");
        let (tape, sealed) = rarkit::internals::rar5::filter_batches_sealed(&archive)
            .unwrap_or_else(|e| panic!("{what}: the tape path failed: {e}"));
        assert!(
            tape.len() == 1 && tape[0] == members[0].1,
            "{what}: tape path bytes"
        );
        assert!(
            sealed > 1,
            "{what}: no transform was handed away ({sealed})"
        );
        let serial = rarkit::internals::rar5::extract(&archive, false)
            .unwrap_or_else(|e| panic!("{what}: the serial path failed: {e}"));
        assert!(serial[0].1 == members[0].1, "{what}: serial path bytes");
        let (_, unfiltered) = rarkit::internals::rar5::filter_batches_sealed(&off).unwrap();
        assert_eq!(
            unfiltered, 0,
            "{what}: an unfiltered member handed something"
        );
        reads_back(&archive, &members, what);
    }
}
