//! Spec G 3.8.3 inside a SOLID set (1 Oct 2026): a solid member of
//! 1 MiB and more whose samples have nothing in them to compress is
//! written STORED where it stands, and it neither starts nor ends the run
//! (spec G 3.9): the member after it continues the history of the member
//! before it. `WriteOptions::solid_store` off keeps every solid member in
//! the compressor.
//!
//! The rows hold four things:
//!
//! - the stored member is stored, the others are not, and every member
//!   reads back to its input, with rarkit's reader and, where they are on
//!   PATH, reference `unrar t` and `rar t`;
//! - THE CHAIN IS KEPT ACROSS IT: a member that repeats the one before the
//!   stored member packs to a fraction of what it packs to alone, which it
//!   could not if the stored member had ended the run or its bytes had
//!   been put in the history's place;
//! - the verdict is a property of the member's bytes: the archive is the
//!   same bytes whether the members arrive as slices or as readers, and at
//!   any width, though a slice is judged as a batch stages it, a reader
//!   beside the flush of the batch before, and a member longer than a
//!   window on its own head;
//! - the option off stores nothing.

use std::io::Read;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, MemoryPolicy, Method, Payload, RangeSource,
    Rar4Version, ReadOptions, Result, Sink, VolumeOut, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};

const MIB: usize = 1 << 20;

/// One member as read back.
struct Back {
    name: Vec<u8>,
    method: Method,
    packed: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Collect {
    members: Vec<Back>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push(Back {
            name: member.name.to_vec(),
            method: member.method,
            packed: member.packed_size,
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

fn read_back(volumes: &[Vec<u8>]) -> Vec<Back> {
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

/// Bytes with no structure: an xorshift stream.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

struct Over<'a>(&'a [u8]);

impl Read for Over<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

fn options(format: WriteFormat, level: u8) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(2 << 20),
        },
        solid: true,
        // In `add` order, so that a row says where each member stands.
        order: rarkit::MemberOrder::AsAdded,
        filters: rarkit::FilterPolicy::Off,
        ..WriteOptions::default()
    }
}

/// Write `members` (name, bytes), all as readers or all as slices.
fn write(options: WriteOptions, members: &[(&[u8], &[u8])], as_readers: bool) -> Vec<Vec<u8>> {
    let volume = options.volume_size.is_some();
    let mut readers: Vec<Over<'_>> = members.iter().map(|m| Over(m.1)).collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, bytes), reader) in members.iter().zip(readers.iter_mut()) {
        let payload = if as_readers {
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
        writer.finish_volumes(&mut out).expect("finish");
        out.kept
    } else {
        let mut out = std::io::Cursor::new(Vec::new());
        writer.finish_seek(&mut out).expect("finish");
        vec![out.into_inner()]
    }
}

fn stored(member: &Back) -> bool {
    matches!(member.method, Method::Stored)
}

const FORMATS: [WriteFormat; 4] = [
    WriteFormat::Rar5,
    WriteFormat::Rar4(Rar4Version::V29),
    WriteFormat::Rar4(Rar4Version::V30),
    WriteFormat::Rar4(Rar4Version::V40),
];

/// Reference `unrar t` and `rar t` over a set, each where it is on PATH;
/// the row says which it ran. Both print a checksum error on stderr and
/// may still exit 0, so stderr must be empty too.
fn reference_tests(volumes: &[Vec<u8>], format: WriteFormat, label: &str) {
    let dir = std::env::temp_dir().join(format!(
        "rarkit-solid-store-{}-{}",
        std::process::id(),
        label.replace(['/', ' '], "-")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut first = None;
    for (index, volume) in volumes.iter().enumerate() {
        let name = if volumes.len() == 1 {
            "set.rar".to_string()
        } else if matches!(format, WriteFormat::Rar5) {
            format!("set.part{}.rar", index + 1)
        } else {
            format!("set.part{:02}.rar", index + 1)
        };
        let path = dir.join(name);
        std::fs::write(&path, volume).unwrap();
        first.get_or_insert(path);
    }
    let first = first.expect("a set has a volume");
    for tool in ["unrar", "rar"] {
        let Ok(output) = std::process::Command::new(tool)
            .arg("t")
            .arg("-idq")
            .arg(&first)
            .output()
        else {
            eprintln!("{label}: SKIPPED the {tool} t arm: {tool} is not on PATH");
            continue;
        };
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "{label}: reference {tool} t refused the set: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// Each member's name with whether its header carries the solid bit, and
/// one member's bytes, as reference `unrar` reads them (`unrar_reads`).
type UnrarRead = (Vec<(String, bool)>, Vec<u8>);

/// What reference `unrar` says of a one-volume RAR 5 archive, where it is
/// on PATH: each member's name with whether its header carries the solid
/// bit (`unrar lt`), and member `print`'s bytes as `unrar p` extracts
/// them. `None` where there is no `unrar`.
fn unrar_reads(archive: &[u8], print: &str, label: &str) -> Option<UnrarRead> {
    let dir = std::env::temp_dir().join(format!(
        "rarkit-solid-store-lt-{}-{}",
        std::process::id(),
        label.replace(['/', ' ', '='], "-")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("set.rar");
    std::fs::write(&path, archive).unwrap();
    let listed = std::process::Command::new("unrar")
        .arg("lt")
        .arg(&path)
        .output();
    let Ok(listed) = listed else {
        eprintln!("{label}: SKIPPED the unrar lt and p arms: unrar is not on PATH");
        std::fs::remove_dir_all(&dir).ok();
        return None;
    };
    let mut members: Vec<(String, bool)> = Vec::new();
    for line in String::from_utf8_lossy(&listed.stdout).lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("Name: ") {
            members.push((name.to_string(), false));
        } else if let Some(flags) = line.strip_prefix("Flags: ") {
            if let Some(last) = members.last_mut() {
                last.1 = flags.contains("solid");
            }
        }
    }
    let printed = std::process::Command::new("unrar")
        .args(["p", "-inul"])
        .arg(&path)
        .arg(print)
        .output()
        .unwrap();
    assert!(printed.status.success(), "{label}: unrar p");
    std::fs::remove_dir_all(&dir).ok();
    Some((members, printed.stdout))
}

/// The set most rows write: text, then noise in several places and of
/// several sizes, each followed by text. Under the 2 MiB dictionary these
/// rows name, a window is 2 MiB: `n-first`, `n-mid`, `n-pair-a`, `n-pair-b`
/// and `n-last` are members a batch may stage (1 to 2 MiB), `n-long` and
/// `n-long-2` are longer than a window, and `n-small` is under the rule's
/// 1 MiB.
fn mixed_set() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut set: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| set.push((name.as_bytes().to_vec(), bytes));
    add("n-first", noise(1, MIB));
    for k in 0..4 {
        add(
            &format!("t{k}"),
            rarkit_testdata::chatter((10 + k) as u64, 400_000 + 4_099 * k as usize),
        );
    }
    add("n-mid", noise(2, MIB + 77_777));
    add("t-after-mid", rarkit_testdata::chatter(20, 500_000));
    add("n-pair-a", noise(3, 2 * MIB));
    add("n-pair-b", noise(4, MIB + 1));
    for k in 0..3 {
        add(
            &format!("u{k}"),
            rarkit_testdata::chatter((30 + k) as u64, 700_000),
        );
    }
    add("n-long", noise(5, 3 * MIB + 12_345));
    add("t-long", rarkit_testdata::chatter(40, 5 * MIB / 2));
    // Two more members longer than a window, each straight after one that
    // is compressed: their heads are judged beside that member's last
    // flush, one to be compressed and one to be stored.
    add("t-long-2", rarkit_testdata::chatter(42, 9 * MIB / 4));
    add("n-long-2", noise(8, 5 * MIB / 2));
    add("n-small", noise(6, MIB - 1));
    add("t-last", rarkit_testdata::chatter(41, 300_000));
    add("n-last", noise(7, MIB + 4_096));
    set
}

fn borrowed(set: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    set.iter()
        .map(|(name, bytes)| (name.as_slice(), bytes.as_slice()))
        .collect()
}

/// Which members of [`mixed_set`] the rule stores.
fn is_stored_noise(name: &[u8]) -> bool {
    name.starts_with(b"n-") && name != b"n-small"
}

fn check_mixed(volumes: &[Vec<u8>], set: &[(Vec<u8>, Vec<u8>)], label: &str) {
    let back = read_back(volumes);
    assert_eq!(back.len(), set.len(), "{label}");
    for (member, (name, bytes)) in back.iter().zip(set) {
        let name_text = String::from_utf8_lossy(name);
        assert_eq!(&member.name, name, "{label}");
        assert_eq!(
            stored(member),
            is_stored_noise(name),
            "{label}: {name_text} stored or not"
        );
        assert!(member.bytes == *bytes, "{label}: {name_text} reads back");
    }
}

/// A solid set with stored members at its start, in its middle, side by
/// side and at its end, at every level and in both families: the noise of
/// 1 MiB and more is stored, the text and the noise under 1 MiB are not,
/// every member reads back, the references accept it, and the archive is
/// the same bytes from slices and from readers.
#[test]
fn stored_members_sit_inside_a_solid_set_at_every_level_and_family() {
    let set = mixed_set();
    let members = borrowed(&set);
    for format in FORMATS {
        for level in 1..=5u8 {
            let label = format!("{format:?} m{level}");
            let slices = write(options(format, level), &members, false);
            check_mixed(&slices, &set, &label);
            reference_tests(&slices, format, &label);
            let readers = write(options(format, level), &members, true);
            assert!(
                slices == readers,
                "{label}: readers and slices wrote different archives"
            );
        }
    }
}

/// The verdict and the bytes do not move with the width: one thread, two,
/// and the caller's pool write the same archive, from readers, whose
/// verdicts are taken beside a flush where there is a pool to take them
/// on.
#[test]
fn the_archive_is_the_same_at_any_width() {
    let set = mixed_set();
    let members = borrowed(&set);
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V30)] {
        for level in [1u8, 5] {
            let wide = write(options(format, level), &members, true);
            for workers in [1usize, 2] {
                let narrow = write(
                    WriteOptions {
                        workers: Some(workers),
                        ..options(format, level)
                    },
                    &members,
                    true,
                );
                assert!(
                    wide == narrow,
                    "{format:?} m{level}: {workers} workers wrote a different archive"
                );
            }
        }
    }
}

/// THE CHAIN IS KEPT ACROSS A STORED MEMBER (spec G 3.9). `first` is
/// noise under the rule's 1 MiB, so it is compressed, to about its own
/// size; `copy` repeats it, with a stored member between them, and packs
/// to a fraction of it, which it can only do out of `first`: its history
/// is the member before the stored one. The stored member is tried as one
/// a batch stages and as one longer than a window AND than the dictionary:
/// there `first` is 3.7 MiB behind `copy` in the files and 0.7 MiB behind
/// it in the history, so the stored bytes were never put in the history's
/// place either. From slices and from readers.
#[test]
fn the_member_after_a_stored_one_continues_the_member_before_it() {
    let first = noise(50, 700_000);
    for format in FORMATS {
        for level in [1u8, 3, 5] {
            for between in [MIB + 5, 3 * MIB] {
                for as_readers in [false, true] {
                    let label = format!("{format:?} m{level} {between} readers={as_readers}");
                    let middle = noise(51, between);
                    let members: [(&[u8], &[u8]); 3] =
                        [(b"first", &first), (b"middle", &middle), (b"copy", &first)];
                    let volumes = write(options(format, level), &members, as_readers);
                    let back = read_back(&volumes);
                    assert!(!stored(&back[0]) && stored(&back[1]) && !stored(&back[2]));
                    assert_eq!(back[1].packed, between as u64, "{label}");
                    assert!(
                        back[0].packed * 10 > first.len() as u64 * 9
                            && back[2].packed * 20 < first.len() as u64,
                        "{label}: the copy packed to {} against {} for the member it repeats",
                        back[2].packed,
                        back[0].packed
                    );
                    for (member, (_, bytes)) in back.iter().zip(members) {
                        assert!(member.bytes == bytes, "{label}");
                    }
                    reference_tests(&volumes, format, &label);
                    // Spec G 3.9: the stored member carries no solid bit,
                    // the compressed member after it does, and reference
                    // unrar extracts that member to its input.
                    if matches!(format, WriteFormat::Rar5) {
                        if let Some((listed, copy)) = unrar_reads(&volumes[0], "copy", &label) {
                            let bits: Vec<bool> = listed.iter().map(|(_, solid)| *solid).collect();
                            assert_eq!(bits, [false, false, true], "{label}: {listed:?}");
                            assert!(copy == first, "{label}: unrar p of the copy");
                        }
                    }
                }
            }
        }
    }
}

/// `WriteOptions::solid_store` off: no solid member is stored, whatever
/// its bytes or its size, at every level and in both families, and the
/// set reads back. (That the option's archives are byte for byte the
/// writer's before the rule reached solid sets is held by the count
/// against the parent's binary, 1 Oct 2026.)
#[test]
fn the_option_off_keeps_every_solid_member_in_the_compressor() {
    let set = mixed_set();
    let members = borrowed(&set);
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V30)] {
        for level in 1..=5u8 {
            let off = WriteOptions {
                solid_store: false,
                ..options(format, level)
            };
            let volumes = write(off, &members, level % 2 == 0);
            let back = read_back(&volumes);
            for (member, (name, bytes)) in back.iter().zip(&set) {
                assert!(
                    !stored(member),
                    "{format:?} m{level}: {} was stored with the option off",
                    String::from_utf8_lossy(name)
                );
                assert!(member.bytes == *bytes);
            }
        }
    }
}

/// A solid VOLUME SET: a stored member is cut across volumes as any stored
/// member is, and the members around it read back; from slices, which a
/// volume set batches, and from readers, which it takes a member at a
/// time.
#[test]
fn stored_members_in_a_solid_volume_set_read_back() {
    let set = mixed_set();
    let members = borrowed(&set);
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V30)] {
        for level in [1u8, 3] {
            for as_readers in [false, true] {
                let label = format!("{format:?} m{level} volumes readers={as_readers}");
                let volumes = write(
                    WriteOptions {
                        volume_size: Some(2_500_000),
                        ..options(format, level)
                    },
                    &members,
                    as_readers,
                );
                assert!(volumes.len() > 3, "{label}");
                check_mixed(&volumes, &set, &label);
                reference_tests(&volumes, format, &label);
            }
        }
    }
}

/// Under a ceiling the caller named the verdicts are the same members,
/// taken one sample at a time on the writing thread, and the set reads
/// back.
#[test]
fn a_named_ceiling_stores_the_same_members() {
    let set = mixed_set();
    let members = borrowed(&set);
    for as_readers in [false, true] {
        let volumes = write(
            WriteOptions {
                memory: MemoryPolicy::from_limit(256 << 20),
                ..options(WriteFormat::Rar5, 3)
            },
            &members,
            as_readers,
        );
        check_mixed(
            &volumes,
            &set,
            &format!("named ceiling readers={as_readers}"),
        );
    }
}

/// A reader that fails part way, as a member a batch would have pulled
/// ahead and sampled: the write ends with that reader's error, as it does
/// with the option off.
#[test]
fn a_failing_reader_ends_the_write_with_its_own_error() {
    struct Fails {
        left: usize,
    }
    impl Read for Fails {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other("the planted failure"));
            }
            let n = buf.len().min(self.left);
            buf[..n].fill(7);
            self.left -= n;
            Ok(n)
        }
    }
    for (solid_store, failing, declared) in [
        (true, 0usize, MIB + 9),
        (true, 2, MIB + 9),
        (false, 2, MIB + 9),
        // Longer than a window: its head is pulled beside the flush of
        // the batch before it.
        (true, 2, 3 * MIB),
        (false, 2, 3 * MIB),
    ] {
        {
            let texts: Vec<Vec<u8>> = (0..4)
                .map(|k| rarkit_testdata::chatter((60 + k) as u64, 600_000))
                .collect();
            let mut readers: Vec<Over<'_>> = texts.iter().map(|t| Over(t)).collect();
            let mut bad = Fails { left: 400_000 };
            let mut writer = Writer::new(WriteOptions {
                solid_store,
                ..options(WriteFormat::Rar5, 1)
            })
            .expect("options");
            let mut bad = Some(&mut bad);
            let names: Vec<String> = (0..texts.len()).map(|k| format!("m{k}")).collect();
            for (index, reader) in readers.iter_mut().enumerate() {
                let payload = if index == failing {
                    Payload::Reader {
                        reader: bad.take().expect("one failing member"),
                        size: declared as u64,
                        crc32: None,
                    }
                } else {
                    Payload::Reader {
                        reader,
                        size: 600_000,
                        crc32: None,
                    }
                };
                writer
                    .add(MemberSpec {
                        name: names[index].as_bytes(),
                        payload,
                        mtime: None,
                        attributes: 0,
                        host_os: rarkit::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let mut out = std::io::Cursor::new(Vec::new());
            let error = writer.finish_seek(&mut out).err().unwrap_or_else(|| {
                panic!("solid_store={solid_store} failing={failing} {declared}: wrote")
            });
            assert!(
                !matches!(error.kind(), rarkit::ErrorKind::Truncated),
                "solid_store={solid_store} failing={failing} {declared}: {error}"
            );
        }
    }
}
