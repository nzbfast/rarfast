//! Spec G 3.6: `Layout::Reference` is byte identity with rar 7.23 for a
//! single-volume stored archive. This is the section's own check,
//! `specs/vectors-G/refcheck.py`, shape for shape, with rarkit's writer in
//! the place of the specification's model: the reference writes each
//! shape here and now, rarkit writes the same members, and the two files
//! are compared byte for byte.
//!
//! The shapes carry the rules of 3.6.3 (the locator's reserved width, at
//! its crossing with ten members, with a non-ASCII name and with an empty
//! member beside a full one), 3.6.5 (a whole-second time in the header
//! field), and 3.2 and 3.3 (the header flags of a comment service header,
//! a directory and an empty file).
//!
//! One shape of the 30 is not here: `qo_all` is the reference's `-qo+`,
//! an entry for every member, and `Layout::Reference` carries quick-open
//! on or off and no third setting.
//!
//! Skipped, saying so, off Unix (the reference's output for a Unix host is
//! what is compared) and where no reference `rar` answers. One thread;
//! the largest member is 1 MiB.

use std::path::{Path, PathBuf};
use std::process::Command;

use rarkit::{ChecksumKind, HostOs, Layout, MemberSpec, Payload, Timestamp, WriteOptions, Writer};

const WHEN: i64 = 1_600_000_000;

struct Member {
    name: &'static str,
    /// `None` is a directory.
    size: Option<usize>,
}

fn file(name: &'static str, size: usize) -> Member {
    Member {
        name,
        size: Some(size),
    }
}

#[derive(Default)]
struct Shape {
    label: String,
    members: Vec<Member>,
    /// Switches for `rar a` beyond `-idq -m0 -ep1`.
    switches: Vec<&'static str>,
    nanos: u32,
    comment: Option<&'static [u8]>,
}

fn shape(label: &str, members: Vec<Member>) -> Shape {
    Shape {
        label: label.to_owned(),
        members,
        ..Shape::default()
    }
}

fn shapes() -> Vec<Shape> {
    let mut all = vec![
        shape("one_small", vec![file("a.txt", 6)]),
        shape("one_127", vec![file("a.txt", 127)]),
        shape("one_128", vec![file("a.txt", 128)]),
        shape("one_4096", vec![file("s.bin", 4_096)]),
        shape("one_4097", vec![file("s.bin", 4_097)]),
        shape("cross_65487", vec![file("s.bin", 65_487)]),
        shape("cross_65488", vec![file("s.bin", 65_488)]),
        shape(
            "three",
            vec![file("a.txt", 100), file("b.bin", 9_000), file("c.txt", 10)],
        ),
        shape(
            "with_dir",
            vec![
                file("d/x.txt", 50),
                Member {
                    name: "d",
                    size: None,
                },
            ],
        ),
        shape("w7679", vec![file("s.bin", 7_679)]),
        shape("w7680", vec![file("s.bin", 7_680)]),
        shape("w1048063", vec![file("s.bin", 1_048_063)]),
        shape("w1048064", vec![file("s.bin", 1_048_064)]),
        Shape {
            switches: vec!["-qo-"],
            ..shape("qo_none", vec![file("a.txt", 9_000)])
        },
        shape("mib_step", vec![file("s.bin", 1 << 20)]),
        shape(
            "longname",
            vec![file("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin", 368)],
        ),
        shape(
            "longname_367",
            vec![file("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin", 367)],
        ),
        Shape {
            switches: vec!["-htb"],
            ..shape("htb", vec![file("a.txt", 300)])
        },
        Shape {
            nanos: 250_000_000,
            ..shape("subsecond_time", vec![file("a.txt", 300)])
        },
        Shape {
            switches: vec!["-k"],
            ..shape("lock", vec![file("a.txt", 300)])
        },
        shape("non_ascii_name", vec![file("caf\u{e9}-\u{65e5}.txt", 300)]),
        shape("empty_member", vec![file("e.dat", 0)]),
        Shape {
            switches: vec!["-zc.txt"],
            comment: Some(b"a rarkit comment\n"),
            ..shape("comment", vec![file("a.txt", 300)])
        },
    ];
    // 3.6.3: one byte below the locator width's crossing, and on it.
    const TEN: [&str; 10] = [
        "m000.dat", "m001.dat", "m002.dat", "m003.dat", "m004.dat", "m005.dat", "m006.dat",
        "m007.dat", "m008.dat", "m009.dat",
    ];
    const KANJI: &str = "\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}\u{65e5}.x";
    for (sign, delta) in [("-1", 0usize), ("+0", 1)] {
        let mut ten: Vec<Member> = TEN[..9].iter().map(|name| file(name, 10)).collect();
        ten.push(file(TEN[9], 65_535 - 10 * 56 - 90 - 1 + delta));
        all.push(shape(&format!("ten_members_cross{sign}"), ten));
        all.push(shape(
            &format!("non_ascii_cross{sign}"),
            vec![file(KANJI, 65_535 - 32 - 66 - 1 + delta)],
        ));
        all.push(shape(
            &format!("two_members_cross{sign}"),
            vec![
                file("e.dat", 0),
                file("s.bin", 65_535 - 2 * 32 - 30 - 1 + delta),
            ],
        ));
    }
    all
}

fn pseudo(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

/// A reference binary: a path named in the environment, then `PATH`, then
/// two usual install places.
fn reference(name: &str, env: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os(env) {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(PathBuf::from(name));
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(Path::new(&home).join("bin").join(name));
    }
    candidates.push(Path::new("/opt/homebrew/bin").join(name));
    candidates
        .into_iter()
        .find(|path| Command::new(path).output().is_ok())
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("metadata").mode() & 0xffff
}

#[cfg(not(unix))]
fn mode_of(_path: &Path) -> u32 {
    0
}

fn set_time(path: &Path, nanos: u32) {
    let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(WHEN as u64, nanos);
    let handle = std::fs::File::open(path).expect("open to set the time");
    handle
        .set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("set the time");
}

/// What the reference wrote for `shape`, and what rarkit writes for the
/// same members.
fn both(rar: &Path, root: &Path, shape: &Shape) -> (Vec<u8>, Vec<u8>) {
    let work = root.join(&shape.label);
    std::fs::create_dir_all(&work).unwrap();
    let mut payloads = Vec::new();
    for (index, member) in shape.members.iter().enumerate() {
        let path = work.join(member.name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        match member.size {
            Some(size) => {
                let data = pseudo(0x5eed + index as u64, size);
                std::fs::write(&path, &data).unwrap();
                payloads.push(data);
            }
            None => {
                std::fs::create_dir_all(&path).unwrap();
                payloads.push(Vec::new());
            }
        }
    }
    // Times last, files before the directories that hold them, so that
    // nothing written afterwards moves one.
    for member in &shape.members {
        set_time(&work.join(member.name), shape.nanos);
    }
    if let Some(comment) = shape.comment {
        std::fs::write(work.join("c.txt"), comment).unwrap();
    }

    let archive = work.join("ref.rar");
    let made = Command::new(rar)
        .args(["a", "-idq", "-m0", "-ep1"])
        .args(&shape.switches)
        .arg(&archive)
        .args(shape.members.iter().map(|m| m.name))
        .current_dir(&work)
        .output()
        .expect("rar a");
    assert!(made.status.success(), "{}: rar a: {made:?}", shape.label);
    let theirs = std::fs::read(&archive).unwrap();

    let mut writer = Writer::new(WriteOptions {
        layout: Layout::Reference {
            quick_open: !shape.switches.contains(&"-qo-"),
        },
        host_os: HostOs::Unix,
        checksum: if shape.switches.contains(&"-htb") {
            ChecksumKind::Blake2sp
        } else {
            ChecksumKind::default()
        },
        lock: shape.switches.contains(&"-k"),
        comment: shape.comment.map(<[u8]>::to_vec),
        workers: Some(1),
        ..WriteOptions::default()
    })
    .unwrap_or_else(|e| panic!("{}: options: {e}", shape.label));
    for (member, data) in shape.members.iter().zip(&payloads) {
        writer
            .add(MemberSpec {
                name: member.name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: Some(Timestamp {
                    unix_seconds: WHEN,
                    nanos: shape.nanos,
                }),
                attributes: mode_of(&work.join(member.name)),
                host_os: HostOs::Unix,
                is_directory: member.size.is_none(),
            })
            .unwrap_or_else(|e| panic!("{}: add {}: {e}", shape.label, member.name));
    }
    let mut ours = Vec::new();
    writer
        .finish_into(&mut ours)
        .unwrap_or_else(|e| panic!("{}: finish: {e}", shape.label));
    (theirs, ours)
}

#[test]
fn every_shape_of_the_specification_is_the_references_bytes() {
    if cfg!(not(unix)) {
        eprintln!("SKIPPED: the shapes are reference rar output for a Unix host");
        return;
    }
    let Some(rar) = reference("rar", "RARKIT_REF_RAR") else {
        eprintln!("SKIPPED: no reference rar");
        return;
    };
    let root = std::env::temp_dir().join(format!("rarkit-refshapes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let shapes = shapes();
    assert_eq!(shapes.len(), 29);
    let mut wrong = Vec::new();
    for shape in &shapes {
        let (theirs, ours) = both(&rar, &root, shape);
        if ours != theirs {
            let at = ours
                .iter()
                .zip(&theirs)
                .position(|(a, b)| a != b)
                .unwrap_or(ours.len().min(theirs.len()));
            let from = at.saturating_sub(8);
            let show = |bytes: &[u8]| {
                bytes[from..bytes.len().min(at + 16)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            wrong.push(format!(
                "{}: ours {} bytes, rar {} bytes, first difference at {at:#x}\n   ours {}\n   rar  {}",
                shape.label,
                ours.len(),
                theirs.len(),
                show(&ours),
                show(&theirs),
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        wrong.is_empty(),
        "{} of {} shapes differ from fresh reference output:\n{}",
        wrong.len(),
        shapes.len(),
        wrong.join("\n")
    );
}
