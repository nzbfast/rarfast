//! Member names built to act on a terminal, several in one archive, as
//! `l`, `v`, `lb`, `lt`, `t`, `x` and `e` print them on macOS and Linux
//! (SPEC-CLI section 10, rules T3 to T5; section 7, rules P1 to P3).
//!
//! The class: a stored name holding an escape sequence, a carriage
//! return, backspaces, a line feed, a C1 control or a NUL, so that what
//! a terminal shows differs from the name acted on, or a member is
//! hidden from a listing. On a terminal every such character is its
//! stand-in `<U+XXXX>` and an escape is `'\033'`, so no byte a terminal
//! acts on is written for any name, on either stream, and every member
//! is still shown. Through a pipe a control character is its own byte
//! (T5, as unrar 7.23 writes it) and an escape is `'\033'` (T4). A NUL
//! ends a name, in what is shown and in what is written alike, so the
//! two never differ. A plain ASCII name is printed as it is.
//!
//! Each archive is built here (spec F 3.2 for RAR 5, the RAR 1.5 to 4
//! block layout for RAR 4): every member is stored and two bytes long.
//! Each run is one process of one thread's work; no pool width and no
//! memory beyond the tool's floor is assumed.

#![cfg(unix)]

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

const DATA: &[u8] = b"0\n";

/// One RAR 5 block: CRC32, size, then `body` (spec F 3.2.2), then `data`.
fn block5(body: &[u8], data: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(body);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
}

/// A stored RAR 5 archive from a Unix host, one two-byte file for each
/// name. `sound` false stores a CRC32 the data does not have, so every
/// member fails its check.
fn rar5(names: &[&[u8]], sound: bool) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block5(&[1, 0, 0], &[], &mut out);
    for name in names {
        let mut body = Vec::new();
        vint(2, &mut body); // file header
        vint(0x0002, &mut body); // a data area follows
        vint(DATA.len() as u64, &mut body);
        vint(0x0006, &mut body); // mtime and CRC32 present
        vint(DATA.len() as u64, &mut body);
        vint(0o100_644, &mut body);
        body.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
        let check = if sound { crc32(DATA) } else { !crc32(DATA) };
        body.extend_from_slice(&check.to_le_bytes());
        vint(0, &mut body); // stored
        vint(1, &mut body); // host: Unix
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name);
        block5(&body, DATA, &mut out);
    }
    block5(&[5, 0, 0], &[], &mut out);
    out
}

/// One RAR 4 block: the low half of the CRC32 of everything after the
/// check, the type, the flags, the size, then the rest of the header.
fn block4(kind: u8, flags: u16, rest: &[u8], out: &mut Vec<u8>) {
    let mut header = vec![kind];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&u16::try_from(rest.len() + 7).unwrap().to_le_bytes());
    header.extend_from_slice(rest);
    out.extend_from_slice(&(crc32(&header) as u16).to_le_bytes());
    out.extend_from_slice(&header);
}

/// A stored RAR 4 archive (version 2.9) from a Unix host, one two-byte
/// file for each 8-bit name.
fn rar4(names: &[&[u8]], sound: bool) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    block4(0x73, 0, &[0; 6], &mut out);
    for name in names {
        let mut rest = Vec::new();
        rest.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
        rest.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
        rest.push(3); // host: Unix
        let check = if sound { crc32(DATA) } else { !crc32(DATA) };
        rest.extend_from_slice(&check.to_le_bytes());
        rest.extend_from_slice(&0x5A21_0000_u32.to_le_bytes()); // 2025-01-01
        rest.push(29);
        rest.push(0x30); // stored
        rest.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        rest.extend_from_slice(&0o100_644_u32.to_le_bytes());
        rest.extend_from_slice(name);
        block4(0x74, 0x8000, &rest, &mut out);
        out.extend_from_slice(DATA);
    }
    block4(0x7B, 0x4000, &[], &mut out);
    out
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-hostile-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A pseudo terminal with output processing off: the end the reader
/// keeps, and the end the tool writes to.
#[allow(unsafe_code)]
fn terminal() -> (std::fs::File, OwnedFd) {
    let (mut reader, mut writer) = (0, 0);
    // SAFETY: openpty fills the two descriptors or fails; the three
    // null pointers ask for no name and the default settings.
    let made = unsafe {
        libc::openpty(
            &mut reader,
            &mut writer,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(made, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: `writer` is the open terminal end just made; the settings
    // are read into a zeroed struct, made raw, and written back.
    unsafe {
        let mut settings: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(writer, &mut settings), 0);
        libc::cfmakeraw(&mut settings);
        assert_eq!(libc::tcsetattr(writer, libc::TCSANOW, &settings), 0);
    }
    // SAFETY: both descriptors are open and owned by nothing else.
    unsafe {
        (
            std::fs::File::from_raw_fd(reader),
            OwnedFd::from_raw_fd(writer),
        )
    }
}

/// Everything `from` gives until the other end is closed. A terminal's
/// reader ends with an error on Linux and with no bytes on macOS.
fn drain(mut from: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut all = Vec::new();
        let mut piece = [0_u8; 4096];
        loop {
            match from.read(&mut piece) {
                Ok(0) | Err(_) => return all,
                Ok(n) => all.extend_from_slice(&piece[..n]),
            }
        }
    })
}

/// What one run wrote to each stream.
struct Said {
    out: Vec<u8>,
    err: Vec<u8>,
}

/// `rarfast <args>` in `dir`, both streams terminals or both pipes.
fn run(dir: &Path, args: &[&str], terminals: bool) -> Said {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rarfast"));
    command
        .args(args)
        .current_dir(dir)
        .env("TZ", "UTC")
        .stdin(Stdio::null());
    let mut readers = [None, None];
    for (slot, kept) in readers.iter_mut().enumerate() {
        let stream = if terminals {
            let (reader, writer) = terminal();
            *kept = Some(drain(reader));
            Stdio::from(writer)
        } else {
            Stdio::piped()
        };
        if slot == 0 {
            command.stdout(stream);
        } else {
            command.stderr(stream);
        }
    }
    let mut child = command.spawn().unwrap();
    // The command still holds the tool's ends of the terminals; they
    // must close here or a reader never sees the end.
    drop(command);
    if let Some(pipe) = child.stdout.take() {
        readers[0] = Some(drain(pipe));
    }
    if let Some(pipe) = child.stderr.take() {
        readers[1] = Some(drain(pipe));
    }
    child.wait().unwrap();
    let [out, err] = readers.map(|reader| reader.unwrap().join().unwrap());
    Said { out, err }
}

fn holds(all: &[u8], part: &[u8]) -> bool {
    all.windows(part.len()).any(|w| w == part)
}

/// How many times `part` stands in `all`, not overlapping.
fn count(all: &[u8], part: &[u8]) -> usize {
    let (mut found, mut at) = (0, 0);
    while at + part.len() <= all.len() {
        if all[at..].starts_with(part) {
            found += 1;
            at += part.len();
        } else {
            at += 1;
        }
    }
    found
}

/// Every byte in `stream` that a terminal acts on, with where it is: a
/// C0 control but the line feed that ends a line, DEL, and the two
/// bytes of a C1 control's UTF-8. The tool's own backspaces, which step
/// back over its percent field on a terminal, are left out: a run of
/// them follows a space or a `%`, where a name's own would follow the
/// name's text.
fn acting_bytes(stream: &[u8]) -> Vec<(usize, u8)> {
    let mut found = Vec::new();
    let mut own_run = false;
    for (at, &b) in stream.iter().enumerate() {
        let c1 = b == 0xC2 && matches!(stream.get(at + 1), Some(0x80..=0x9F));
        if b == 0x08 {
            let after = if at > 0 { stream[at - 1] } else { b'\n' };
            own_run = matches!(after, b' ' | b'%') || (after == 0x08 && own_run);
            if own_run {
                continue;
            }
        }
        if (b < 0x20 && b != b'\n') || b == 0x7F || c1 {
            found.push((at, b));
        }
    }
    found
}

/// One member: its stored name, what a terminal is sent for it, what a
/// stream that is not a terminal is sent for it, and the name written
/// to disk by `x`.
struct Member {
    stored: &'static [u8],
    on_terminal: &'static [u8],
    off_terminal: &'static [u8],
    on_disk: &'static [u8],
}

/// The members, each name unique on every stream so a count of it
/// counts that member alone.
const MEMBERS: [Member; 7] = [
    Member {
        stored: b"plain.txt",
        on_terminal: b"plain.txt",
        off_terminal: b"plain.txt",
        on_disk: b"plain.txt",
    },
    // Erase the line and go up one: hides the member and the one above.
    Member {
        stored: b"esc\x1b[2K\x1b[1Ahid.txt",
        on_terminal: b"esc'\\033'[2K'\\033'[1Ahid.txt",
        off_terminal: b"esc'\\033'[2K'\\033'[1Ahid.txt",
        on_disk: b"esc\x1b[2K\x1b[1Ahid.txt",
    },
    // Back to the line's start and overwrite: `forged.txt` is seen.
    Member {
        stored: b"real.exe\rforged.txt",
        on_terminal: b"real.exe<U+000D>forged.txt",
        off_terminal: b"real.exe\rforged.txt",
        on_disk: b"real.exe\rforged.txt",
    },
    Member {
        stored: b"bs.exe\x08\x08\x08\x08txt",
        on_terminal: b"bs.exe<U+0008><U+0008><U+0008><U+0008>txt",
        off_terminal: b"bs.exe\x08\x08\x08\x08txt",
        on_disk: b"bs.exe\x08\x08\x08\x08txt",
    },
    // A line feed: one member read as two.
    Member {
        stored: b"nl\ninjected.txt",
        on_terminal: b"nl<U+000A>injected.txt",
        off_terminal: b"nl\ninjected.txt",
        on_disk: b"nl\ninjected.txt",
    },
    // CSI as one C1 character.
    Member {
        stored: "csi\u{9b}2Jx".as_bytes(),
        on_terminal: b"csi<U+009B>2Jx",
        off_terminal: "csi\u{9b}2Jx".as_bytes(),
        on_disk: "csi\u{9b}2Jx".as_bytes(),
    },
    // A NUL ends the name both where it is shown and where it is written.
    Member {
        stored: b"nul.txt\0.exe",
        on_terminal: b"nul.txt",
        off_terminal: b"nul.txt",
        on_disk: b"nul.txt",
    },
];

fn names() -> Vec<&'static [u8]> {
    MEMBERS.iter().map(|m| m.stored).collect()
}

/// Both families, each archive sound or every member failing its check.
fn archives(sound: bool) -> [(&'static str, Vec<u8>); 2] {
    [
        ("rar5", rar5(&names(), sound)),
        ("rar4", rar4(&names(), sound)),
    ]
}

const COMMANDS: [&str; 7] = ["l", "v", "lb", "lt", "t", "x", "e"];

/// On a terminal, no stream holds a byte a terminal acts on, and every
/// member is shown in its stand-in form; `lb` gives one line a member.
#[test]
fn on_a_terminal_no_name_writes_a_byte_the_terminal_acts_on() {
    let mut wrong = Vec::new();
    for (family, archive) in archives(true) {
        for cmd in COMMANDS {
            let dir = work(&format!("term-{family}-{cmd}"));
            std::fs::write(dir.join("arc.rar"), &archive).unwrap();
            let said = run(&dir, &[cmd, "-y", "arc.rar"], true);
            for (stream, what) in [(&said.out, "stdout"), (&said.err, "stderr")] {
                let acting = acting_bytes(stream);
                if !acting.is_empty() {
                    wrong.push(format!(
                        "{family} {cmd} {what}: acting bytes {acting:?} in {:?}",
                        String::from_utf8_lossy(stream)
                    ));
                }
                if holds(stream, b"\x1b") {
                    wrong.push(format!("{family} {cmd} {what}: a raw ESC"));
                }
            }
            for m in &MEMBERS {
                if !holds(&said.out, m.on_terminal) {
                    wrong.push(format!(
                        "{family} {cmd}: {:?} not shown as {:?} in {:?}",
                        String::from_utf8_lossy(m.stored),
                        String::from_utf8_lossy(m.on_terminal),
                        String::from_utf8_lossy(&said.out)
                    ));
                }
            }
            if cmd == "lb" {
                let lines = said
                    .out
                    .split(|&b| b == b'\n')
                    .filter(|l| !l.is_empty())
                    .count();
                if lines != MEMBERS.len() {
                    wrong.push(format!(
                        "{family} lb: {lines} lines for {} members: {:?}",
                        MEMBERS.len(),
                        String::from_utf8_lossy(&said.out)
                    ));
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A member that fails its check is named on standard error (and under
/// `t` on standard output): on a terminal, with nothing that acts.
#[test]
fn on_a_terminal_an_error_line_writes_no_byte_the_terminal_acts_on() {
    let mut wrong = Vec::new();
    for (family, archive) in archives(false) {
        for cmd in ["t", "x", "e"] {
            let dir = work(&format!("bad-{family}-{cmd}"));
            std::fs::write(dir.join("arc.rar"), &archive).unwrap();
            let said = run(&dir, &[cmd, "-y", "arc.rar"], true);
            for (stream, what) in [(&said.out, "stdout"), (&said.err, "stderr")] {
                let acting = acting_bytes(stream);
                if !acting.is_empty() || holds(stream, b"\x1b") {
                    wrong.push(format!(
                        "{family} {cmd} {what}: acting bytes {acting:?} in {:?}",
                        String::from_utf8_lossy(stream)
                    ));
                }
            }
            for m in &MEMBERS[1..6] {
                if !holds(&said.err, m.on_terminal) {
                    wrong.push(format!(
                        "{family} {cmd}: stderr does not name {:?}: {:?}",
                        String::from_utf8_lossy(m.on_terminal),
                        String::from_utf8_lossy(&said.err)
                    ));
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Through pipes each name is its own bytes but for ESC, which is
/// `'\033'` (T4, T5), and a plain name is as it is; `lb` names each
/// member exactly once.
#[test]
fn through_a_pipe_a_name_is_its_bytes_but_an_escape() {
    let mut wrong = Vec::new();
    for (family, archive) in archives(true) {
        for cmd in COMMANDS {
            let dir = work(&format!("pipe-{family}-{cmd}"));
            std::fs::write(dir.join("arc.rar"), &archive).unwrap();
            let said = run(&dir, &[cmd, "-y", "arc.rar"], false);
            for stream in [&said.out, &said.err] {
                if holds(stream, b"\x1b") {
                    wrong.push(format!("{family} {cmd}: a raw ESC"));
                }
                if holds(stream, b".exe\0") || holds(stream, b"\0") {
                    wrong.push(format!("{family} {cmd}: a NUL or what follows it"));
                }
            }
            for m in &MEMBERS {
                let want = if cmd == "lb" { 1 } else { 0 };
                let seen = count(&said.out, m.off_terminal);
                if seen == 0 || (want == 1 && seen != 1) {
                    wrong.push(format!(
                        "{family} {cmd}: {:?} seen {seen} times in {:?}",
                        String::from_utf8_lossy(m.off_terminal),
                        String::from_utf8_lossy(&said.out)
                    ));
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The check above finds a name's own control bytes beside the tool's
/// backspaces, so a pass of it is not an empty one.
#[test]
fn the_check_finds_a_planted_control_byte() {
    let line = b"Testing     bs.exe\x08\x08txt    \x08\x08\x08\x08 17%\x08\x08\x08\x08\x08  OK \n";
    assert_eq!(acting_bytes(line), [(18, 8), (19, 8)]);
    assert_eq!(acting_bytes(b"real.exe\rforged.txt\n"), [(8, b'\r')]);
    assert_eq!(acting_bytes(b"a\x1bb"), [(1, 0x1b)]);
    assert_eq!(acting_bytes("c\u{9b}x".as_bytes()), [(1, 0xC2)]);
    assert_eq!(acting_bytes(b"a\x7fb\0"), [(1, 0x7f), (3, 0)]);
    assert!(acting_bytes(b"plain.txt <U+000D> '\\033'\n").is_empty());
}

/// The other lines that name a member, on a terminal: the overwrite
/// question, a member that cannot be created, `a` adding files whose
/// names on disk are the hostile ones, and an encrypted member's
/// password question, each with nothing that acts.
#[test]
fn on_a_terminal_other_lines_that_name_a_member_write_nothing_that_acts() {
    fn check(wrong: &mut Vec<String>, what: &str, said: &Said) {
        // A run that named no member would pass the rest unseen.
        let named = b"real.exe<U+000D>forged.txt";
        if !holds(&said.out, named) && !holds(&said.err, named) {
            wrong.push(format!(
                "{what}: no member named: {:?} {:?}",
                String::from_utf8_lossy(&said.out),
                String::from_utf8_lossy(&said.err)
            ));
        }
        for (stream, which) in [(&said.out, "stdout"), (&said.err, "stderr")] {
            let acting = acting_bytes(stream);
            if !acting.is_empty() || holds(stream, b"\x1b") {
                wrong.push(format!(
                    "{what} {which}: acting bytes {acting:?} in {:?}",
                    String::from_utf8_lossy(stream)
                ));
            }
        }
    }
    let mut wrong = Vec::new();
    let dir = work("other-lines");
    std::fs::write(dir.join("arc.rar"), rar5(&names(), true)).unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let first = run(&dir, &["x", "-y", "arc.rar", "out/"], true);
    check(&mut wrong, "x", &first);
    // The files are there now: no -y, and no answer on standard input,
    // for the member the question would name.
    let asked = run(
        &dir,
        &["x", "arc.rar", "real.exe\rforged.txt", "out/"],
        true,
    );
    check(&mut wrong, "x over existing files", &asked);
    // Each name is a directory now, so no member can be created.
    let blocked = dir.join("blocked");
    for m in &MEMBERS {
        use std::os::unix::ffi::OsStrExt;
        let at = blocked.join(std::ffi::OsStr::from_bytes(m.on_disk));
        std::fs::create_dir_all(at.join("inside")).unwrap();
    }
    let refused = run(&dir, &["x", "-y", "arc.rar", "blocked/"], true);
    check(&mut wrong, "x onto directories", &refused);
    // `a` over the files `x` wrote names files on DISK, and its lines
    // give them the same stand-ins as a name from an archive
    // (creator_lines_hostile_names.rs pins each line), where `rar` 7.23
    // writes every control character as its own byte but ESC.
    let added = run(&dir, &["a", "-ep1", "new.rar", "out/"], true);
    check(&mut wrong, "a", &added);
    let locked = run(&dir, &["a", "-ep1", "-psecret", "enc.rar", "out/"], true);
    check(&mut wrong, "a -p", &locked);
    let enc_out = dir.join("enc-out");
    std::fs::create_dir_all(&enc_out).unwrap();
    let no_password = run(&dir, &["x", "enc.rar", "enc-out/"], true);
    check(
        &mut wrong,
        "x of an encrypted archive with no password",
        &no_password,
    );
    let wrong_password = run(&dir, &["x", "-y", "-pwrong", "enc.rar", "enc-out/"], true);
    check(&mut wrong, "x with a wrong password", &wrong_password);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// What `x` writes is each name as stored up to a NUL: the member a
/// listing showed, and no other.
#[test]
fn what_x_writes_is_what_was_shown() {
    let mut wrong = Vec::new();
    for (family, archive) in archives(true) {
        let dir = work(&format!("disk-{family}"));
        std::fs::write(dir.join("arc.rar"), &archive).unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let said = run(&dir, &["x", "-y", "arc.rar", "out/"], false);
        let mut written: Vec<Vec<u8>> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| {
                use std::os::unix::ffi::OsStrExt;
                e.unwrap().file_name().as_bytes().to_vec()
            })
            .collect();
        written.sort();
        let mut want: Vec<Vec<u8>> = MEMBERS.iter().map(|m| m.on_disk.to_vec()).collect();
        want.sort();
        if written != want {
            wrong.push(format!(
                "{family}: wrote {:?}, want {:?}; {:?}",
                written
                    .iter()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .collect::<Vec<_>>(),
                want.iter()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .collect::<Vec<_>>(),
                String::from_utf8_lossy(&said.err)
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
