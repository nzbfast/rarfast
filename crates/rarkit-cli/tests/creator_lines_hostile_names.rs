//! File names on disk built to act on a terminal, as `a` names them in
//! its `Adding` lines on macOS and Linux (SPEC-CLI section 10, rules T3
//! to T5 and T8).
//!
//! A name `a` adds comes from the user's own disk, and it is printed
//! the way a name from an archive is: on a terminal every control
//! character is its stand-in `<U+XXXX>` and an escape is `'\033'`, so
//! no byte a terminal acts on is written for any name. Through a pipe a
//! control character is its own byte (T5) and an escape is `'\033'`
//! (T4). Either way the line is padded as if each control character
//! were one column (T8), so the counter is drawn where it was.
//!
//! Every source is a two-byte file and every run is one process of one
//! thread's work; no pool width and no memory beyond the tool's floor
//! is assumed.

#![cfg(unix)]

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-adding-{}-{tag}", std::process::id()));
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
    command.args(args).current_dir(dir).stdin(Stdio::null());
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

/// Every byte in `stream` that a terminal acts on, with where it is: a
/// C0 control but the line feed that ends a line, DEL, and the two
/// bytes of a C1 control's UTF-8. The tool's own backspaces, which step
/// back over its percent field, are left out: a run of them follows a
/// space or a `%`, where a name's own would follow the name's text.
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

/// One source file: its name on disk, what a terminal is sent for it,
/// and what a stream that is not a terminal is sent for it.
struct Source {
    on_disk: &'static [u8],
    terminal: &'static [u8],
    pipe: &'static [u8],
}

const SOURCES: [Source; 6] = [
    Source {
        on_disk: b"plain.txt",
        terminal: b"plain.txt",
        pipe: b"plain.txt",
    },
    Source {
        on_disk: b"esc\x1b[2K\x1b[1Ahid.txt",
        terminal: b"esc'\\033'[2K'\\033'[1Ahid.txt",
        pipe: b"esc'\\033'[2K'\\033'[1Ahid.txt",
    },
    Source {
        on_disk: b"real.exe\rforged.txt",
        terminal: b"real.exe<U+000D>forged.txt",
        pipe: b"real.exe\rforged.txt",
    },
    Source {
        on_disk: b"bs.exe\x08\x08\x08\x08txt",
        terminal: b"bs.exe<U+0008><U+0008><U+0008><U+0008>txt",
        pipe: b"bs.exe\x08\x08\x08\x08txt",
    },
    Source {
        on_disk: b"nl\ninjected.txt",
        terminal: b"nl<U+000A>injected.txt",
        pipe: b"nl\ninjected.txt",
    },
    Source {
        on_disk: b"csi\xc2\x9b2Jx",
        terminal: b"csi<U+009B>2Jx",
        pipe: b"csi\xc2\x9b2Jx",
    },
];

/// A directory `src` in `dir` holding every source.
fn sources(dir: &Path) {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    for s in &SOURCES {
        std::fs::write(src.join(std::ffi::OsStr::from_bytes(s.on_disk)), b"0\n").unwrap();
    }
}

/// The `Adding` line's start for `shown`, the name as sent.
fn adding(shown: &[u8]) -> Vec<u8> {
    let mut line = b"Adding    src/".to_vec();
    line.extend_from_slice(shown);
    line
}

#[test]
fn on_a_terminal_an_adding_line_writes_no_byte_the_terminal_acts_on() {
    let mut wrong = Vec::new();
    let dir = work("terminal");
    sources(&dir);
    for (what, args) in [
        ("a", &["a", "-ep1", "one.rar", "src/"][..]),
        ("a -idp", &["a", "-ep1", "-idp", "two.rar", "src/"]),
        ("a -p", &["a", "-ep1", "-psecret", "three.rar", "src/"]),
    ] {
        let said = run(&dir, args, true);
        for s in &SOURCES {
            if !holds(&said.out, &adding(s.terminal)) {
                wrong.push(format!(
                    "{what}: {:?} not in {:?}",
                    String::from_utf8_lossy(&adding(s.terminal)),
                    String::from_utf8_lossy(&said.out)
                ));
            }
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
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn through_a_pipe_an_adding_line_is_the_names_bytes_but_an_escape() {
    let mut wrong = Vec::new();
    let dir = work("pipe");
    sources(&dir);
    let said = run(&dir, &["a", "-ep1", "one.rar", "src/"], false);
    for s in &SOURCES {
        if !holds(&said.out, &adding(s.pipe)) {
            wrong.push(format!(
                "{:?} not in {:?}",
                String::from_utf8_lossy(&adding(s.pipe)),
                String::from_utf8_lossy(&said.out)
            ));
        }
    }
    if holds(&said.out, b"\x1b") || holds(&said.err, b"\x1b") {
        wrong.push("a raw ESC".to_owned());
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// T8: the field is padded for the name with each control character
/// one column wide, on both kinds of stream, so the counter's
/// backspaces start where they would for a plain name of that length.
#[test]
fn an_adding_line_pads_a_control_character_as_one_column() {
    let mut wrong = Vec::new();
    let dir = work("pad");
    sources(&dir);
    // `Adding    src/bs.exe` and four controls and `txt`: 27 columns,
    // padded to 73.
    let pad = vec![b' '; 73 - 27];
    let s = &SOURCES[3];
    for (terminals, shown) in [(true, s.terminal), (false, s.pipe)] {
        let said = run(&dir, &["a", "-ep1", "one.rar", "src/"], terminals);
        let mut line = adding(shown);
        line.extend_from_slice(&pad);
        line.push(0x08);
        if !holds(&said.out, &line) {
            wrong.push(format!(
                "terminal {terminals}: {:?} not in {:?}",
                String::from_utf8_lossy(&line),
                String::from_utf8_lossy(&said.out)
            ));
        }
        let _ = std::fs::remove_file(dir.join("one.rar"));
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
