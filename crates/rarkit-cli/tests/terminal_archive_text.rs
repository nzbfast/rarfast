//! Text from an archive, to a terminal and through a pipe, on macOS and
//! Linux (SPEC-CLI section 10, rules T1 to T6 and T8).
//!
//! A control character in a member's name, a link's target or the
//! comment is printed as its stand-in `<U+XXXX>` on a stream that is a
//! terminal and as its own bytes on one that is not; an escape is the
//! six characters `'\033'` on both; each of the two streams is judged
//! by what it is; and a comment keeps a line feed, a carriage return a
//! line feed follows, and a tab on a terminal too.
//!
//! Every run here is made four ways: both streams pipes, both
//! terminals, and each one a terminal while the other is a pipe. A
//! terminal is a pseudo terminal of its own for each stream, with
//! output processing off so that what the tool wrote is what is read.
//!
//! The expectations are the section's two tables and nothing else: no
//! program was run to get them. Each run is one process of one
//! thread's work on a member of two bytes; no pool width and no memory
//! beyond the tool's floor is assumed.

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

/// One block: CRC32, size, then `body` (spec F 3.2.2), then `data`.
fn block(body: &[u8], data: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(body);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
}

/// A stored RAR 5 archive of one two-byte file named `name`, written
/// from a Unix host (spec F 3.2). `sound` false stores a CRC32 the data
/// does not have, so the member fails its check.
fn rar5(name: &[u8], sound: bool) -> Vec<u8> {
    let data = b"0\n";
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    let mut body = Vec::new();
    vint(2, &mut body); // file header
    vint(0x0002, &mut body); // a data area follows
    vint(data.len() as u64, &mut body);
    vint(0x0006, &mut body); // mtime and CRC32 present
    vint(data.len() as u64, &mut body);
    vint(0o100_644, &mut body);
    body.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
    let check = if sound { crc32(data) } else { !crc32(data) };
    body.extend_from_slice(&check.to_le_bytes());
    vint(0, &mut body); // stored
    vint(1, &mut body); // host: Unix
    vint(name.len() as u64, &mut body);
    body.extend_from_slice(name);
    block(&body, data, &mut out);
    block(&[5, 0, 0], &[], &mut out);
    out
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-termtext-{}-{tag}", std::process::id()));
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

/// `rarfast <args>` in `dir`, each stream a terminal of its own or a
/// pipe as `terminals` says for (standard output, standard error).
fn run(dir: &Path, args: &[&str], terminals: (bool, bool)) -> Said {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rarfast"));
    command
        .args(args)
        .current_dir(dir)
        .env("TZ", "UTC")
        .stdin(Stdio::null());
    let mut readers = [None, None];
    for (slot, wanted) in [terminals.0, terminals.1].into_iter().enumerate() {
        let stream = if wanted {
            let (reader, writer) = terminal();
            readers[slot] = Some(drain(reader));
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

/// The four ways the two streams can be: (standard output is a
/// terminal, standard error is a terminal).
const MIXES: [(bool, bool); 4] = [(false, false), (true, true), (true, false), (false, true)];

/// A row's tag, the stored name, and what a terminal and a stream
/// that is not one are sent for it.
type Row = (&'static str, Vec<u8>, Vec<u8>, Vec<u8>);

/// Section 10's first table: the name `a`, the character, `b`, and
/// what a terminal and a stream that is not one are sent for it.
fn name_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    for (tag, code) in [
        ("tab", 0x09_u32),
        ("lf", 0x0A),
        ("cr", 0x0D),
        ("bel", 0x07),
        ("bs", 0x08),
        ("del", 0x7F),
        ("csi", 0x9B),
    ] {
        let c = char::from_u32(code).unwrap();
        let name = format!("a{c}b").into_bytes();
        rows.push((
            tag,
            name.clone(),
            format!("a<U+{code:04X}>b").into_bytes(),
            name,
        ));
    }
    rows.push((
        "esc",
        b"a\x1bb".to_vec(),
        b"a'\\033'b".to_vec(),
        b"a'\\033'b".to_vec(),
    ));
    rows.push((
        "lt",
        b"<U+0007>".to_vec(),
        b"<U+003C>U+0007>".to_vec(),
        b"<U+0007>".to_vec(),
    ));
    rows
}

/// What `stream` must hold for a name, and what it must not.
fn judge(stream: &[u8], terminal: bool, row: &Row, told: &str) {
    let (tag, _, on_terminal, off_terminal) = row;
    let (want, other) = if terminal {
        (on_terminal, off_terminal)
    } else {
        (off_terminal, on_terminal)
    };
    let shown = String::from_utf8_lossy(stream);
    assert!(
        holds(stream, want),
        "{told}, {tag}, terminal {terminal}: {shown:?}"
    );
    if want != other {
        assert!(
            !holds(stream, other),
            "{told}, {tag}, terminal {terminal}: {shown:?}"
        );
    }
}

/// Listing (`lb`, `l`, `v`, `lt`), testing and extracting: the name is
/// on standard output, in the form that stream's kind asks for.
#[test]
fn a_listed_tested_or_extracted_name_is_shown_as_its_stream_asks() {
    for row in name_rows() {
        for mix in MIXES {
            let dir = work(&format!("name-{}-{}{}", row.0, mix.0, mix.1));
            std::fs::write(dir.join("arc.rar"), rar5(&row.1, true)).unwrap();
            for cmd in ["lb", "l", "v", "lt", "t", "x"] {
                let said = run(&dir, &[cmd, "arc.rar"], mix);
                judge(&said.out, mix.0, &row, &format!("{cmd} {mix:?}"));
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// A member that fails its check is named on standard error, and under
/// `t` on standard output too: each stream by what IT is, so the two
/// forms stand side by side when one is a terminal and one is not.
#[test]
fn an_error_line_is_shown_as_its_own_stream_asks() {
    for row in name_rows() {
        for mix in MIXES {
            let dir = work(&format!("bad-{}-{}{}", row.0, mix.0, mix.1));
            std::fs::write(dir.join("arc.rar"), rar5(&row.1, false)).unwrap();
            let said = run(&dir, &["t", "arc.rar"], mix);
            judge(
                &said.out,
                mix.0,
                &row,
                &format!("t, standard output {mix:?}"),
            );
            judge(
                &said.err,
                mix.1,
                &row,
                &format!("t, standard error {mix:?}"),
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// The lines `d`, `rn` and `r` print about a member.
#[test]
fn the_deleting_renaming_and_found_lines_are_shown_as_their_stream_asks() {
    for row in name_rows() {
        // `d` and `rn` are given a mask that takes the one member.
        for (cmd, args) in [("d", &["*"][..]), ("rn", &["*", "q*"][..]), ("r", &[][..])] {
            for mix in MIXES {
                let dir = work(&format!("{cmd}-{}-{}{}", row.0, mix.0, mix.1));
                std::fs::write(dir.join("arc.rar"), rar5(&row.1, true)).unwrap();
                let said = run(&dir, &[&[cmd, "arc.rar"][..], args].concat(), mix);
                judge(&said.out, mix.0, &row, &format!("{cmd} {mix:?}"));
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
}

/// Section 10's second table. The comment is written by the tool's own
/// `a -z`, then shown by a listing and by `cw` with no file named.
#[test]
fn a_comment_keeps_three_characters_and_shows_the_rest_as_its_stream_asks() {
    let comment = b"one\ttab\r\ntwo\rover\x07bell\x1besc\nend\n";
    let on_terminal = b"one\ttab\r\ntwo<U+000D>over<U+0007>bell'\\033'esc\nend\n";
    let off_terminal = b"one\ttab\r\ntwo\rover\x07bell'\\033'esc\nend\n";
    for mix in MIXES {
        let dir = work(&format!("cmt-{}{}", mix.0, mix.1));
        std::fs::write(dir.join("f.txt"), b"0\n").unwrap();
        std::fs::write(dir.join("cmt.txt"), comment).unwrap();
        let made = run(
            &dir,
            &["a", "-idq", "-m0", "-zcmt.txt", "arc.rar", "f.txt"],
            (false, false),
        );
        assert!(dir.join("arc.rar").exists(), "{:?}", made.err);
        for cmd in ["l", "cw"] {
            let said = run(&dir, &[cmd, "arc.rar"], mix);
            let (want, other) = if mix.0 {
                (&on_terminal[..], &off_terminal[..])
            } else {
                (&off_terminal[..], &on_terminal[..])
            };
            let shown = String::from_utf8_lossy(&said.out);
            assert!(holds(&said.out, want), "{cmd} {mix:?}: {shown:?}");
            assert!(!holds(&said.out, other), "{cmd} {mix:?}: {shown:?}");
        }
        // `cw` given a file writes the comment's own bytes, all of them.
        run(&dir, &["cw", "arc.rar", "out.txt"], mix);
        assert_eq!(
            std::fs::read(dir.join("out.txt")).unwrap(),
            comment,
            "{mix:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The data `p` writes is not archive text and is never changed, to a
/// terminal either.
#[test]
fn the_data_p_writes_is_never_changed() {
    let dir = work("p");
    std::fs::write(dir.join("f.bin"), b"a\x07b\tc\x1bd\r\x7f\n").unwrap();
    let made = run(
        &dir,
        &["a", "-idq", "-m0", "arc.rar", "f.bin"],
        (false, false),
    );
    assert!(dir.join("arc.rar").exists(), "{:?}", made.err);
    for mix in MIXES {
        let said = run(&dir, &["p", "-idq", "arc.rar"], mix);
        assert_eq!(said.out, b"a\x07b\tc\x1bd\r\x7f\n", "{mix:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A mask on the command line is matched with the name the archive
/// holds, whatever a line would print for it: a member is still named
/// by its own bytes, a control character or the text of a stand-in
/// among them, and a mask of what a terminal is shown names nothing.
#[test]
fn a_mask_names_a_member_by_the_name_the_archive_holds() {
    for row in name_rows() {
        let dir = work(&format!("mask-{}", row.0));
        std::fs::write(dir.join("arc.rar"), rar5(&row.1, true)).unwrap();
        let name = std::str::from_utf8(&row.1).unwrap();
        for mix in MIXES {
            let said = run(&dir, &["lb", "arc.rar", name], mix);
            judge(&said.out, mix.0, &row, &format!("lb by name {mix:?}"));
        }
        if row.1 != row.2 {
            let shown = std::str::from_utf8(&row.2).unwrap();
            let said = run(&dir, &["lb", "arc.rar", shown], (false, false));
            assert!(said.out.is_empty(), "{}: {:?}", row.0, said.out);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
