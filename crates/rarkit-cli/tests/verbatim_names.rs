//! `rarfast x` and `e` write each member under the name the FILE SYSTEM
//! gets (`dialect::unrar::disk_name`), never under the name the terminal
//! is shown. Before this, a Unix name `tab<TAB>there` landed as the ten
//! characters `tab\tthere` and `bs\x` as a directory `bs` holding `x`,
//! with exit 0.
//!
//! Every expectation here was MEASURED against reference unrar 7.23 on
//! Linux (a small VPS) and macOS (an M3 Mac), 27 Sep 2026, over archives
//! built exactly as [`rar5`] builds them; where the two hosts differ the
//! test says which it expects. The archives are written here from spec F
//! 3.2 (block framing, file header), so no fixture is needed for them.

// Unix only by its nature: the names written hold control characters and raw
// bytes no Windows file name can hold.
#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const WINDOWS: u8 = 0;
const UNIX: u8 = 1;

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

/// A stored RAR 5 archive of one file per `(host, name)`, whose content
/// is the member's index as text: the archive the measurements used.
fn rar5(members: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &[], &mut out);
    for (index, (host, name)) in members.iter().enumerate() {
        let data = format!("{index}\n").into_bytes();
        let mut body = Vec::new();
        vint(2, &mut body); // file header
        vint(0x0002, &mut body); // a data area follows
        vint(data.len() as u64, &mut body);
        vint(0x0006, &mut body); // mtime and CRC32 present
        vint(data.len() as u64, &mut body);
        vint(if *host == UNIX { 0o100_644 } else { 0x20 }, &mut body);
        body.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
        body.extend_from_slice(&crc32(&data).to_le_bytes());
        vint(0, &mut body); // stored
        vint(u64::from(*host), &mut body);
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name);
        block(&body, &data, &mut out);
    }
    block(&[5, 0, 0], &[], &mut out);
    out
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-verbatim-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out")).unwrap();
    dir
}

/// `rarfast <cmd> -y <width> arc.rar out/`, the archive written first.
fn run(dir: &Path, cmd: &str, width: &str, archive: &[u8]) -> Output {
    let arc = dir.join("arc.rar");
    std::fs::write(&arc, archive).unwrap();
    Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args([cmd, "-y", width])
        .arg(&arc)
        .arg(format!("{}/", dir.join("out").display()))
        .output()
        .unwrap()
}

/// Every path under `root`, relative, as bytes, sorted; a directory
/// ends in `/`.
fn tree(root: &Path) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let mut rel = path
                .strip_prefix(root)
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec();
            if path.is_dir() {
                rel.push(b'/');
                stack.push(path);
            }
            found.push(rel);
        }
    }
    found.sort();
    found
}

const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

/// One member per case, each alone in its archive; `want` is the tree
/// unrar 7.23 left, on both hosts. `tag` keeps each test's directories
/// apart from every other test's, since they run at once.
fn each_alone(tag: &str, host: u8, cases: &[(&[u8], &[&[u8]])]) {
    for (i, (name, want)) in cases.iter().enumerate() {
        for width in WIDTHS {
            let dir = work(&format!("{tag}-h{host}-{i}{width}"));
            let done = run(&dir, "x", width, &rar5(&[(host, name)]));
            assert!(done.status.success(), "{name:?} at {width}: {done:?}");
            let want: Vec<Vec<u8>> = want.iter().map(|w| w.to_vec()).collect();
            assert_eq!(tree(&dir.join("out")), want, "{name:?} at {width}");
            let file = want.iter().find(|w| !w.ends_with(b"/")).unwrap();
            assert_eq!(
                std::fs::read(dir.join("out").join(OsStr::from_bytes(file))).unwrap(),
                b"0\n",
                "{name:?} at {width}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// `a<byte>b` for every control byte and DEL, a name that is only a
/// control character, and names whose `\` is a character, not a
/// separator: all written byte for byte from a Unix host.
#[test]
fn a_unix_name_is_written_byte_for_byte() {
    let names: Vec<Vec<u8>> = (0x01..0x20_u8)
        .chain([0x7F, b'\\', b':', b'*', b'?'])
        .map(|b| vec![b'a', b, b'b'])
        .chain(
            [
                &b"\t"[..],
                b"\x01",
                b"\x1b",
                b"\\",
                b"..\\x",
                b"a\\..\\..\\x",
                b"\\x",
                b"x\\",
                b"\\\\srv\\s\\x",
                b"C:\\x",
                b"caf\xc3\xa9",
            ]
            .map(<[u8]>::to_vec),
        )
        .collect();
    let cases: Vec<(&[u8], Vec<&[u8]>)> = names.iter().map(|n| (&n[..], vec![&n[..]])).collect();
    let cases: Vec<(&[u8], &[&[u8]])> = cases.iter().map(|(n, w)| (*n, &w[..])).collect();
    each_alone("unix1", UNIX, &cases);
    each_alone(
        "unix2",
        UNIX,
        &[
            (b"d/a\\b", &[b"d/", b"d/a\\b"]),
            (b"d\x01/e\\f", &[b"d\x01/", b"d\x01/e\\f"]),
        ],
    );
}

/// From a Windows host the control characters are still written as
/// stored, and a `\` is written `_`: RAR 5 separates with `/`, and a
/// Windows name cannot hold a `\`.
#[test]
fn a_windows_name_keeps_its_control_characters_and_writes_a_backslash_as_underscore() {
    each_alone(
        "win",
        WINDOWS,
        &[
            (b"a\tb", &[b"a\tb"]),
            (b"a\x1bb", &[b"a\x1bb"]),
            (b"\x01", &[b"\x01"]),
            (b"a\\b", &[b"a_b"]),
            (b"\\", &[b"_"]),
            (b"..\\x", &[b".._x"]),
            (b"a\\..\\..\\x", &[b"a_.._.._x"]),
            (b"\\\\srv\\s\\x", &[b"__srv_s_x"]),
            (b"C:\\x", &[b"C:_x"]),
            (b"d/a\\b", &[b"d/", b"d/a_b"]),
        ],
    );
}

/// A NUL ends the name, and invalid UTF-8 ends a RAR 5 name, on every
/// host: no file system takes a NUL, and a RAR 5 name is UTF-8. A
/// surrogate (`ED A0 80`) is invalid UTF-8 too; unrar on Linux wrote
/// `a` for it and on macOS failed with `Illegal byte sequence`.
#[test]
fn a_rar5_name_ends_at_a_nul_or_at_invalid_utf8() {
    for host in [UNIX, WINDOWS] {
        each_alone(
            "cut",
            host,
            &[
                (b"a\x00b", &[b"a"]),
                (b"a\x00/b", &[b"a"]),
                (b"a\xffb", &[b"a"]),
                (b"a\x80b", &[b"a"]),
                (b"a\xed\xa0\x80b", &[b"a"]),
            ],
        );
    }
}

/// A member whose name is cut to NOTHING is skipped silently, and the
/// run is still `All OK`, as unrar 7.23 runs it.
#[test]
fn a_name_cut_to_nothing_is_skipped_silently() {
    for width in WIDTHS {
        let dir = work(&format!("empty{width}"));
        let done = run(&dir, "x", width, &rar5(&[(UNIX, b"\xc3"), (UNIX, b"ok")]));
        assert!(done.status.success(), "{done:?}");
        assert_eq!(tree(&dir.join("out")), vec![b"ok".to_vec()]);
        assert_eq!(std::fs::read(dir.join("out/ok")).unwrap(), b"1\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The cut name is what the traversal checks judge: `..\0/x` is `..`,
/// refused, and `a/\xffb/c` is `a/`, which names no file. unrar 7.23
/// fails both with `Cannot create` and exit 9; rarfast refuses them as
/// unsafe paths. Either way nothing lands outside the destination, the
/// other member is written, and the exit is not 0. The plain traversal
/// names ride along, so the cut is seen to add no way past the check.
#[test]
fn a_cut_name_is_judged_after_the_cut() {
    for (i, name) in [
        &b"..\x00/x"[..],
        b"a/\xffb/c",
        b"../x",
        b"a/../../x",
        b"/abs",
    ]
    .iter()
    .enumerate()
    {
        for width in WIDTHS {
            let dir = work(&format!("cut{i}{width}"));
            let done = run(&dir, "x", width, &rar5(&[(UNIX, name), (UNIX, b"ok")]));
            assert!(!done.status.success(), "{name:?} at {width}: {done:?}");
            // unrar makes `a` before its create of `a/` fails; rarfast
            // judges the name first and makes nothing for it.
            assert_eq!(
                tree(&dir),
                vec![b"arc.rar".to_vec(), b"out/".to_vec(), b"out/ok".to_vec()],
                "{name:?} at {width}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// The display form never reaches the file system in the other
/// direction either: a name that is LITERALLY an escape's text is
/// written as that text, inside the destination.
#[test]
fn a_name_spelled_like_an_escape_is_just_that_name() {
    each_alone(
        "escape",
        UNIX,
        &[
            (b"tab\\tthere", &[b"tab\\tthere"]),
            (
                b"\\u{2e}\\u{2e}/x",
                &[b"\\u{2e}\\u{2e}/", b"\\u{2e}\\u{2e}/x"],
            ),
        ],
    );
}

/// `e` drops the directory part at the separators the host names: on
/// Unix a `\` belongs to the base name.
#[test]
fn e_keeps_a_unix_backslash_in_the_base_name() {
    for width in WIDTHS {
        let dir = work(&format!("flat{width}"));
        let done = run(
            &dir,
            "e",
            width,
            &rar5(&[(UNIX, b"d/a\\b"), (UNIX, b"t\tx")]),
        );
        assert!(done.status.success(), "{done:?}");
        assert_eq!(
            tree(&dir.join("out")),
            vec![b"a\\b".to_vec(), b"t\tx".to_vec()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The progress line names the file written the way unrar 7.23 does:
/// every control character as the byte it is, except ESC, which the
/// reference writes as `'\033'` wherever it prints one, so no escape
/// sequence reaches the screen; and a `\` as the `\` written. Measured on
/// Linux and macOS, 27 Sep 2026.
#[test]
fn the_progress_line_shows_what_the_file_system_got_with_esc_written_out() {
    let dir = work("shown");
    let done = run(
        &dir,
        "x",
        "-mt1",
        &rar5(&[(UNIX, b"d\x1b/e\tf"), (UNIX, b"bs\\x"), (UNIX, b"n\x00ul")]),
    );
    assert!(done.status.success(), "{done:?}");
    let text = String::from_utf8(done.stdout).unwrap();
    assert!(!text.contains('\x1b'), "{text:?}");
    assert!(text.contains("Creating    "), "{text:?}");
    assert!(text.contains("d'\\033' "), "{text:?}");
    assert!(text.contains("d'\\033'/e\tf "), "{text:?}");
    assert!(text.contains("out/bs\\x "), "{text:?}");
    // The NUL's cut shows too: the line names `n`, the file written.
    assert!(text.contains("out/n "), "{text:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A RAR 1.3 to 4 name that is 8-bit and not UTF-8 (`s\caf\xe9`, written
/// by a genuine rar 4.2.0 on Linux from a file of that name, beside a
/// Unicode-flagged `s\u\xc3\xa9`): unrar 7.23 wrote `caf\xe9` byte for
/// byte on Linux, which takes any bytes, and cut it to `caf` on macOS,
/// which does not.
#[test]
fn a_rar4_8bit_name_is_written_as_stored_where_the_host_can() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/verbatim/r4-8bit.rar");
    let want_caf: &[u8] = if cfg!(any(target_os = "macos", target_os = "ios")) {
        b"s/caf"
    } else {
        b"s/caf\xe9"
    };
    for width in WIDTHS {
        let dir = work(&format!("r4{width}"));
        let done = run(&dir, "x", width, &std::fs::read(&fixture).unwrap());
        assert!(done.status.success(), "{done:?}");
        let mut want = vec![b"s/".to_vec(), want_caf.to_vec(), b"s/u\xc3\xa9".to_vec()];
        want.sort();
        assert_eq!(tree(&dir.join("out")), want, "at {width}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
