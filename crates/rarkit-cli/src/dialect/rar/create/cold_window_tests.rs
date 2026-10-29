//! A cold member read through the read window: the bytes are the file's,
//! and which commands take a window at all.
//!
//! Threads and memory: each read test starts the window's one reader
//! thread and no pool; it holds two slabs of 256 KiB and a file of about
//! 5 MiB.

use super::*;

/// A file of `len` bytes no two stretches of which are alike, and its bytes.
#[cfg(unix)]
fn fixture(tag: &str, len: usize) -> (PathBuf, Vec<u8>) {
    let path = std::env::temp_dir().join(format!(
        "rarfast-create-window-{}-{tag}",
        std::process::id()
    ));
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let bytes: Vec<u8> = (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect();
    std::fs::write(&path, &bytes).expect("the fixture is written");
    (path, bytes)
}

/// Reads the whole file through a window in requests of `request` bytes,
/// as the writer does: in order to the end, then once more past it.
#[cfg(unix)]
fn read_through(path: &Path, request: usize) -> (Vec<u8>, u64) {
    let file = std::fs::File::open(path).expect("the fixture opens");
    let mut windowed =
        Windowed::over_with(&file, 0, 256 << 10, 1 << 20).expect("a regular file is windowed");
    let mut got = Vec::new();
    let mut buffer = vec![0u8; request];
    loop {
        let read = windowed.read(&file, &mut buffer).expect("the read answers");
        if read == 0 {
            break;
        }
        got.extend_from_slice(&buffer[..read]);
    }
    // The writer's one byte past the end is answered by the file: nothing.
    assert_eq!(
        windowed
            .read(&file, &mut buffer[..1])
            .expect("past the end"),
        0
    );
    (got, windowed.served())
}

/// The bytes a windowed member hands the writer are the file's own, at the
/// engine's request size, at a small odd one and at one over a slab, for a
/// length that is no multiple of a slab or of a request; and the window
/// did serve them, so the test is of the window and not of the file.
#[cfg(unix)]
#[test]
fn a_windowed_member_reads_the_files_bytes_at_every_request_size() {
    let (path, bytes) = fixture("sizes", (5 << 20) + 13);
    for request in [2 << 20, 4099, (256 << 10) + 7, 1] {
        if request == 1 {
            // One byte a read over 5 MiB is slow and proves nothing more
            // than a short file does.
            let (short, short_bytes) = fixture("short", (600 << 10) + 1);
            let (got, _) = read_through(&short, request);
            assert_eq!(got, short_bytes, "one byte a read");
            let _ = std::fs::remove_file(&short);
            continue;
        }
        let (got, served) = read_through(&path, request);
        assert_eq!(got.len(), bytes.len(), "the length at {request} a read");
        assert!(got == bytes, "the bytes at {request} a read");
        assert!(
            served > (bytes.len() / 2) as u64,
            "the window served {served} of {} bytes at {request} a read",
            bytes.len()
        );
    }
    let _ = std::fs::remove_file(&path);
}

/// A member under the floor has no window, and neither has anything that
/// is not a regular file.
#[cfg(unix)]
#[test]
fn a_member_under_the_floor_takes_no_window() {
    let (path, bytes) = fixture("floor", 4096);
    let file = std::fs::File::open(&path).expect("the fixture opens");
    assert!(Windowed::over(&file, bytes.len() as u64 + 1).is_none());
    assert!(Windowed::over(&file, bytes.len() as u64).is_some());
    let dir = std::fs::File::open(std::env::temp_dir()).expect("a directory opens");
    assert!(Windowed::over(&dir, 0).is_none());
    let _ = std::fs::remove_file(&path);
}

/// Only a plain stored create at the default width windows its members:
/// each other form of the command has no row and reads as it did.
#[test]
fn only_a_plain_stored_create_takes_a_window() {
    let stored = || Options {
        level: super::super::args::Level::Store,
        ..Options::default()
    };
    assert!(command_takes_window(&stored()));
    assert!(
        !command_takes_window(&Options::default()),
        "the default level compresses"
    );
    let mut opts = stored();
    opts.shared.threads = Some(1);
    assert!(!command_takes_window(&opts), "one thread stated");
    let mut opts = stored();
    opts.shared.threads = Some(4);
    assert!(command_takes_window(&opts), "a width over one");
    let mut opts = stored();
    opts.shared.password = Some("p".into());
    assert!(!command_takes_window(&opts), "a password");
    let mut opts = stored();
    opts.volume_size = Some(100 << 20);
    assert!(!command_takes_window(&opts), "volumes");
    let mut opts = stored();
    opts.memory_cap = Some(1 << 30);
    assert!(!command_takes_window(&opts), "a memory limit");
}

/// The window is macOS's, where its rows are, and from 2 GiB, the smallest
/// member with a winning row: a member of a gibibyte lost with one.
#[test]
fn the_shipped_rule_is_macos_from_two_gibibytes() {
    let on = cfg!(all(target_os = "macos", feature = "parallel"));
    assert_eq!(WINDOWS_COLD_INPUT, on);
    assert_eq!(windows_cold_input(), on.then_some(2 << 30));
}

/// A soft resource limit is a cap unless it is the system's word for none,
/// zero included: a limit of nothing is still a limit stated.
#[test]
fn a_resource_limit_is_a_cap_unless_it_is_infinity() {
    assert!(!limit_is_finite(u64::MAX, u64::MAX));
    assert!(limit_is_finite(1u64 << 30, u64::MAX));
    assert!(limit_is_finite(0u64, u64::MAX));
}
