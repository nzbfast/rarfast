//! The output past the cache, the staged writer, the probe and the rule,
//! each against a real file.

use super::*;
use std::io::Read;

/// A directory whose files take a past-the-cache open, and the path
/// `name` in it; `None` where no directory here does (a tmpfs).
fn direct_path(name: &str) -> Option<PathBuf> {
    for dir in [std::env::temp_dir(), std::env::current_dir().ok()?] {
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        if let Ok(file) = open_direct(&path) {
            let taken = take_direct(&file);
            drop(file);
            let _ = std::fs::remove_file(&path);
            if taken {
                return Some(path);
            }
        }
    }
    None
}

/// **[`FLAG`] is this Linux architecture's `O_DIRECT`**, as a number
/// and as the C library's own constant: the generic value on x86-64,
/// arm64's own on aarch64. The generic value on arm64 is `O_DIRECTORY`.
#[cfg(target_os = "linux")]
#[test]
fn the_open_flag_is_this_architectures_o_direct() {
    #[cfg(target_arch = "x86_64")]
    assert_eq!(FLAG, 0o40000);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(FLAG, 0o200000);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        assert_eq!(FLAG, libc::O_DIRECT as u32);
        assert_ne!(FLAG, libc::O_DIRECTORY as u32);
    }
}

/// **An output opened past the cache IS direct**: where a directory's
/// file system takes a plain open with the C library's `O_DIRECT`,
/// [`open_direct`] must succeed there too, and the kernel's own record
/// of the open descriptor (`flags:` in `/proc/self/fdinfo`, octal)
/// carries `O_DIRECT` and not `O_DIRECTORY`. A directory whose file
/// system refuses the plain open (a tmpfs, some overlays) is passed
/// over, and said so.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn an_output_opened_past_the_cache_is_direct_by_the_kernels_record() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let name = format!("rarfast-open-direct-flag-{}", std::process::id());
    let dirs = [
        std::env::current_dir().expect("working directory"),
        std::env::temp_dir(),
    ];
    for dir in dirs {
        let path = dir.join(&name);
        let _ = std::fs::remove_file(&path);
        let probe = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path);
        let _ = std::fs::remove_file(&path);
        if let Err(err) = probe {
            eprintln!("{}: no direct open here ({err}): skipped", dir.display());
            continue;
        }
        drop(probe);
        let file = open_direct(&path).expect("the file system takes a direct open");
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
            .expect("fdinfo");
        drop(file);
        let _ = std::fs::remove_file(&path);
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|octal| u32::from_str_radix(octal.trim(), 8).ok())
            .expect("a flags line");
        assert_ne!(flags & libc::O_DIRECT as u32, 0, "flags {flags:o}");
        assert_eq!(flags & libc::O_DIRECTORY as u32, 0, "flags {flags:o}");
    }
}

/// Noise, so nothing about the bytes lines up with a sector.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    rarkit_testdata::scramble(u64::from(seed), len)
}

/// **An archive's output past the cache holds exactly what the same
/// writes through the cache hold**, corrections behind the end
/// included, and every read of it reads what was written: with nothing
/// forced, and with each failure forced in turn (the open, a direct
/// write, the tail, a correction's read-back), each of which must fall
/// back without a byte out of place.
///
/// The script is an archive's shape: a short head, then pieces enough
/// to send two whole blocks to disk, a correction of the head (on disk:
/// a read-modify-write), one across a sector boundary on disk, one of
/// bytes still staged, reads from both places, and a tail that is not a
/// whole sector.
#[test]
fn an_output_past_the_cache_holds_exactly_what_was_written() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !ABLE {
        eprintln!("no past-the-cache open on this target: skipped");
        return;
    }
    for (depth, forced) in [0, 1, 3].into_iter().flat_map(|depth| {
        [
            Forced::None,
            Forced::Open,
            Forced::Write,
            Forced::Tail,
            Forced::Patch,
        ]
        .map(|forced| (depth, forced))
    }) {
        *TEST_DEPTH.lock().unwrap() = Some(depth);
        let name = format!("rarfast-output-{depth}-{forced:?}-{}", std::process::id());
        let Some(path) = direct_path(&name) else {
            eprintln!("no directory here takes a direct open: skipped");
            return;
        };
        *TEST_FORCED.lock().unwrap() = forced;
        let mut out = Output::create(&path, 100 << 20).expect("create");
        if forced == Forced::Open {
            assert!(!out.is_direct(), "{forced:?}: a refused open went direct");
        } else {
            assert!(out.is_direct(), "{forced:?}: the output was not direct");
        }
        let mut want: Vec<u8> = Vec::new();
        let put = |out: &mut Output, want: &mut Vec<u8>, bytes: &[u8]| {
            out.write_all(bytes).expect("append");
            want.extend_from_slice(bytes);
        };
        let fix = |out: &mut Output, want: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            let end = out.stream_position().expect("position");
            out.seek(SeekFrom::Start(at as u64)).expect("seek back");
            out.write_all(bytes).expect("correct");
            out.seek(SeekFrom::Start(end)).expect("seek end");
            want[at..at + bytes.len()].copy_from_slice(bytes);
        };
        let check = |out: &mut Output, want: &[u8], at: usize, len: usize| {
            let end = out.stream_position().expect("position");
            let mut got = vec![0u8; len];
            out.seek(SeekFrom::Start(at as u64)).expect("seek back");
            out.read_exact(&mut got).expect("read back");
            out.seek(SeekFrom::Start(end)).expect("seek end");
            assert!(
                got == want[at..at + len],
                "{forced:?}: {len} bytes read back at {at} differ"
            );
        };

        put(&mut out, &mut want, &noise(37, 1));
        let body = noise(9 * (1 << 20) + 123, 2);
        for piece in body.chunks(1 << 20) {
            put(&mut out, &mut want, piece);
        }
        fix(&mut out, &mut want, 5, &noise(20, 3));
        fix(&mut out, &mut want, 4090, &noise(12, 4));
        put(&mut out, &mut want, &noise(3, 5));
        let near_end = want.len() - 9;
        fix(&mut out, &mut want, near_end, &noise(6, 6));
        check(&mut out, &want, 0, 100);
        check(&mut out, &want, 4000, 9000);
        check(&mut out, &want, want.len() - 5000, 5000);
        // A recovery record's shape: many small reads in order over
        // what is on disk, served from one window a block at a time;
        // then a correction inside a window already read, which the
        // next read must see.
        for at in (0..(5 << 20)).step_by(65_536) {
            check(&mut out, &want, at, 65_536);
        }
        check(&mut out, &want, 64_000, 1_000);
        fix(&mut out, &mut want, 70_000, &noise(40, 8));
        check(&mut out, &want, 69_000, 3_000);
        put(&mut out, &mut want, &noise(777, 7));
        if forced == Forced::None {
            assert!(out.is_direct(), "nothing forced, yet the output fell back");
        }
        if forced == Forced::Write || forced == Forced::Patch {
            assert!(
                !out.is_direct(),
                "{forced:?}: the failure did not fall back"
            );
        }
        out.close().expect("close");
        drop(out);
        *TEST_FORCED.lock().unwrap() = Forced::None;

        let got = std::fs::read(&path).expect("read the output");
        let _ = std::fs::remove_file(&path);
        assert_eq!(got.len(), want.len(), "{depth} {forced:?}: length");
        assert!(
            got == want,
            "{depth} {forced:?}: the output holds other bytes"
        );
    }
    *TEST_DEPTH.lock().unwrap() = None;
}

/// A cached output's path, removed first.
fn cached_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// A correction as the writer makes one (`VolumeOut::patch`): where it
/// is, a seek back, the bytes, a seek to where it was; `want` is what
/// the file must hold once closed.
fn fix(out: &mut Output, want: &mut [u8], at: usize, bytes: &[u8]) {
    let end = out.stream_position().expect("position");
    out.seek(SeekFrom::Start(at as u64)).expect("seek back");
    out.write_all(bytes).expect("correct");
    out.seek(SeekFrom::Start(end)).expect("seek end");
    want[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put(out: &mut Output, want: &mut Vec<u8>, bytes: &[u8]) {
    out.write_all(bytes).expect("append");
    want.extend_from_slice(bytes);
}

/// **A cached output holds its corrections until its close, and closed
/// it holds exactly what the same writes made at once would**: before
/// the close the file holds every appended byte and the headers as
/// first laid down; after it, the corrections too, a later one over an
/// earlier one's bytes winning as the order given says.
#[test]
fn a_cached_output_makes_its_corrections_at_its_close() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::Always)));
    let path = cached_path("rarfast-held-close");
    let mut out = Output::create(&path, 1 << 20).expect("create");
    assert!(!out.is_direct(), "a small output went direct");
    let mut want: Vec<u8> = Vec::new();
    let mut laid: Vec<u8> = Vec::new();
    let mut headers = Vec::new();
    for member in 0..8u32 {
        headers.push(want.len());
        for piece in [
            noise(64, member),
            noise(200_000 + member as usize, 100 + member),
        ] {
            put(&mut out, &mut want, &piece);
            laid.extend_from_slice(&piece);
        }
        // Each member's header corrected once its bytes have passed.
        let at = headers[member as usize] + 20;
        fix(&mut out, &mut want, at, &noise(30, 200 + member));
    }
    // Two more over bytes already corrected: the later is what stays.
    fix(&mut out, &mut want, headers[2] + 25, &noise(40, 300));
    fix(&mut out, &mut want, headers[2] + 10, &noise(20, 301));
    assert_eq!(out.held_count(), 10, "the corrections were not held");
    let before = std::fs::read(&path).expect("read before the close");
    assert!(
        before == laid,
        "before its close the file held something other than what was appended"
    );
    out.close().expect("close");
    assert_eq!(out.held_count(), 0);
    drop(out);
    let got = std::fs::read(&path).expect("read the output");
    let _ = std::fs::remove_file(&path);
    assert!(got == want, "the closed output holds other bytes");
}

/// **A read of a cached output reads every correction given before
/// it** (a recovery record's read-back, SPEC-API 7.1): the held list is
/// written first, the read is of the file, and appends and corrections
/// after it land where they should.
#[test]
fn a_read_of_a_cached_output_makes_its_corrections_first() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::Always)));
    let path = cached_path("rarfast-held-read");
    let mut out = Output::create(&path, 1 << 20).expect("create");
    let mut want: Vec<u8> = Vec::new();
    let check = |out: &mut Output, want: &[u8], at: usize, len: usize| {
        let end = out.stream_position().expect("position");
        let mut got = vec![0u8; len];
        out.seek(SeekFrom::Start(at as u64)).expect("seek back");
        out.read_exact(&mut got).expect("read back");
        out.seek(SeekFrom::Start(end)).expect("seek end");
        assert!(got == want[at..at + len], "{len} bytes at {at} differ");
    };
    put(&mut out, &mut want, &noise(300_000, 1));
    fix(&mut out, &mut want, 7, &noise(50, 2));
    fix(&mut out, &mut want, 150_000, &noise(9, 3));
    assert_eq!(out.held_count(), 2);
    check(&mut out, &want, 0, 1_000);
    assert_eq!(out.held_count(), 0, "a read left corrections unmade");
    // In order over what is there, as a recovery record reads.
    for at in (0..300_000).step_by(4_096) {
        check(&mut out, &want, at, 4_096.min(300_000 - at));
    }
    put(&mut out, &mut want, &noise(70_000, 4));
    fix(&mut out, &mut want, 299_990, &noise(30, 5));
    check(&mut out, &want, 299_000, 2_000);
    put(&mut out, &mut want, &noise(11, 6));
    fix(&mut out, &mut want, 0, &noise(3, 7));
    out.close().expect("close");
    drop(out);
    let got = std::fs::read(&path).expect("read the output");
    let _ = std::fs::remove_file(&path);
    assert!(got == want, "the closed output holds other bytes");
}

/// **At its bounds the held list is written early, in the order
/// given**: more corrections than [`HELD_SPANS_MOST`], more bytes than
/// [`HELD_BYTES_MOST`], and one correction too large to hold, each over
/// bytes an earlier one touched, leave what immediate writes leave.
#[test]
fn held_corrections_past_their_bound_are_made_early_and_in_order() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::Always)));
    let path = cached_path("rarfast-held-bound");
    let mut out = Output::create(&path, 1 << 20).expect("create");
    let mut want: Vec<u8> = Vec::new();
    put(&mut out, &mut want, &noise(3 << 20, 1));
    // Past the count: every correction a byte, cycling over 100 places,
    // so the order they are made in decides what stays.
    for i in 0..HELD_SPANS_MOST + 77 {
        fix(&mut out, &mut want, 1_000 + i % 100, &[i as u8]);
    }
    assert_eq!(
        out.held_count(),
        77,
        "the list did not start again at its bound"
    );
    // Past the bytes: pieces an eighth of the bound, each half over the
    // one before.
    let piece = HELD_BYTES_MOST / 8;
    for i in 0..12usize {
        fix(
            &mut out,
            &mut want,
            4_096 + i * piece / 2,
            &noise(piece, 10 + i as u32),
        );
    }
    assert!(out.held_count() < 12, "the byte bound was not kept");
    // Too large to hold at all, over what is held and what was made.
    fix(
        &mut out,
        &mut want,
        500,
        &noise(HELD_BYTES_MOST / 4 + 1, 40),
    );
    assert_eq!(
        out.held_count(),
        0,
        "a large correction left the list unmade"
    );
    fix(&mut out, &mut want, 600, &noise(10, 41));
    put(&mut out, &mut want, &noise(1_234, 42));
    out.close().expect("close");
    drop(out);
    let got = std::fs::read(&path).expect("read the output");
    let _ = std::fs::remove_file(&path);
    assert!(got == want, "the closed output holds other bytes");
}

/// **A correction that runs past the end is held as far as the end**,
/// and the rest is the next write's, an append, as `write_all` asks for
/// it; **a seek past the end ends the account** and the output is the
/// plain file it was before, the gap read as zeros.
#[test]
fn a_cached_output_past_its_end_is_a_plain_file() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::Always)));
    let path = cached_path("rarfast-held-past");
    let mut out = Output::create(&path, 1 << 20).expect("create");
    let mut want: Vec<u8> = Vec::new();
    put(&mut out, &mut want, &noise(10_000, 1));
    out.seek(SeekFrom::Start(9_990)).expect("seek back");
    let tail = noise(25, 2);
    out.write_all(&tail).expect("a write across the end");
    want.truncate(9_990);
    want.extend_from_slice(&tail);
    assert_eq!(out.stream_position().expect("position"), 10_015);
    assert_eq!(out.held_count(), 1);
    assert_eq!(out.seek(SeekFrom::End(-15)).expect("from the end"), 10_000);
    assert_eq!(out.seek(SeekFrom::Current(15)).expect("from here"), 10_015);
    // Past the end: the held correction is made and the file is driven
    // as a file from here.
    assert_eq!(
        out.seek(SeekFrom::Start(10_100)).expect("past the end"),
        10_100
    );
    assert_eq!(out.held_count(), 0);
    out.write_all(b"after a gap").expect("write");
    want.resize(10_100, 0);
    want.extend_from_slice(b"after a gap");
    out.seek(SeekFrom::Start(3)).expect("seek back");
    out.write_all(b"xyz").expect("correct");
    want[3..6].copy_from_slice(b"xyz");
    out.close().expect("close");
    drop(out);
    let got = std::fs::read(&path).expect("read the output");
    let _ = std::fs::remove_file(&path);
    assert!(got == want, "the output holds other bytes");
}

/// **An output dropped without its close** (a failed create, whose file
/// the run then removes, or a killed one) holds every appended byte and
/// the headers as first laid down: the corrections are in the file only
/// once `close` has returned.
#[test]
fn a_cached_output_dropped_unclosed_holds_what_was_appended() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::Always)));
    let path = cached_path("rarfast-held-drop");
    let mut out = Output::create(&path, 1 << 20).expect("create");
    let mut want: Vec<u8> = Vec::new();
    put(&mut out, &mut want, &noise(50_000, 1));
    let laid = want.clone();
    fix(&mut out, &mut want, 10, &noise(20, 2));
    drop(out);
    let got = std::fs::read(&path).expect("read the output");
    let _ = std::fs::remove_file(&path);
    assert!(
        got == laid,
        "an unclosed output holds other than what was appended"
    );
}

/// **The shipped default, by system** ([`HOLDS`]): on macOS a cached
/// output holds a correction while its input is warm or its create is
/// bound by its cipher; everywhere else never. The list's charge is
/// the same on every system. And each rule by name: `Never` is the
/// plain file (the correction in the file as soon as it is given),
/// `Always` holds whatever the input, `WhenWarm` holds a correction
/// given while the input is warm and makes one given while it is cold
/// at once; the closed bytes are the same in all of them.
#[test]
fn a_cached_output_holds_by_default_on_macos_only() {
    let shipped = if cfg!(target_os = "macos") {
        Holds::WarmOrBound
    } else {
        Holds::Never
    };
    assert_eq!(HOLDS, shipped);
    assert_eq!(HELD_MOST, 80 << 10);
    TEST_HOLDS.with(|h| h.set(None));
    assert_eq!(holds(), shipped, "the default is not the shipped dial");
    assert_eq!(samples_input(), cfg!(target_os = "macos"));
    for (rule, warm, holding) in [
        (Holds::Never, true, false),
        (Holds::Always, false, true),
        (Holds::WhenWarm, true, true),
        (Holds::WhenWarm, false, false),
    ] {
        TEST_HOLDS.with(|h| h.set(Some(rule)));
        TEST_WARM.with(|w| w.set(Some(warm)));
        let path = cached_path("rarfast-held-default");
        let mut out = Output::create(&path, 1 << 20).expect("create");
        let mut want: Vec<u8> = Vec::new();
        put(&mut out, &mut want, &noise(40_000, 1));
        let laid = want.clone();
        fix(&mut out, &mut want, 100, &noise(16, 2));
        put(&mut out, &mut want, &noise(1_000, 3));
        assert_eq!(out.held_count(), usize::from(holding), "{rule:?} {warm}");
        let before = std::fs::read(&path).expect("read before the close");
        let head = if holding {
            &laid[..40_000]
        } else {
            &want[..40_000]
        };
        assert!(
            before[..40_000] == *head,
            "{rule:?} {warm}: the file before its close"
        );
        out.close().expect("close");
        drop(out);
        let got = std::fs::read(&path).expect("read the output");
        let _ = std::fs::remove_file(&path);
        assert!(
            got == want,
            "{rule:?} {warm}: the closed output holds other bytes"
        );
    }
    TEST_HOLDS.with(|h| h.set(None));
    TEST_WARM.with(|w| w.set(None));
}

/// **Each rule, by what it holds**: never and always whatever is said;
/// while-warm by the input alone; warm-or-bound by the input, or by a
/// create bound by its own cipher whatever the input.
#[test]
fn each_rule_holds_by_the_input_and_the_create() {
    for warm in [false, true] {
        for bound in [false, true] {
            assert!(!held_by(Holds::Never, warm, bound));
            assert!(held_by(Holds::Always, warm, bound));
            assert_eq!(held_by(Holds::WhenWarm, warm, bound), warm);
            assert_eq!(held_by(Holds::WarmOrBound, warm, bound), warm || bound);
        }
    }
    // And through an output: cold but bound, the correction is held.
    TEST_HOLDS.with(|h| h.set(Some(Holds::WarmOrBound)));
    TEST_WARM.with(|w| w.set(Some(false)));
    for bound in [false, true] {
        TEST_BOUND.with(|b| b.set(bound));
        let path = cached_path("rarfast-held-bound-rule");
        let mut out = Output::create(&path, 1 << 20).expect("create");
        let mut want: Vec<u8> = Vec::new();
        put(&mut out, &mut want, &noise(20_000, 1));
        fix(&mut out, &mut want, 50, &noise(16, 2));
        assert_eq!(out.held_count(), usize::from(bound), "bound {bound}");
        out.close().expect("close");
        drop(out);
        assert!(std::fs::read(&path).expect("read") == want, "bound {bound}");
        let _ = std::fs::remove_file(&path);
    }
    TEST_HOLDS.with(|h| h.set(None));
    TEST_WARM.with(|w| w.set(None));
    TEST_BOUND.with(|b| b.set(false));
}

/// **The input turning cold, and warm again, part way through an
/// archive**: corrections given while it is warm are held; the first
/// one given while it is cold is made at once AFTER everything held
/// before it (so the order given is the order made, and a later
/// correction over an earlier one's bytes still wins); one given once
/// it is warm again is held. The closed bytes are those of immediate
/// writes.
#[test]
fn a_cached_output_follows_its_input_from_warm_to_cold_and_back() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::WhenWarm)));
    let path = cached_path("rarfast-held-turn");
    let mut out = Output::create(&path, 1 << 20).expect("create");
    let mut want: Vec<u8> = Vec::new();
    let on_disk = |path: &Path| std::fs::read(path).expect("read the file");
    // Never sampled yet: cold, the plain form.
    put(&mut out, &mut want, &noise(30_000, 1));
    fix(&mut out, &mut want, 10, &noise(8, 2));
    assert_eq!(out.held_count(), 0, "an unsampled input was held");
    assert!(on_disk(&path) == want);
    // Warm: two members' corrections held.
    TEST_WARM.with(|w| w.set(Some(true)));
    put(&mut out, &mut want, &noise(30_000, 3));
    let laid = want.clone();
    fix(&mut out, &mut want, 30_010, &noise(8, 4));
    put(&mut out, &mut want, &noise(30_000, 5));
    fix(&mut out, &mut want, 30_014, &noise(8, 6));
    assert_eq!(out.held_count(), 2);
    assert!(
        on_disk(&path)[..60_000] == laid[..60_000],
        "a held correction reached the file"
    );
    // Cold: this member's correction is made now, after the two held,
    // over bytes one of them touched.
    TEST_WARM.with(|w| w.set(Some(false)));
    put(&mut out, &mut want, &noise(30_000, 7));
    fix(&mut out, &mut want, 30_016, &noise(8, 8));
    assert_eq!(
        out.held_count(),
        0,
        "a cold correction left the list unmade"
    );
    assert!(
        on_disk(&path) == want,
        "the file is not current after a cold correction"
    );
    // Warm again: held again.
    TEST_WARM.with(|w| w.set(Some(true)));
    put(&mut out, &mut want, &noise(30_000, 9));
    fix(&mut out, &mut want, 90_100, &noise(8, 10));
    assert_eq!(out.held_count(), 1);
    out.close().expect("close");
    drop(out);
    assert!(
        on_disk(&path) == want,
        "the closed output holds other bytes"
    );
    let _ = std::fs::remove_file(&path);
    TEST_HOLDS.with(|h| h.set(None));
    TEST_WARM.with(|w| w.set(None));
}

/// **An output that falls back from direct writing holds its later
/// corrections like any cached one**, from the right length and place,
/// whichever call the failure came in.
#[test]
fn an_output_that_fell_back_holds_its_corrections() {
    TEST_HOLDS.with(|h| h.set(Some(Holds::Always)));
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !ABLE {
        eprintln!("no past-the-cache open on this target: skipped");
        return;
    }
    for forced in [Forced::Write, Forced::Patch] {
        *TEST_DEPTH.lock().unwrap() = Some(0);
        let name = format!("rarfast-held-fell-{forced:?}-{}", std::process::id());
        let Some(path) = direct_path(&name) else {
            eprintln!("no directory here takes a direct open: skipped");
            *TEST_DEPTH.lock().unwrap() = None;
            return;
        };
        *TEST_FORCED.lock().unwrap() = forced;
        let mut out = Output::create(&path, 100 << 20).expect("create");
        let mut want: Vec<u8> = Vec::new();
        put(&mut out, &mut want, &noise(37, 1));
        for piece in noise(9 * (1 << 20) + 123, 2).chunks(1 << 20) {
            put(&mut out, &mut want, piece);
        }
        // On disk: the forced read-back failure falls back here; the
        // forced write failure fell back in the appends above.
        fix(&mut out, &mut want, 5, &noise(20, 3));
        assert!(
            !out.is_direct(),
            "{forced:?}: the failure did not fall back"
        );
        put(&mut out, &mut want, &noise(100_000, 4));
        fix(&mut out, &mut want, 4_090, &noise(12, 5));
        let near_end = want.len() - 9;
        fix(&mut out, &mut want, near_end, &noise(6, 6));
        assert!(
            out.held_count() >= 2,
            "{forced:?}: nothing was held after the fall back"
        );
        put(&mut out, &mut want, &noise(777, 7));
        out.close().expect("close");
        drop(out);
        *TEST_FORCED.lock().unwrap() = Forced::None;
        let got = std::fs::read(&path).expect("read the output");
        let _ = std::fs::remove_file(&path);
        assert!(got == want, "{forced:?}: the output holds other bytes");
    }
    *TEST_DEPTH.lock().unwrap() = None;
}

/// **The gate's arithmetic**: a slow device is found as
/// soon as the time taken exceeds the whole window's at the gate's
/// rate; a fast one only once the window is full; the window's rate
/// decides at its end.
#[test]
fn the_gate_judges_the_probe_window_by_its_rate() {
    let ms = Duration::from_millis;
    let slab = 4 << 20;
    // 4 MiB in 84 ms is a 50 MB/s disk; in 2 ms, 2.1 GB/s.
    assert!(!at_rate(slab, ms(84), GATE_RATE));
    assert!(at_rate(slab, ms(2), GATE_RATE));
    // A test build's rate of 0 finds every write fast.
    assert!(at_rate(slab, ms(1_000), 0));
    // The span at 1.5 GB/s takes 715.8 ms. Short of it, nothing is
    // decided while the time is inside that...
    assert_eq!(judge(slab, ms(2), GATE_RATE), None);
    assert_eq!(judge(SPAN / 2, ms(700), GATE_RATE), None);
    // ...and past it the device is slow, however few bytes: a 50 MB/s
    // disk after nine slabs, a throttle after its burst and 0.7 s.
    assert_eq!(judge(9 * slab, ms(756), GATE_RATE), Some(Verdict::Slow));
    assert_eq!(judge(SPAN / 2, ms(717), GATE_RATE), Some(Verdict::Slow));
    // The whole span inside the time is fast, a stall included: an
    // 11 GB/s disk that spent 600 ms on 243 MB and ran the rest at speed.
    assert_eq!(judge(SPAN, ms(98), GATE_RATE), Some(Verdict::Fast));
    assert_eq!(judge(SPAN, ms(670), GATE_RATE), Some(Verdict::Fast));
    // A 1.4 GB/s disk over the whole span: slow.
    assert_eq!(judge(SPAN, ms(767), GATE_RATE), Some(Verdict::Slow));
}

thread_local! {
    /// The kind of [`write_staged`]'s member: stored, unless a test of
    /// the rule on facts says otherwise.
    static MEMBER: std::cell::Cell<Member> = const { std::cell::Cell::new(Member::Stored) };
}

/// Writes `bytes` in `piece` sized pieces through a fresh [`Staged`]
/// over `path` opened as an extract opens a big member, falling back
/// as the staging says; returns the staging's direct bytes at the
/// moment it fell back (`None` if it never did) and leaves the file
/// closed and cut to length.
fn write_staged(path: &Path, bytes: &[u8], piece: usize) -> Option<u64> {
    let _ = std::fs::remove_file(path);
    let mut file = open_direct(path).expect("open");
    assert!(take_direct(&file), "the handle was refused");
    let mut staged = Some(Staged::new(path, &file, MEMBER.with(std::cell::Cell::get)));
    let mut fell_at = None;
    for chunk in bytes.chunks(piece) {
        match staged.as_mut() {
            Some(s) => {
                let before = s.done();
                if !s.put(&mut file, chunk).expect("put") {
                    fell_at = Some(before);
                    staged = None;
                }
            }
            None => file.write_all(chunk).expect("cached write"),
        }
    }
    if let Some(mut s) = staged {
        s.finish(&mut file).expect("finish");
    }
    file.set_len(bytes.len() as u64).expect("cut back");
    fell_at
}

/// **A slow verdict falls back MID-FILE without a byte out of place,
/// and the device is remembered**: under [`Forced::Slow`] the first
/// block goes past the cache, the probe finds the device slow, and the
/// rest of the member goes cached from exactly there. The next output
/// on the same device, nothing forced, falls back before any direct
/// write (the memo says slow). With the memo saying FAST instead, a
/// forced slow probe is never reached: the device is not timed again.
///
/// Through the member's staging, which a plain handle carries as well
/// as a direct one, so this runs on every target.
#[test]
fn a_slow_verdict_falls_back_mid_file_and_is_remembered_per_device() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rarfast-gate-{}", std::process::id()));
    let bytes = noise(3 * BLOCK + 2 * SECTOR + 1234, 11);
    let device = {
        let file = File::create(&path).expect("create");
        device_of(&path, &file)
    };

    for depth in [0, 2] {
        *TEST_DEPTH.lock().unwrap() = Some(depth);
        // Probed, found slow after the first block: mid-file.
        forget();
        *TEST_FORCED.lock().unwrap() = Forced::Slow;
        let fell = write_staged(&path, &bytes, 64 << 10);
        *TEST_FORCED.lock().unwrap() = Forced::None;
        // After the first direct write: a whole block staged, or the
        // first piece straight where the allocation happens to be
        // aligned; with blocks in flight, at most those behind it.
        let most = (depth as u64 + 1) * BLOCK as u64;
        assert!(
            matches!(fell, Some(n) if n > 0 && n <= most),
            "depth {depth}: the fall back was not mid-file after the first direct write: {fell:?}"
        );
        assert!(
            std::fs::read(&path).expect("read") == bytes,
            "depth {depth}: mid-file fall back: bytes"
        );
    }
    *TEST_DEPTH.lock().unwrap() = Some(0);
    assert!(
        std::fs::read(&path).expect("read") == bytes,
        "mid-file fall back: bytes"
    );
    if device.is_some() {
        assert_eq!(remembered(device), Some(Verdict::Slow));

        // Remembered slow: out before the first direct write.
        let fell = write_staged(&path, &bytes, 64 << 10);
        assert_eq!(fell, Some(0), "a device remembered slow was written direct");
        assert!(
            std::fs::read(&path).expect("read") == bytes,
            "remembered slow: bytes"
        );

        // Remembered fast: never timed, so a forced slow probe is never
        // reached and the member stays direct to its end.
        forget();
        remember(device, Verdict::Fast);
        *TEST_FORCED.lock().unwrap() = Forced::Slow;
        let fell = write_staged(&path, &bytes, 4 << 20);
        *TEST_FORCED.lock().unwrap() = Forced::None;
        assert_eq!(fell, None, "a device remembered fast was probed again");
        assert!(
            std::fs::read(&path).expect("read") == bytes,
            "remembered fast: bytes"
        );
    }
    forget();
    *TEST_DEPTH.lock().unwrap() = None;
    let _ = std::fs::remove_file(&path);
}

/// Whether this process is refused by a mode at all: root is not, and
/// the test below then holds nothing a mode could refuse.
#[cfg(unix)]
fn modes_refuse_this_user(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let probe = dir.join(format!("rarfast-mode-probe-{}", std::process::id()));
    let _ = std::fs::remove_file(&probe);
    let file = File::create(&probe).expect("probe");
    file.set_permissions(std::fs::Permissions::from_mode(0o444))
        .expect("probe mode");
    drop(file);
    let refused = std::fs::OpenOptions::new()
        .write(true)
        .open(&probe)
        .is_err();
    let _ = std::fs::remove_file(&probe);
    refused
}

/// **A member created WITHOUT its owner's write bit falls back like
/// any other**: the file holds every byte and ends with the mode it was
/// created with. An extract creates a member with its stored mode, so a
/// read-only binary of 64 MiB or more (`0444`, `0555`) is exactly this
/// file, and the fall back's second open by name is refused by that
/// mode. Until 1 Oct 2026 that refusal ended the extract (`Write error
/// ... Permission denied`, exit 5) on every device the gate finds slow.
///
/// THE UMASK: none is assumed. Each mode is set through the open handle
/// (an `fchmod`), which no umask touches, and read back.
#[cfg(unix)]
#[test]
fn a_member_created_read_only_falls_back_and_keeps_its_mode() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir();
    if !modes_refuse_this_user(&dir) {
        eprintln!("no mode refuses this user (root): nothing to hold");
    }
    let path = dir.join(format!("rarfast-read-only-member-{}", std::process::id()));
    let bytes = noise(2 * BLOCK + 3 * SECTOR + 777, 31);
    *TEST_DEPTH.lock().unwrap() = Some(0);
    for stored in [0o444_u32, 0o555, 0o400, 0o000, 0o4555] {
        let _ = std::fs::remove_file(&path);
        let mut file = open_direct(&path).expect("open");
        assert!(take_direct(&file), "the handle was refused");
        file.set_permissions(std::fs::Permissions::from_mode(stored))
            .expect("the member's mode");
        let made = file.metadata().expect("metadata").permissions().mode() & 0o7777;
        forget();
        *TEST_FORCED.lock().unwrap() = Forced::Slow;
        let mut staged = Some(Staged::new(&path, &file, Member::Stored));
        let mut fell = false;
        for chunk in bytes.chunks(64 << 10) {
            match staged.as_mut() {
                Some(s) => {
                    let kept = s.put(&mut file, chunk);
                    if !kept.unwrap_or_else(|e| {
                        *TEST_FORCED.lock().unwrap() = Forced::None;
                        *TEST_DEPTH.lock().unwrap() = None;
                        panic!("mode {stored:o}: the fall back was refused: {e}")
                    }) {
                        fell = true;
                        staged = None;
                    }
                }
                None => file.write_all(chunk).expect("cached write"),
            }
        }
        *TEST_FORCED.lock().unwrap() = Forced::None;
        assert!(fell, "mode {stored:o}: the slow verdict did not fall back");
        file.set_len(bytes.len() as u64).expect("cut back");
        let left = file.metadata().expect("metadata").permissions().mode() & 0o7777;
        // A write by an ordinary user clears setuid, as on any file;
        // the extract sets a member's final mode after its last write.
        assert_eq!(
            left & 0o777,
            made & 0o777,
            "mode {stored:o}: the member's mode was not put back"
        );
        // Read back through a mode that lets this user read it.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .expect("readable");
        drop(file);
        assert!(
            std::fs::read(&path).expect("read") == bytes,
            "mode {stored:o}: bytes"
        );
    }
    forget();
    *TEST_DEPTH.lock().unwrap() = None;
    let _ = std::fs::remove_file(&path);
}

/// **A link planted at a member's name is refused at the fall back**:
/// the second open by name does not follow a symbolic link at the final
/// component, as the create does not, so the staged bytes are never
/// written through one. The member's name is swapped for a link to
/// another file between its first direct write and the fall back; the
/// fall back fails and the other file is untouched. Until 1 Oct 2026
/// the reopen followed the link and wrote there.
#[cfg(unix)]
#[test]
fn a_link_planted_at_a_members_name_is_refused_at_the_fall_back() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rarfast-swapped-member-{}", std::process::id()));
    let other = dir.join(format!("rarfast-swapped-other-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::write(&other, b"not this run's file").expect("the other file");
    let bytes = noise(2 * BLOCK + 99, 41);
    *TEST_DEPTH.lock().unwrap() = Some(0);
    forget();
    *TEST_FORCED.lock().unwrap() = Forced::Slow;
    let mut file = open_direct(&path).expect("open");
    assert!(take_direct(&file), "the handle was refused");
    let mut staged = Staged::new(&path, &file, Member::Stored);
    // One whole block: it goes to the device and the probe shuts the
    // gate, so the next put is the fall back.
    let first = staged.put(&mut file, &bytes[..BLOCK]);
    std::fs::remove_file(&path).expect("the name removed");
    std::os::unix::fs::symlink(&other, &path).expect("the link planted");
    let second = staged.put(&mut file, &bytes[BLOCK..]);
    *TEST_FORCED.lock().unwrap() = Forced::None;
    drop(staged);
    drop(file);
    let held = std::fs::read(&other).expect("the other file");
    forget();
    *TEST_DEPTH.lock().unwrap() = None;
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&other);
    assert!(matches!(first, Ok(true)), "the first block: {first:?}");
    assert!(
        second.is_err(),
        "the fall back opened through a planted link: {second:?}"
    );
    assert!(
        held == b"not this run's file",
        "the fall back wrote through a planted link"
    );
}

/// **An archive's output falls back mid-file on a slow verdict and
/// stays the same archive**: a whole block goes past the cache, the
/// output stays direct until its next append, then goes cached; a
/// correction of bytes on disk and a read of them after the fall back
/// see what was written. A second output on the device leaves direct
/// writing at its first append.
#[test]
fn an_output_leaves_direct_writing_mid_file_on_a_slow_verdict() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    if !ABLE {
        eprintln!("no past-the-cache open on this target: skipped");
        return;
    }
    let Some(path) = direct_path(&format!("rarfast-gate-output-{}", std::process::id())) else {
        eprintln!("no directory here takes a direct open: skipped");
        return;
    };
    forget();
    // Synchronous writes, so the verdict is in before the next append.
    *TEST_DEPTH.lock().unwrap() = Some(0);
    *TEST_FORCED.lock().unwrap() = Forced::Slow;
    let mut out = Output::create(&path, 100 << 20).expect("create");
    assert!(out.is_direct());
    // Exactly one block: it goes past the cache and the probe shuts the
    // gate with nothing of this append left over, so the output is
    // still direct until the next one.
    let mut want = noise(BLOCK, 21);
    out.write_all(&want).expect("first block");
    assert!(out.is_direct(), "fell back before the next append");
    let more = noise((5 << 20) + 99, 22);
    out.write_all(&more).expect("the rest");
    want.extend_from_slice(&more);
    assert!(!out.is_direct(), "the slow verdict did not fall back");
    out.seek(SeekFrom::Start(10)).expect("seek");
    out.write_all(b"corrected").expect("correct");
    want[10..19].copy_from_slice(b"corrected");
    let mut got = vec![0u8; 64];
    out.seek(SeekFrom::Start(0)).expect("seek");
    out.read_exact(&mut got).expect("read back");
    assert!(got == want[..64], "read after the fall back");
    out.seek(SeekFrom::End(0)).expect("seek end");
    out.close().expect("close");
    drop(out);
    *TEST_FORCED.lock().unwrap() = Forced::None;
    assert!(std::fs::read(&path).expect("read") == want, "output bytes");

    let mut again = Output::create(&path, 100 << 20).expect("create");
    again.write_all(&noise(1 << 20, 23)).expect("write");
    assert!(!again.is_direct(), "a device remembered slow stayed direct");
    again.close().expect("close");
    forget();
    *TEST_DEPTH.lock().unwrap() = None;
    let _ = std::fs::remove_file(&path);
}

/// **The probe times the DEVICE's busy wall**: two writes in flight at
/// once count their overlap once, not twice (each output's share of a
/// drive is not the drive's rate), and time with nothing in flight
/// counts not at all (a producer slower than the device is not the
/// device being slow).
#[test]
fn the_probe_counts_the_devices_busy_wall_once() {
    let busy = |probe: &Probe| {
        let state = probe.state();
        (state.busy, state.bytes, state.writing)
    };
    // Each bound is the test's OWN wall around the calls, taken here: a
    // sleep on a loaded machine runs long by any amount (40 ms was seen to
    // take 76), so a bound in fixed milliseconds asserted the machine. The
    // wall once is at most the wall around it; counted twice it is twice
    // the sleep, which is over that wall.
    let probe = Probe::new();
    let around = std::time::Instant::now();
    probe.start();
    probe.start();
    std::thread::sleep(Duration::from_millis(40));
    probe.end(3);
    probe.end(4);
    let wall = around.elapsed();
    let (first, bytes, writing) = busy(&probe);
    assert_eq!((bytes, writing), (7, 0));
    assert!(
        first >= Duration::from_millis(40) && first <= wall,
        "two overlapping writes counted {first:?}, not the wall once ({wall:?})"
    );
    // Idle: nothing counted. An idle 40 ms and more counted in would put
    // what was added over the wall around the one write.
    std::thread::sleep(Duration::from_millis(40));
    let around = std::time::Instant::now();
    probe.start();
    std::thread::sleep(Duration::from_millis(10));
    probe.end(1);
    let wall = around.elapsed();
    let (second, _, _) = busy(&probe);
    let added = second - first;
    assert!(
        added >= Duration::from_millis(10) && added <= wall,
        "an idle device was counted busy: {added:?} in a write of {wall:?}"
    );
    // A write that failed lands nothing, and its time still counts.
    probe.start();
    probe.end(0);
    assert_eq!(busy(&probe).1, 8);
}

/// **One probe per device**, shared by every output on it: two outputs
/// in one directory join the same probe, and a verdict it reaches is
/// every later output's.
#[test]
fn outputs_on_one_device_share_its_probe() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let _direct = StoredDirect::on();
    let dir = std::env::temp_dir();
    let one = dir.join(format!("rarfast-probe-a-{}", std::process::id()));
    let two = dir.join(format!("rarfast-probe-b-{}", std::process::id()));
    forget();
    let (a, b) = (
        File::create(&one).expect("a"),
        File::create(&two).expect("b"),
    );
    let (sa, sb) = (
        Staged::new(&one, &a, Member::Stored),
        Staged::new(&two, &b, Member::Stored),
    );
    if device_of(&one, &a).is_some() && shared_probe() {
        let (Gate::Probing(pa), Gate::Probing(pb)) = (&sa.gate, &sb.gate) else {
            panic!("an output on an unjudged device was not probing");
        };
        assert!(std::sync::Arc::ptr_eq(pa, pb), "two probes for one device");
        pa.state().verdict = Some(Verdict::Slow);
        assert_eq!(remembered(device_of(&one, &a)), Some(Verdict::Slow));
        // Remembered slow: no direct open at all, the slow form at once.
        if ABLE {
            assert_eq!(
                form_at(LEAST, &dir, Member::Stored, None),
                slow_form(device_of(&one, &a))
            );
            // On the archive's own device a slow verdict is cached.
            note_source(&[&dir], false);
            assert_eq!(form_at(LEAST, &dir, Member::Stored, None), Form::Cached);
            assert_eq!(sa.slow_form(), Form::Cached);
            *SOURCE.lock().unwrap() = Source::NONE;
        }
    }
    drop((sa, sb, a, b));
    forget();
    let _ = std::fs::remove_file(&one);
    let _ = std::fs::remove_file(&two);
}

/// **A big member written back to its archive's own device** is direct,
/// as on any other device: the gate decides, whatever the size.
#[test]
fn a_member_on_its_archives_device_is_left_to_the_gate() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let _direct = StoredDirect::on();
    assert_eq!(same_form(), Form::Direct);
    if !ABLE {
        return;
    }
    let dir = std::env::temp_dir();
    forget();
    *SOURCE.lock().unwrap() = Source::NONE;
    assert_eq!(form_at(LEAST, &dir, Member::Stored, None), Form::Direct);
    note_source(&[&dir], false);
    assert_eq!(form_at(LEAST, &dir, Member::Stored, None), Form::Direct);
    assert_eq!(form_at(8 << 30, &dir, Member::Coded, None), Form::Direct);
    *SOURCE.lock().unwrap() = Source::NONE;
}

/// Every case of the rule on facts: `(member, residency, same device,
/// parity)`.
fn cases() -> Vec<(Member, Residency, bool, bool)> {
    let mut cases = Vec::new();
    for member in [Member::Stored, Member::Coded, Member::Solid] {
        for residency in [Residency::Resident, Residency::Cold, Residency::Unknown] {
            for same in [false, true] {
                for parity in [false, true] {
                    cases.push((member, residency, same, parity));
                }
            }
        }
    }
    cases
}

/// **The rule on facts, row by row** (the form on a device the line
/// found slow): a coded member direct, except a solid archive's on
/// another device, which keeps write-behind where the target has it; a
/// stored member cached where its archive is resident or cannot be
/// sampled; a stored member of a cold archive cached on the archive's
/// own device and direct on another; a parity array cached ahead of them
/// all; and write-behind taken by that one row alone.
#[test]
fn the_rule_on_facts_is_its_table() {
    use Member::{Coded, Solid, Stored};
    use Residency::{Cold, Resident, Unknown};
    let (other, same) = (false, true);
    for residency in [Resident, Cold, Unknown] {
        // A coded member, the archive not solid.
        for place in [other, same] {
            assert_eq!(facts_form(Coded, residency, place, false), Form::Direct);
        }
        // A solid archive's coded member.
        assert_eq!(facts_form(Solid, residency, same, false), Form::Direct);
        assert_eq!(facts_form(Solid, residency, other, false), BEHIND_OR_DIRECT);
    }
    assert_eq!(
        BEHIND_OR_DIRECT == Form::Behind,
        cfg!(all(target_os = "linux", target_env = "gnu")),
        "write-behind where the target has it, direct where it has not"
    );
    // Stored, the archive resident, or not sampled.
    for residency in [Resident, Unknown] {
        for place in [other, same] {
            assert_eq!(facts_form(Stored, residency, place, false), Form::Cached);
        }
    }
    // Stored, the archive cold.
    assert_eq!(facts_form(Stored, Cold, same, false), Form::Cached);
    assert_eq!(facts_form(Stored, Cold, other, false), Form::Direct);
    // A parity array, ahead of every row; and write-behind for the one
    // row alone.
    assert_eq!(cases().len(), 36);
    for (member, residency, place, parity) in cases() {
        let form = facts_form(member, residency, place, parity);
        if parity {
            assert_eq!(form, Form::Cached, "{member:?} {residency:?} {place}");
        }
        if form == Form::Behind {
            assert!(
                member == Solid && !place && !parity,
                "{member:?} {residency:?} {place} {parity}"
            );
        }
    }
}

/// States the rule, the source and the output's parity for a test, and
/// puts the line, no source and no parity back when dropped.
struct Stated;

impl Stated {
    fn facts(member: Member, residency: Residency, device: Option<u64>, parity: bool) -> Stated {
        *TEST_RULE.lock().unwrap() = Some(Rule::Facts);
        *SOURCE.lock().unwrap() = Source { device, residency };
        TEST_PARITY.with(|p| p.set(parity));
        MEMBER.with(|m| m.set(member));
        Stated
    }
}

impl Drop for Stated {
    fn drop(&mut self) {
        *TEST_RULE.lock().unwrap_or_else(|p| p.into_inner()) = None;
        *SOURCE.lock().unwrap_or_else(|p| p.into_inner()) = Source::NONE;
        TEST_PARITY.with(|p| p.set(false));
        MEMBER.with(|m| m.set(Member::Stored));
        *TEST_FORCED.lock().unwrap_or_else(|p| p.into_inner()) = Forced::None;
        *TEST_DEPTH.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// Reads the direct form's own rules for a STORED member, which Linux
/// otherwise writes cached ([`STORED_CACHED`]), until dropped.
struct StoredDirect;

impl StoredDirect {
    fn on() -> StoredDirect {
        *TEST_STORED_DIRECT.lock().unwrap() = true;
        StoredDirect
    }
}

impl Drop for StoredDirect {
    fn drop(&mut self) {
        *TEST_STORED_DIRECT.lock().unwrap_or_else(|p| p.into_inner()) = false;
    }
}

/// **A big STORED member that fits inside the working limit is written
/// cached on Linux, and direct above it; elsewhere direct wherever the
/// target writes direct at all.** A stated `-mm` moves the limit to its
/// own budget's; a coded member keeps the direct form; a form a count
/// build forces wins over the stored rule.
#[test]
fn a_stored_member_inside_the_working_limit_is_cached_on_linux() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(STORED_CACHED, cfg!(target_os = "linux"));
    let limit = rarkit::MemoryPolicy::process_default(0).working_limit;
    let capped = rarkit::MemoryPolicy::for_process(256 << 20, 0).working_limit;
    if STORED_CACHED {
        assert_eq!(stored_cached_up_to(None), limit);
        assert_eq!(stored_cached_up_to(Some(256 << 20)), capped);
        assert!(limit >= 448 << 20 && capped < 256 << 20, "{limit} {capped}");
    } else {
        assert_eq!(stored_cached_up_to(None), 0);
        assert_eq!(stored_cached_up_to(Some(256 << 20)), 0);
    }
    if !ABLE {
        return;
    }
    let dir = std::env::temp_dir();
    forget();
    *SOURCE.lock().unwrap() = Source::NONE;
    let inside = if STORED_CACHED {
        Form::Cached
    } else {
        Form::Direct
    };
    assert_eq!(form_at(LEAST, &dir, Member::Stored, None), inside);
    assert_eq!(form_at(limit, &dir, Member::Stored, None), inside);
    assert_eq!(form_at(limit + 1, &dir, Member::Stored, None), Form::Direct);
    assert_eq!(form_at(LEAST - 1, &dir, Member::Stored, None), Form::Cached);
    // Under `-mm256m` the limit is that budget's, under 256 MiB.
    assert_eq!(
        form_at(LEAST, &dir, Member::Stored, Some(256 << 20)),
        inside
    );
    assert_eq!(
        form_at(capped + 1, &dir, Member::Stored, Some(256 << 20)),
        Form::Direct
    );
    assert_eq!(form_at(LEAST, &dir, Member::Coded, None), Form::Direct);
    assert_eq!(form_at(LEAST, &dir, Member::Solid, None), Form::Direct);
    note_source(&[&dir], false);
    assert_eq!(form_at(LEAST, &dir, Member::Stored, None), inside);
    *SOURCE.lock().unwrap() = Source::NONE;
    for forced in [Forced::On, Forced::Slow] {
        *TEST_FORCED.lock().unwrap() = forced;
        assert_eq!(
            form_at(LEAST, &dir, Member::Stored, None),
            Form::Direct,
            "{forced:?}"
        );
    }
    *TEST_FORCED.lock().unwrap() = Forced::None;
    forget();
}

/// **The shipped rule is the line, and under it no fact is asked**: no
/// sample of the archive is taken, and a slow device's form is
/// [`slow_form`]'s for a coded member and a stored one alike. Under the
/// rule on facts an archive's output (no member) keeps the line's form
/// too.
#[test]
fn the_line_ships_and_asks_no_fact() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(RULE, Rule::Line);
    assert_eq!(rule(), Rule::Line);
    assert!(!samples_source());
    let dir = std::env::temp_dir();
    let device = device_at(&dir);
    // The archive on another device, and on the output's own.
    for source in [None, device] {
        *SOURCE.lock().unwrap() = Source {
            device: source,
            residency: Residency::Cold,
        };
        for member in [
            Some(Member::Stored),
            Some(Member::Coded),
            Some(Member::Solid),
            None,
        ] {
            assert_eq!(slow_for(device, member, &dir), slow_form(device));
        }
        let stated = Stated::facts(Member::Coded, Residency::Cold, source, false);
        assert_eq!(slow_for(device, None, &dir), slow_form(device));
        drop(stated);
    }
    // A sample asked for under the line is not taken.
    let path = dir.join(format!("rarfast-line-{}", std::process::id()));
    std::fs::write(&path, vec![7u8; 1 << 20]).expect("write");
    note_source(&[&path], true);
    assert_eq!(source().residency, Residency::Unknown);
    assert_eq!(source().device, device_at(&path));
    *SOURCE.lock().unwrap() = Source::NONE;
    let _ = std::fs::remove_file(&path);
}

/// **The archive's residency is the one NOTED when the run began, never
/// asked again**: an archive noted cold stays cold for the rule although
/// every page of it is in memory by now (as the run's own reads leave
/// it), and one noted under the rule on facts is sampled there and then.
#[test]
fn the_archives_residency_is_taken_once_when_the_run_begins() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rarfast-noted-{}", std::process::id()));
    // Just written: in the page cache.
    std::fs::write(&path, vec![7u8; 3 << 20]).expect("write");
    let stated = Stated::facts(Member::Stored, Residency::Unknown, None, false);
    note_source(&[&path], true);
    if cfg!(unix) {
        assert_eq!(source().residency, Residency::Resident);
    }
    // A set with a volume that cannot be sampled beside one that is in
    // memory is still resident (unknown changes nothing); a set of
    // nothing leaves the note as it was.
    let gone = dir.join("rarfast-noted-no-such-volume");
    note_source(&[&path, &gone], true);
    if cfg!(unix) {
        assert_eq!(source().residency, Residency::Resident);
    }
    note_source::<&Path>(&[], true);
    assert_eq!(source().device, device_at(&path));
    // Not asked for: not sampled.
    note_source(&[&path], false);
    assert_eq!(source().residency, Residency::Unknown);
    // Noted cold when the run began, resident now: the note stands. On
    // another device than the output's, a stored member stays direct.
    *SOURCE.lock().unwrap() = Source {
        device: None,
        residency: Residency::Cold,
    };
    let device = device_at(&dir);
    if device.is_some() {
        assert_eq!(slow_for(device, Some(Member::Stored), &dir), Form::Direct);
        assert_eq!(source().residency, Residency::Cold);
    }
    drop(stated);
    let _ = std::fs::remove_file(&path);
}

/// **Only an archive WHOLLY in memory is resident for the rule**: one
/// sampled page out of memory in any sampled volume makes it cold (the
/// measured hole: a set's first volumes in memory and the rest on the
/// device read resident by the first volume alone, and was written
/// cached at 0.65x of today on disk); what cannot be sampled changes
/// nothing; and a long set is sampled at its first volume, its last and
/// evenly between.
#[test]
fn only_an_archive_wholly_in_memory_is_resident() {
    use Residency::{Cold, Resident, Unknown};
    let full = (Some(1.0), Resident);
    let cold = (Some(0.0), Cold);
    // The majority verdict of one file is not enough: 70 percent.
    let most = (Some(0.7), Resident);
    let nearly = (Some(63.0 / 64.0), Resident);
    let unknown = (None, Unknown);
    assert_eq!(whole_residency(&[full]), Resident);
    assert_eq!(whole_residency(&[full, full, full]), Resident);
    // The first volumes in memory, the rest not.
    assert_eq!(whole_residency(&[full, full, cold, cold, cold]), Cold);
    assert_eq!(whole_residency(&[cold, full]), Cold);
    assert_eq!(whole_residency(&[most]), Cold);
    assert_eq!(whole_residency(&[full, nearly]), Cold);
    assert_eq!(whole_residency(&[cold]), Cold);
    // What cannot be sampled changes nothing.
    assert_eq!(whole_residency(&[unknown, full]), Resident);
    assert_eq!(whole_residency(&[unknown, cold]), Cold);
    assert_eq!(whole_residency(&[unknown, unknown]), Unknown);
    assert_eq!(whole_residency(&[]), Unknown);
    // A stated verdict with no fraction (a count build's knob).
    assert_eq!(whole_residency(&[(None, Resident)]), Resident);
    assert_eq!(whole_residency(&[(None, Resident), (None, Cold)]), Cold);

    assert_eq!(spread(0, 32), Vec::<usize>::new());
    assert_eq!(spread(1, 32), vec![0]);
    assert_eq!(spread(8, 32), (0..8).collect::<Vec<_>>());
    assert_eq!(spread(32, 32), (0..32).collect::<Vec<_>>());
    for count in [33, 100, 999] {
        let picked = spread(count, 32);
        assert_eq!(picked.len(), 32, "{count}");
        assert_eq!((picked[0], picked[31]), (0, count - 1), "{count}");
        assert!(picked.windows(2).all(|pair| pair[0] < pair[1]), "{count}");
    }
    assert_eq!(spread(5, 1), vec![0]);
}

/// **On a slow device each member takes the form its facts give, byte
/// exact, for every row of the rule and at depths 0 and 2.** The probe
/// is forced slow at its first direct write. A member the rule keeps
/// direct is written direct to its end and the next one on the device,
/// now remembered slow, is too; a member the rule sends cached leaves
/// direct writing mid-file, and the next is never written direct. (The
/// form after a fall back is the rule's: cached, or write-behind for the
/// one row that keeps it; both write through the cache.)
#[test]
fn on_a_slow_device_each_member_takes_the_form_of_its_facts() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let _direct = StoredDirect::on();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rarfast-facts-{}", std::process::id()));
    let bytes = noise(3 * BLOCK + 2 * SECTOR + 1234, 31);
    let device = {
        let file = File::create(&path).expect("create");
        device_of(&path, &file)
    };
    if device.is_none() {
        eprintln!("the device cannot be named here: skipped");
        return;
    }
    for depth in [0, 2] {
        for (member, residency, same, parity) in cases() {
            let case =
                format!("depth {depth}, {member:?}, {residency:?}, same {same}, parity {parity}");
            let want = facts_form(member, residency, same, parity);
            let source = if same { device } else { None };
            let stated = Stated::facts(member, residency, source, parity);
            *TEST_DEPTH.lock().unwrap() = Some(depth);
            assert_eq!(slow_for(device, Some(member), &path), want, "{case}");

            // Probed, and found slow at the first direct write.
            forget();
            *TEST_FORCED.lock().unwrap() = Forced::Slow;
            let fell = write_staged(&path, &bytes, 64 << 10);
            *TEST_FORCED.lock().unwrap() = Forced::None;
            assert_eq!(remembered(device), Some(Verdict::Slow), "{case}");
            assert!(
                std::fs::read(&path).expect("read") == bytes,
                "{case}: bytes"
            );
            match want {
                Form::Direct => assert_eq!(fell, None, "{case}: left direct writing"),
                _ => assert!(
                    matches!(fell, Some(n) if n > 0),
                    "{case}: no fall back mid-file: {fell:?}"
                ),
            }

            // Remembered slow: the next member on the device.
            let fell = write_staged(&path, &bytes, 64 << 10);
            assert!(
                std::fs::read(&path).expect("read") == bytes,
                "{case}: bytes"
            );
            match want {
                Form::Direct => assert_eq!(fell, None, "{case}: remembered slow, left direct"),
                _ => assert_eq!(fell, Some(0), "{case}: remembered slow, written direct"),
            }
            if ABLE {
                assert_eq!(
                    form_at(LEAST, &dir, member, None),
                    want,
                    "{case}: at the open"
                );
            }

            // Rule 1: remembered FAST, direct to the end, nothing asked
            // and nothing timed again.
            forget();
            remember(device, Verdict::Fast);
            *TEST_FORCED.lock().unwrap() = Forced::Slow;
            let fell = write_staged(&path, &bytes, 4 << 20);
            *TEST_FORCED.lock().unwrap() = Forced::None;
            assert_eq!(fell, None, "{case}: a fast device left direct writing");
            if ABLE {
                assert_eq!(form_at(LEAST, &dir, member, None), Form::Direct, "{case}");
            }
            drop(stated);
        }
    }
    forget();
    let _ = std::fs::remove_file(&path);
}

/// **Under a cgroup memory cap an ARCHIVE's output is not timed and stays
/// direct on a device remembered slow; a member's output, and an archive's
/// with no cap, are gated as they were.**
#[test]
fn an_archive_output_under_a_cgroup_cap_stays_direct_on_a_slow_device() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rarfast-capped-{}", std::process::id()));
    forget();
    let file = File::create(&path).expect("create");
    *TEST_DEPTH.lock().unwrap() = Some(0);
    let device = device_of(&path, &file);
    if device.is_some() {
        // No cap, an unjudged device: timed, as before.
        TEST_CAPPED.with(|cell| cell.set(Some(false)));
        let archive = Staged::at_depth(&path, &file, 0, None);
        assert!(
            matches!(archive.gate, Gate::Probing(_)),
            "an archive's output with no cap was not timed"
        );
        drop(archive);
        // A cap: open from the first byte, nothing timed.
        TEST_CAPPED.with(|cell| cell.set(Some(true)));
        let archive = Staged::at_depth(&path, &file, 0, None);
        assert!(
            matches!(archive.gate, Gate::Open),
            "an archive's output under a cap was timed"
        );
        drop(archive);
        // The device remembered slow.
        remember(device, Verdict::Slow);
        let archive = Staged::at_depth(&path, &file, 0, None);
        assert!(
            matches!(archive.gate, Gate::Open),
            "an archive's output under a cap left direct writing on a slow device"
        );
        drop(archive);
        // A member's output is not the archive's: gated as it was.
        let stated = Stated::facts(Member::Stored, Residency::Resident, None, false);
        let member = Staged::new(&path, &file, Member::Stored);
        assert!(
            matches!(member.gate, Gate::Shut),
            "a stored member's output on a slow device stayed direct under a cap"
        );
        drop((member, stated));
        // And with no cap the archive's output there is shut, as before.
        TEST_CAPPED.with(|cell| cell.set(Some(false)));
        let archive = Staged::at_depth(&path, &file, 0, None);
        assert!(
            matches!(archive.gate, Gate::Shut),
            "an archive's output with no cap stayed direct on a slow device"
        );
        drop(archive);
    }
    TEST_CAPPED.with(|cell| cell.set(None));
    *TEST_DEPTH.lock().unwrap() = None;
    drop(file);
    forget();
    let _ = std::fs::remove_file(&path);
}

/// **A MIXED archive: one slow device, two outputs, two forms.** A coded
/// member and a stored one join the device's one probe; its slow verdict
/// keeps the coded member direct and sends the stored one (its archive
/// resident) cached, and the verdict is the device's once.
#[test]
fn a_coded_and_a_stored_member_on_one_slow_device_take_their_own_forms() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir();
    let one = dir.join(format!("rarfast-mixed-a-{}", std::process::id()));
    let two = dir.join(format!("rarfast-mixed-b-{}", std::process::id()));
    forget();
    let (a, b) = (
        File::create(&one).expect("a"),
        File::create(&two).expect("b"),
    );
    let stated = Stated::facts(Member::Stored, Residency::Resident, None, false);
    *TEST_DEPTH.lock().unwrap() = Some(0);
    let (mut coded, mut stored) = (
        Staged::new(&one, &a, Member::Coded),
        Staged::new(&two, &b, Member::Stored),
    );
    if device_of(&one, &a).is_some() {
        let (Gate::Probing(pa), Gate::Probing(pb)) = (&coded.gate, &stored.gate) else {
            panic!("an output on an unjudged device was not probing");
        };
        assert!(std::sync::Arc::ptr_eq(pa, pb), "two probes for one device");
        pa.state().verdict = Some(Verdict::Slow);
        coded.look();
        stored.look();
        assert!(
            matches!(coded.gate, Gate::Open),
            "the coded member left direct"
        );
        assert!(
            matches!(stored.gate, Gate::Shut),
            "the stored member stayed"
        );
        assert_eq!(coded.slow_form(), Form::Direct);
        assert_eq!(stored.slow_form(), Form::Cached);
        assert_eq!(remembered(device_of(&one, &a)), Some(Verdict::Slow));
    }
    drop((coded, stored, a, b, stated));
    forget();
    let _ = std::fs::remove_file(&one);
    let _ = std::fs::remove_file(&two);
}

/// Below [`LEAST`] an output is written through the cache, as every
/// small member is.
#[test]
fn a_small_output_is_written_through_the_cache() {
    let path = std::env::temp_dir().join(format!("rarfast-output-small-{}", std::process::id()));
    let mut out = Output::create(&path, LEAST - 1).expect("create");
    assert!(!out.is_direct());
    out.write_all(b"small").expect("write");
    out.close().expect("close");
    assert_eq!(std::fs::read(&path).expect("read"), b"small");
    let _ = std::fs::remove_file(&path);
}

/// **A full block whose hand-over to the writer fails is still the block
/// the fall back writes.** The block is moved into its job and a spare
/// put in its place BEFORE the send; where the send found no writer (its
/// thread gone), the job was dropped with the block in it and the fall
/// back wrote the spare's stale bytes in its place, 4 MiB of an earlier
/// block under a checksum the engine had already taken from the right
/// ones.
///
/// One writer thread, started by the staging itself (depth 1); two blocks
/// and a tail, about 12 MiB held. Through a plain handle, so this runs on
/// every target.
#[test]
fn a_block_whose_hand_over_fails_is_the_block_the_fall_back_writes() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let path = std::env::temp_dir().join(format!("rarfast-handover-{}", std::process::id()));
    let mut file = File::create(&path).expect("create");
    // Remembered fast, so nothing is timed and the gate cannot shut.
    forget();
    let device = device_of(&path, &file);
    remember(device, Verdict::Fast);
    let mut staged = Staged::at_depth(&path, &file, 1, None);
    let (first, second, tail) = (noise(BLOCK, 21), noise(BLOCK, 22), noise(1000, 23));
    assert!(staged.put(&mut file, &first).expect("the first block"));
    {
        let ring = staged.ring.as_mut().expect("a writer at depth 1");
        // The first block lands and its store comes back as the spare,
        // holding the first block's bytes.
        while ring.in_flight > 0 && ring.reap(true) {}
        assert!(ring.failed.is_empty(), "the first block's write failed");
        // The writer is gone: the next hand-over finds no receiver.
        let (dead, gone) = std::sync::mpsc::channel();
        drop(gone);
        ring.jobs = Some(dead);
    }
    let direct = staged.put(&mut file, &second).expect("the second block");
    assert!(!direct, "a refused hand-over did not fall back");
    file.write_all(&tail).expect("the tail, cached");
    drop(staged);
    drop(file);
    forget();
    let got = std::fs::read(&path).expect("read");
    let _ = std::fs::remove_file(&path);
    assert_eq!(got.len(), 2 * BLOCK + tail.len(), "length");
    assert!(got[..BLOCK] == first[..], "the first block");
    assert!(
        got[BLOCK..2 * BLOCK] != first[..],
        "the second block's place holds the FIRST block: the spare's stale bytes"
    );
    assert!(got[BLOCK..2 * BLOCK] == second[..], "the second block");
    assert!(got[2 * BLOCK..] == tail[..], "the tail");
}

/// **A direct write refused for want of SPACE is the write's error, and
/// nothing is then written through the cache.** Until 4 Oct 2026 any failed
/// direct write sent the output to its fall back: the file opened again
/// cached, and the staged block and the caller's bytes written there. On a
/// full volume that second write is refused too, but the kernel takes the
/// cache pages for it BEFORE it finds no room, and under a cgroup memory
/// cap with nothing left to reclaim that allocation is what the process is
/// killed for (exit 137, nothing said), where the run owed a write error
/// and its usual exit.
///
/// Counted here by what reaches the file after the refusal: the staging is
/// over a plain handle and the fall back writes through a second one, so
/// every byte past the first block is the fall back's. One block lands, the
/// volume then "fills" ([`Forced::Full`]): the next block's put, a put of
/// an aligned piece, the tail's finish, and a settle once the gate has
/// shut (a slow verdict arriving late) each return `StorageFull` and the
/// file stays one block long. At depth 0 (every shipped output but a
/// Windows member's) and depth 1 (that one).
///
/// One writer thread at depth 1, none at depth 0; about 16 MiB held.
/// Through a plain handle, so this runs on every target.
#[test]
fn a_full_volume_is_the_writes_error_and_nothing_goes_through_the_cache() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    for depth in [0, 1] {
        for tail_only in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "rarfast-full-{depth}-{tail_only}-{}",
                std::process::id()
            ));
            let mut file = File::create(&path).expect("create");
            // Remembered fast, so nothing is timed and the gate cannot shut.
            forget();
            let device = device_of(&path, &file);
            remember(device, Verdict::Fast);
            let mut staged = Staged::at_depth(&path, &file, depth, None);
            let (first, second) = (noise(BLOCK + 1000, 31), noise(BLOCK, 32));
            assert!(staged.put(&mut file, &first).expect("the first block"));
            assert!(staged.settle(&mut file).expect("the first block lands"));
            *TEST_FORCED.lock().unwrap() = Forced::Full;
            let mut refusals = Vec::new();
            if !tail_only {
                // The block being filled comes full and is refused; at
                // depth 1 the refusal is known by the time the next block
                // is handed over, or at the settle.
                refusals.push(
                    staged
                        .put(&mut file, &second)
                        .and_then(|_| staged.put(&mut file, &second))
                        .and_then(|_| staged.settle(&mut file)),
                );
            }
            refusals.push(staged.finish(&mut file).map(|()| true));
            *TEST_FORCED.lock().unwrap() = Forced::None;
            // The device's verdict comes in slow as the failed output is
            // let go: a shut gate asks for the fall back at the next
            // settle, and that is refused too.
            staged.gate = Gate::Shut;
            refusals.push(staged.settle(&mut file));
            drop(staged);
            drop(file);
            forget();
            let reached = std::fs::metadata(&path).expect("the output").len();
            let _ = std::fs::remove_file(&path);
            for refusal in refusals {
                let kind = refusal.as_ref().err().map(std::io::Error::kind);
                assert_eq!(
                    kind,
                    Some(std::io::ErrorKind::StorageFull),
                    "depth {depth}, tail only {tail_only}: a write refused for want of \
                     space answered {refusal:?}"
                );
            }
            assert_eq!(
                reached,
                BLOCK as u64,
                "depth {depth}, tail only {tail_only}: {} bytes were written through the \
                 cache after the volume was full",
                reached.saturating_sub(BLOCK as u64)
            );
        }
    }
}
