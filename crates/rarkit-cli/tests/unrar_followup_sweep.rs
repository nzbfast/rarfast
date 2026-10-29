//! Small faults of the extract and list dialect, each measured against
//! rar and unrar 7.23 on macOS arm64 on 4 Oct 2026 (the Windows rows on a
//! Windows 11 PC with Rar.exe and UnRAR.exe 7.23 the same day) and pinned
//! here one test an item.
//!
//! Every archive is built in the test, with the engine's own writer or
//! with `rarfast a`, so the bytes are the same on every system; a listed
//! name is compared with the SYSTEM's separator.
//!
//! Assumes: no thread pool to speak of (members of a few bytes; every run
//! that reads an archive states `-mt1`), under 16 MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// One test's directory with two copies of rarfast in it, one named
/// `unrar` and one under its own name: the name selects the dialect.
struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    own: PathBuf,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-fu-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = std::env::consts::EXE_SUFFIX;
        let unrar = dir.join(format!("unrar{exe}"));
        let own = dir.join(format!("rarfast{exe}"));
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &own);
        Bench { dir, unrar, own }
    }

    fn names(&self) -> [(&'static str, &Path); 2] {
        [("unrar", &self.unrar), ("rarfast", &self.own)]
    }

    /// `<exe> <args>` in the bench's directory, standard input closed.
    fn run(&self, exe: &Path, args: &[&str]) -> Output {
        output_of(
            Command::new(exe)
                .args(args)
                .current_dir(&self.dir)
                .stdin(Stdio::null()),
        )
        .expect("the command runs")
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One member of an archive [`write_archive`] makes: its name with `/`,
/// its bytes, its modification time in Unix seconds (or none at all), and
/// whether it is a directory.
struct Entry {
    name: &'static str,
    bytes: &'static [u8],
    mtime: Option<i64>,
    directory: bool,
}

fn file(name: &'static str, bytes: &'static [u8], mtime: Option<i64>) -> Entry {
    Entry {
        name,
        bytes,
        mtime,
        directory: false,
    }
}

/// A stored RAR 5 archive of `entries` at `path`, written by the engine.
fn write_archive(path: &Path, entries: &[Entry]) {
    use rarkit::{HostOs, MemberSpec, Payload, Timestamp, WriteOptions, Writer};
    let mut writer = Writer::new(WriteOptions::default()).expect("options");
    for entry in entries {
        writer
            .add(MemberSpec {
                name: entry.name.as_bytes(),
                payload: Payload::Bytes(entry.bytes),
                mtime: entry.mtime.map(|unix_seconds| Timestamp {
                    unix_seconds,
                    nanos: 0,
                }),
                attributes: if entry.directory {
                    0o040_755
                } else {
                    0o100_644
                },
                host_os: HostOs::Unix,
                is_directory: entry.directory,
            })
            .expect("add");
    }
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).expect("finish");
    std::fs::write(path, bytes).unwrap();
}

/// 2019-01-02 03:04:05 UTC, and a time a day ago.
const OLD: i64 = 1_546_398_245;
fn recent() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    i64::try_from(now).unwrap() - 86_400
}

/// The lines of a run's standard output.
fn lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Item 1. `mf` is a creator command under rarfast's own name, as `m` is:
/// rar 7.23 `mf z.rar f.txt` archives the file and deletes it, exit 0.
/// It answered the decoder's help screen, exit 7, and did nothing.
#[test]
fn mf_under_our_own_name_reaches_the_creator() {
    let bench = Bench::new("mf");
    std::fs::write(bench.dir.join("f.txt"), b"moved").unwrap();
    let out = bench.run(&bench.own, &["mf", "-idq", "-mt1", "z.rar", "f.txt"]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(bench.dir.join("z.rar").is_file(), "{}", said(&out));
    assert!(!bench.dir.join("f.txt").exists(), "the file was not moved");
    let listed = bench.run(&bench.own, &["lb", "-mt1", "z.rar"]);
    assert_eq!(String::from_utf8_lossy(&listed.stdout), "f.txt\n");
}

/// Item 2. `-t` and a tail the reference does not know is `Unknown
/// option`, exit 7, on a listing, a test and an extraction; it was
/// swallowed, exit 0. unrar 7.23 takes, after `-t`, nothing or a first
/// character of `a b c n o s v -` in either case, and refuses every other
/// (`-tq`, `-t1`, `-tx`, `-t+`, `-tk`, `-tl`); rar 7.23 also takes `-tk`
/// and `-tl`, so rarfast's own name, which reads both sets, does too.
/// The kind and the field letter are read in either case: `-tA20200101`
/// and `-TB20200101` filter as `-ta` and `-tb` do, where they filtered
/// nothing.
#[test]
fn a_t_switch_the_reference_refuses_is_an_unknown_option() {
    let bench = Bench::new("ttail");
    write_archive(
        &bench.dir.join("set.rar"),
        &[
            file("old.txt", b"old", Some(OLD)),
            file("new.txt", b"new", Some(recent())),
        ],
    );
    for (name, exe) in bench.names() {
        for tail in ["tq", "t1", "tx", "td", "t+", "tQ", "t\u{e9}"] {
            for command in ["lb", "t", "x"] {
                let switch = format!("-{tail}");
                let out = bench.run(exe, &[command, "-mt1", &switch, "set.rar", "out/"]);
                let what = format!("{name} {command} {switch}: {}", said(&out));
                assert_eq!(out.status.code(), Some(7), "{what}");
                assert_eq!(
                    String::from_utf8_lossy(&out.stdout),
                    format!("\nERROR: Unknown option: {tail}\n"),
                    "{what}"
                );
                assert!(!bench.dir.join("out").exists(), "{what}");
            }
        }
        // Taken, and nothing is filtered by them.
        for switch in [
            "-t", "-tc", "-tv", "-t-", "-tC", "-tV", "-ts", "-tcx", "-tv1",
        ] {
            let out = bench.run(exe, &["lb", "-mt1", switch, "set.rar"]);
            let what = format!("{name} lb {switch}: {}", said(&out));
            assert_eq!(out.status.code(), Some(0), "{what}");
            assert_eq!(lines(&out), ["old.txt", "new.txt"], "{what}");
        }
        // Either case of the kind and of the field.
        for (switch, kept) in [
            ("-tA20200101", "new.txt"),
            ("-TA20200101", "new.txt"),
            ("-tAM20200101", "new.txt"),
            ("-tB20200101", "old.txt"),
            ("-TN7d", "new.txt"),
            ("-tO7D", "old.txt"),
        ] {
            let out = bench.run(exe, &["lb", "-mt1", switch, "set.rar"]);
            let what = format!("{name} lb {switch}: {}", said(&out));
            assert_eq!(out.status.code(), Some(0), "{what}");
            assert_eq!(lines(&out), [kept], "{what}");
        }
    }
    // `-tk` and `-tl` are the creator's: refused under the name unrar,
    // taken under rarfast's own.
    for switch in ["-tk", "-tl"] {
        let out = bench.run(&bench.unrar, &["lb", "-mt1", switch, "set.rar"]);
        assert_eq!(out.status.code(), Some(7), "unrar {switch}: {}", said(&out));
        let out = bench.run(&bench.own, &["lb", "-mt1", switch, "set.rar"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "rarfast {switch}: {}",
            said(&out)
        );
        assert_eq!(lines(&out), ["old.txt", "new.txt"], "rarfast {switch}");
    }
}

/// Item 3. A time filter on the creation or the access time is REFUSED by
/// name, exit 7, with nothing listed or written: it read the modification
/// time instead. The reference (rar and unrar 7.23) judges `-t[abno]c` and
/// `-t[abno]a` on the member's OWN creation and access time, and a member
/// that stores none is never newer and always older: over an archive with
/// modification times alone `lb -tnc7d` and `-tac20200101` list nothing
/// and `-toc7d` and `-tbc20200101` list every member. The engine's member
/// record carries the modification time only, so until it carries the
/// other two the switch cannot be honoured. The `m` and `o` fields and the
/// bare forms read the modification time, as the reference does.
#[test]
fn a_time_filter_on_creation_or_access_time_exits_7_naming_its_form() {
    let bench = Bench::new("tfield");
    write_archive(
        &bench.dir.join("set.rar"),
        &[
            file("old.txt", b"old", Some(OLD)),
            file("new.txt", b"new", Some(recent())),
        ],
    );
    for (name, exe) in bench.names() {
        for (switch, named) in [
            ("-tnc7d", "-t[abno]c"),
            ("-tna7d", "-t[abno]a"),
            ("-toc7d", "-t[abno]c"),
            ("-toa7d", "-t[abno]a"),
            ("-tac20200101", "-t[abno]c"),
            ("-taa20200101", "-t[abno]a"),
            ("-tbc20200101", "-t[abno]c"),
            ("-tba20200101", "-t[abno]a"),
            ("-tNC7d", "-t[abno]c"),
        ] {
            for command in ["lb", "l", "t", "x", "p"] {
                let out = bench.run(exe, &[command, "-mt1", switch, "set.rar", "out/"]);
                let what = format!("{name} {command} {switch}: {}", said(&out));
                assert_eq!(out.status.code(), Some(7), "{what}");
                assert!(out.stdout.is_empty(), "{what}");
                let stderr = String::from_utf8_lossy(&out.stderr);
                assert!(stderr.contains(named), "{what}");
                assert!(stderr.contains("refused"), "{what}");
                assert!(!bench.dir.join("out").exists(), "{what}");
            }
        }
        for (switch, kept) in [
            ("-tn7d", "new.txt"),
            ("-tnm7d", "new.txt"),
            ("-tno7d", "new.txt"),
            ("-tom7d", "old.txt"),
            ("-tao20200101", "new.txt"),
            ("-tbm20200101", "old.txt"),
        ] {
            let out = bench.run(exe, &["lb", "-mt1", switch, "set.rar"]);
            let what = format!("{name} lb {switch}: {}", said(&out));
            assert_eq!(out.status.code(), Some(0), "{what}");
            assert_eq!(lines(&out), [kept], "{what}");
        }
    }
}

/// Item 4. `-sl<size>` and `-sm<size>` in the extract and list dialect,
/// as rar and unrar 7.23 read them (the two agree on every row):
///
/// - `-sl` keeps a file SMALLER than the size and `-sm` one LARGER; a
///   directory is kept by both, `-sl0` included;
/// - the size is bytes, or carries a unit as its LAST character: `k m g
///   t` are powers of 1024, `K M G T` powers of 1000, anything else bytes
///   (`-sl1kb` is one byte);
/// - a text that does not begin with a digit is no filter and leaves an
///   earlier one standing; the last of each switch wins; both together
///   are both applied;
/// - odd spellings, fitted: the digits are read together whatever stands
///   between them (`-sl1k5` is 15 bytes), and a point makes a fraction
///   (`-sl0.5k` is 512, `-sl1.5` is 1).
///
/// Until then `-sl` read the digits alone, so `lb -sl1m` listed the empty
/// file only, `-sl0` dropped the directory, and `-sm` was not read at all.
#[test]
fn the_size_switches_read_a_unit_and_keep_a_directory() {
    static ZEROS: [u8; 1025] = [0; 1025];
    let sizes = [0, 14, 15, 511, 512, 999, 1000, 1001, 1023, 1024, 1025];
    let names: Vec<&'static str> = sizes
        .iter()
        .map(|size| &*Box::leak(format!("f{size}").into_boxed_str()))
        .collect();
    let mut entries: Vec<Entry> = sizes
        .iter()
        .zip(&names)
        .map(|(&size, &name)| file(name, &ZEROS[..size], Some(OLD)))
        .collect();
    entries.push(Entry {
        name: "d",
        bytes: b"",
        mtime: Some(OLD),
        directory: true,
    });
    let bench = Bench::new("size");
    write_archive(&bench.dir.join("set.rar"), &entries);
    // The files a row keeps, by size; the directory is kept by every row.
    let under = |limit: usize| sizes.iter().copied().filter(|&s| s < limit).collect();
    let over = |limit: usize| sizes.iter().copied().filter(|&s| s > limit).collect();
    let all = || sizes.to_vec();
    let rows: Vec<(&[&str], Vec<usize>)> = vec![
        (&["-sl1"], under(1)),
        (&["-sl1000"], under(1000)),
        (&["-sl1001"], under(1001)),
        (&["-sl1k"], under(1024)),
        (&["-sl1K"], under(1000)),
        (&["-sl1m"], all()),
        (&["-sl1M"], all()),
        (&["-sl1g"], all()),
        (&["-sl1G"], all()),
        (&["-sl1t"], all()),
        (&["-sl1T"], all()),
        (&["-sl0"], vec![]),
        (&["-sl1b"], under(1)),
        (&["-sl1x"], under(1)),
        (&["-sl1kb"], under(1)),
        (&["-sl"], all()),
        (&["-slk"], all()),
        (&["-slx5"], all()),
        (&["-sl-5"], all()),
        (&["-SL15"], under(15)),
        (&["-sL15"], under(15)),
        (&["-sl1k5"], under(15)),
        (&["-sl00015"], under(15)),
        (&["-sl0.5k"], under(512)),
        (&["-sl1.5"], under(1)),
        (&["-sl0.999K"], under(999)),
        (&["-sl15", "-sl"], under(15)),
        (&["-sl15", "-slx"], under(15)),
        (&["-sl1m", "-sl1k"], under(1024)),
        (&["-sl18446744073709551615"], vec![]),
        (&["-sm0"], over(0)),
        (&["-sm999"], over(999)),
        (&["-sm1000"], over(1000)),
        (&["-sm1k"], over(1024)),
        (&["-sm1K"], over(1000)),
        (&["-SM1K"], over(1000)),
        (&["-sm1m"], vec![]),
        (&["-sm1kb"], over(1)),
        (&["-sm0.5k"], over(512)),
        (&["-sm"], all()),
        (&["-smx5"], all()),
        (&["-sm1k", "-sm"], over(1024)),
        (&["-sm1k", "-sm14"], over(14)),
        (&["-sm18446744073709551615"], all()),
        (
            &["-sm14", "-sl1k"],
            vec![15, 511, 512, 999, 1000, 1001, 1023],
        ),
    ];
    for (name, exe) in bench.names() {
        for (switches, kept) in &rows {
            let mut args = vec!["lb", "-mt1"];
            args.extend_from_slice(switches);
            args.push("set.rar");
            let out = bench.run(exe, &args);
            let what = format!("{name} lb {switches:?}: {}", said(&out));
            assert_eq!(out.status.code(), Some(0), "{what}");
            let mut expected: Vec<String> = kept.iter().map(|size| format!("f{size}")).collect();
            expected.push("d".to_owned());
            assert_eq!(lines(&out), expected, "{what}");
        }
        // An extraction honours them as the listing does.
        let room = format!("out-{name}");
        let dest = format!("{room}/");
        let out = bench.run(exe, &["x", "-mt1", "-idq", "-sm1k", "set.rar", &dest]);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", said(&out));
        let mut left: Vec<String> = std::fs::read_dir(bench.dir.join(&room))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["d", "f1025"], "{name}");
    }
}

/// Item 5. A member that stores no time lists `????-??-?? ??:??` in the
/// `l` and `v` tables, as unrar 7.23 prints it on macOS and UnRAR.exe 7.23
/// on Windows (an archive made with `rar a -tsm-`, and one of the
/// engine's writer's); the column was left blank. The technical listing
/// has no time line for it at either, and that is unchanged.
#[test]
fn a_member_with_no_time_lists_question_marks() {
    let bench = Bench::new("notime");
    write_archive(
        &bench.dir.join("set.rar"),
        &[
            file("none.txt", b"n", None),
            file("old.txt", b"o", Some(OLD)),
        ],
    );
    for (name, exe) in bench.names() {
        let out = bench.run(exe, &["l", "-mt1", "set.rar"]);
        let what = format!("{name} l: {}", said(&out));
        assert_eq!(out.status.code(), Some(0), "{what}");
        assert!(
            lines(&out).contains(&" -rw-r--r--          1  ????-??-?? ??:??  none.txt".to_owned()),
            "{what}"
        );
        let out = bench.run(exe, &["v", "-mt1", "set.rar"]);
        let what = format!("{name} v: {}", said(&out));
        assert_eq!(out.status.code(), Some(0), "{what}");
        assert!(
            lines(&out).contains(
                &" -rw-r--r--          1          1 100%  ????-??-?? ??:??  7808A3D2  none.txt"
                    .to_owned()
            ),
            "{what}"
        );
        // A member with a time keeps its own, and the marks are nowhere
        // else.
        let marked = lines(&out).iter().filter(|l| l.contains("????")).count();
        assert_eq!(marked, 1, "{what}");
        let out = bench.run(exe, &["lt", "-mt1", "set.rar"]);
        let what = format!("{name} lt: {}", said(&out));
        assert_eq!(out.status.code(), Some(0), "{what}");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(!text.contains('?'), "{what}");
        let times = lines(&out)
            .iter()
            .filter(|l| l.contains("mtime: ") || l.contains("Modified: "))
            .count();
        assert_eq!(times, 1, "{what}");
    }
}

/// Item 6. A list file's line, as unrar 7.23 reads it (macOS arm64, some
/// forty lists; the first five rows again with UnRAR.exe on Windows 11):
///
/// - the space or tab BEFORE a name is part of the name; only what trails
///   it is dropped. Both ends were trimmed, so a line of a space and
///   `a.txt` chose `a.txt` and not the member named with the space;
/// - a line that begins and ends with a double quote names what stands
///   between them, a trailing space included; one that only begins or
///   only ends with one is taken as written;
/// - two slashes and everything after them are a remark, dropped before
///   the rest is read;
/// - a carriage return ends a line as a line feed does;
/// - a line with nothing left is no name.
///
/// Each row is the list's bytes and the members it chooses as a
/// positional; the same list under `-x@` excludes exactly those.
#[test]
fn a_list_file_line_keeps_its_leading_space_and_reads_quotes_and_remarks() {
    let bench = Bench::new("listline");
    // Windows shows a name that ends with a space, or holds a tab, with
    // an underscore in its place, and a mask is matched against the name
    // as shown: the two members that need those, and their rows, are left
    // out there.
    let everywhere = [" a.txt", "a.txt", "c.txt"];
    let all: Vec<&'static str> = if cfg!(windows) {
        everywhere.to_vec()
    } else {
        [&everywhere[..], &["q.txt ", "\tt.txt"]].concat()
    };
    let entries: Vec<Entry> = all.iter().map(|name| file(name, b"x", Some(OLD))).collect();
    write_archive(&bench.dir.join("set.rar"), &entries);
    // The list's bytes, the members it chooses, and whether the row needs
    // a member Windows does not have here.
    let rows: [(&[u8], &[&str], bool); 20] = [
        (b"a.txt\n", &["a.txt"], false),
        (b" a.txt\n", &[" a.txt"], false),
        (b"a.txt \n", &["a.txt"], false),
        (b" a.txt \n", &[" a.txt"], false),
        (b"\tt.txt\n", &["\tt.txt"], true),
        (b"c.txt\t\n", &["c.txt"], false),
        (b"c.txt \t \n", &["c.txt"], false),
        (b"\"q.txt \"\n", &["q.txt "], true),
        (b"\"q.txt \" \n", &["q.txt "], true),
        (b"\"a.txt\"\n", &["a.txt"], false),
        (b" \"q.txt \"\n", &[], true),
        (b"\"a.txt\n", &[], false),
        (b"a.txt\"\n", &[], false),
        (b"\"a.txt\"x\n", &[], false),
        (b"a.txt // a remark\n", &["a.txt"], false),
        (b"//c.txt\na.txt\n", &["a.txt"], false),
        (b"c.txt//\n", &["c.txt"], false),
        (b"\"q.txt \"//n\n", &["q.txt "], true),
        (b"a.txt\rc.txt\n", &["a.txt", "c.txt"], false),
        (b"a.txt\r\nc.txt\r\n", &["a.txt", "c.txt"], false),
    ];
    // A listing prints a name as stored; the space that ends one is not
    // compared, since a console may not show it.
    let listed = |out: &Output| -> Vec<String> {
        lines(out)
            .iter()
            .map(|line| line.trim_end_matches(' ').to_owned())
            .collect()
    };
    let shown = |names: &[&str]| -> Vec<String> {
        names
            .iter()
            .map(|name| name.trim_end_matches(' ').to_owned())
            .collect()
    };
    for (name, exe) in bench.names() {
        for (number, (bytes, chosen, unix_only)) in rows.iter().enumerate() {
            if *unix_only && cfg!(windows) {
                continue;
            }
            let list = format!("row{number}.lst");
            std::fs::write(bench.dir.join(&list), bytes).unwrap();
            let told = format!("{name} {:?}", String::from_utf8_lossy(bytes));
            let out = bench.run(exe, &["lb", "-mt1", "set.rar", &format!("@{list}")]);
            assert_eq!(out.status.code(), Some(0), "{told}: {}", said(&out));
            assert_eq!(listed(&out), shown(chosen), "{told}: {}", said(&out));
            let out = bench.run(exe, &["lb", "-mt1", &format!("-n@{list}"), "set.rar"]);
            assert_eq!(listed(&out), shown(chosen), "{told} as -n: {}", said(&out));
            let rest: Vec<&str> = all
                .iter()
                .copied()
                .filter(|name| !chosen.contains(name))
                .collect();
            let out = bench.run(exe, &["lb", "-mt1", &format!("-x@{list}"), "set.rar"]);
            assert_eq!(listed(&out), shown(&rest), "{told} as -x: {}", said(&out));
        }
        // A line with nothing left is no name: such a list filters nothing
        // as an include, and as a positional selects nothing.
        for bytes in [
            &b"   \n"[..],
            b" //c.txt\n",
            b"\"//c.txt\"\n",
            b"\"\n",
            b"\"\"\n",
            b"\t\r\n",
        ] {
            std::fs::write(bench.dir.join("none.lst"), bytes).unwrap();
            let told = format!("{name} {:?}", String::from_utf8_lossy(bytes));
            let include = format!("-n@{}", "none.lst");
            let out = bench.run(exe, &["lb", "-mt1", &include, "set.rar"]);
            assert_eq!(listed(&out), shown(&all), "{told}: {}", said(&out));
            let out = bench.run(exe, &["lb", "-mt1", "set.rar", "@none.lst"]);
            assert!(out.stdout.is_empty(), "{told}: {}", said(&out));
        }
    }
}

/// Item 7. `t -ep` prints no line for a directory, as rar and unrar 7.23
/// (macOS arm64, and UnRAR.exe on Windows 11): the files keep their lines
/// with their whole paths, the directories' own lines go, and an archive
/// of directories alone ends `No files to extract`, exit 10. rarfast
/// printed the directory lines. `-ep1`, `-ep2`, `-ep3` and `-ep4` keep
/// them at the reference, and a listing is the same with `-ep` as without.
#[test]
fn a_test_with_ep_prints_no_line_for_a_directory() {
    let directory = |name| Entry {
        name,
        bytes: b"",
        mtime: Some(OLD),
        directory: true,
    };
    let bench = Bench::new("tep");
    write_archive(
        &bench.dir.join("set.rar"),
        &[
            file("dir/inner/q.txt", b"q", Some(OLD)),
            file("dir/z.txt", b"z", Some(OLD)),
            directory("dir/inner"),
            directory("dir"),
        ],
    );
    write_archive(
        &bench.dir.join("dirs.rar"),
        &[directory("only/e"), directory("only")],
    );
    let sep = std::path::MAIN_SEPARATOR;
    // The names of the `Testing` lines, in order.
    let tested = |out: &Output| -> Vec<String> {
        lines(out)
            .iter()
            .filter_map(|line| line.strip_prefix("Testing     "))
            .filter_map(|rest| rest.split_whitespace().next())
            .map(str::to_owned)
            .collect()
    };
    let files = [format!("dir{sep}inner{sep}q.txt"), format!("dir{sep}z.txt")];
    let with_directories = [
        files[0].clone(),
        files[1].clone(),
        format!("dir{sep}inner"),
        "dir".to_owned(),
    ];
    for (name, exe) in bench.names() {
        for switch in ["-ep1", "-ep2", "-ep3", "-ep4dir", "-idp"] {
            let out = bench.run(exe, &["t", "-mt1", switch, "set.rar"]);
            let what = format!("{name} t {switch}: {}", said(&out));
            assert_eq!(out.status.code(), Some(0), "{what}");
            assert_eq!(tested(&out), with_directories, "{what}");
        }
        let out = bench.run(exe, &["t", "-mt1", "-ep", "set.rar"]);
        let what = format!("{name} t -ep: {}", said(&out));
        assert_eq!(out.status.code(), Some(0), "{what}");
        assert_eq!(tested(&out), files, "{what}");
        assert!(lines(&out).contains(&"All OK".to_owned()), "{what}");

        let out = bench.run(exe, &["t", "-mt1", "-ep", "dirs.rar"]);
        let what = format!("{name} t -ep, directories alone: {}", said(&out));
        assert_eq!(out.status.code(), Some(10), "{what}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "\nTesting archive dirs.rar\n\nNo files to extract\n",
            "{what}"
        );

        let out = bench.run(exe, &["lb", "-mt1", "-ep", "set.rar"]);
        assert_eq!(
            lines(&out),
            with_directories,
            "{name} lb -ep: {}",
            said(&out)
        );
    }
}
