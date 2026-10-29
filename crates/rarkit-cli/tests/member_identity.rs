//! No member's bytes are written, or called `OK`, under a name they do not
//! belong to: the extract dialect over archives whose file headers do not
//! line up one to one with the members the engine opens.
//!
//! Each shape below put the tool one member out of step with the engine
//! until 8 Oct 2026, and from there every later member's bytes were
//! written to, and reported `OK` under, a neighbouring member's name (the
//! run as a whole still ended 2 or 3). What each asserts is the bytes of
//! every file written, against the member of that name, and that every
//! `OK` line names a file that is right; the exit code comes after.
//!
//! The expectation is unrar 7.23's outcome, measured on macOS arm64 on
//! 8 Oct 2026 over inputs of the same shapes: it passes over a file header
//! flagged "split before" that does not continue the member it is
//! unpacking, says nothing of it, and delivers every other member, `All
//! OK`, exit 0. The one shape where it does NOT deliver every file is the
//! cleared "split after" bit: there it writes the member's first fragment
//! alone and calls that `OK`, exit 0; this tool says `checksum error` for
//! that member, exit 3, and delivers every other member as it does.
//!
//! **Inputs.** A RAR 5 archive is written here by this tree's own writer
//! (`rarfast a`, stored, so a fragment is the member's own bytes) and then
//! edited by block; the RAR 1.5, 2.0 and 2.9 sets are the committed
//! `fixtures/legacy/archives` volume sets with one block written twice,
//! since no writer here makes those formats.
//!
//! Assumes: every run that reads states its width, `-mt1` or `-mt4` (the
//! walk on one thread, and through the pool); under 64 MiB of memory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// The widths every shape is read at.
const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

/// The members of every RAR 5 input here, in archive order, with sizes
/// that put a volume end inside most of them at [`VOLUME`].
const MEMBERS: [(&str, usize); 8] = [
    ("f0_a.bin", 9_000),
    ("f1_b.bin", 33_000),
    ("f2_c.bin", 61_000),
    ("f3_d.bin", 120_007),
    ("f4_e.bin", 45_001),
    ("f5_f.bin", 77_777),
    ("f6_g.bin", 15_003),
    ("f7_h.bin", 98_123),
];

/// The volume size of the sets, in bytes.
const VOLUME: &str = "-v50000b";

/// One test's directory with two copies of rarfast in it, named `unrar`
/// and `rar`: the name a copy is run under selects its dialect.
struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    rar: PathBuf,
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("rarfast-identity-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let unrar = exe_copy::tool_named(&dir, "unrar");
        let rar = exe_copy::tool_named(&dir, "rar");
        copy_executable(&rarfast(), &unrar);
        copy_executable(&rarfast(), &rar);
        Bench { dir, unrar, rar }
    }

    fn run(&self, exe: &Path, args: &[&str]) -> Output {
        output_of(
            Command::new(exe)
                .args(args)
                .current_dir(&self.dir)
                .stdin(Stdio::null()),
        )
        .expect("the command runs")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        // `RARFAST_KEEP_IDENTITY_INPUTS=1` keeps the inputs, to run a
        // reference tool over them by hand.
        if std::env::var_os("RARFAST_KEEP_IDENTITY_INPUTS").is_none() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// A member's bytes: the same on every run, different for every member,
/// and nothing a stored member could be taken for another's.
fn content(index: usize, len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64 ^ ((index as u64 + 1) << 32);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

/// Every member's name and bytes.
fn members() -> BTreeMap<String, Vec<u8>> {
    MEMBERS
        .iter()
        .enumerate()
        .map(|(index, (name, len))| ((*name).to_owned(), content(index, *len)))
        .collect()
}

/// Writes the members into the bench and archives them, stored, through
/// this tree's writer: one archive, or a set in volumes of [`VOLUME`].
/// Answers the archive files in order.
fn write_rar5(bench: &Bench, volumes: bool) -> Vec<PathBuf> {
    for (name, bytes) in members() {
        std::fs::write(bench.path(&name), bytes).unwrap();
    }
    // No quick-open record: unrar reads its headers from one where there
    // is one, and the shapes here are edits of the headers themselves.
    let mut args = vec!["a", "-ma5", "-m0", "-qo-", "-y", "-idq"];
    if volumes {
        args.push(VOLUME);
    }
    args.push("set.rar");
    args.extend(MEMBERS.iter().map(|(name, _)| *name));
    let made = bench.run(&bench.rar, &args);
    assert_eq!(made.status.code(), Some(0), "not written: {}", said(&made));
    for (name, _) in MEMBERS {
        std::fs::remove_file(bench.path(name)).unwrap();
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir(&bench.dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rar"))
        .collect();
    found.sort();
    assert_eq!(found.len() > 1, volumes, "{found:?}");
    found
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).replace('\x08', ""),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ---- RAR 5 blocks -------------------------------------------------------

const HF_SPLIT_BEFORE: u64 = 0x0008;
const HF_SPLIT_AFTER: u64 = 0x0010;
const FILE: u64 = 2;

/// A RAR 5 variable-length integer at `at`: its value and its length.
fn vint(bytes: &[u8], at: usize) -> (u64, usize) {
    let mut value = 0_u64;
    for (n, byte) in bytes[at..].iter().enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * n);
        if byte & 0x80 == 0 {
            return (value, n + 1);
        }
    }
    panic!("a vint runs off the end at {at}");
}

/// One RAR 5 block: where it starts, where its header's flags are, where
/// the header and its data end, and the name a file block carries.
#[derive(Clone, Debug)]
struct Block5 {
    start: usize,
    kind: u64,
    flags: u64,
    flags_at: usize,
    header_end: usize,
    end: usize,
    name: Option<(usize, usize)>,
}

impl Block5 {
    fn file(&self) -> bool {
        self.kind == FILE
    }
    fn split_before(&self) -> bool {
        self.flags & HF_SPLIT_BEFORE != 0
    }
    fn split_after(&self) -> bool {
        self.flags & HF_SPLIT_AFTER != 0
    }
}

/// The blocks of a RAR 5 archive, in order.
fn blocks5(bytes: &[u8]) -> Vec<Block5> {
    assert_eq!(&bytes[..8], b"Rar!\x1a\x07\x01\x00", "a RAR 5 signature");
    let mut at = 8;
    let mut found = Vec::new();
    while at + 7 <= bytes.len() {
        let (size, n) = vint(bytes, at + 4);
        let body = at + 4 + n;
        let header_end = body + usize::try_from(size).unwrap();
        let (kind, k) = vint(bytes, body);
        let flags_at = body + k;
        let (flags, f) = vint(bytes, flags_at);
        let mut p = flags_at + f;
        if flags & 0x0001 != 0 {
            p += vint(bytes, p).1;
        }
        let data = if flags & 0x0002 != 0 {
            let (data, d) = vint(bytes, p);
            p += d;
            usize::try_from(data).unwrap()
        } else {
            0
        };
        let name = (kind == FILE).then(|| {
            let (file_flags, n) = vint(bytes, p);
            p += n;
            p += vint(bytes, p).1; // unpacked size
            p += vint(bytes, p).1; // attributes
            if file_flags & 0x0002 != 0 {
                p += 4;
            }
            if file_flags & 0x0004 != 0 {
                p += 4;
            }
            p += vint(bytes, p).1; // compression information
            p += vint(bytes, p).1; // host
            let (len, n) = vint(bytes, p);
            p += n;
            (p, p + usize::try_from(len).unwrap())
        });
        found.push(Block5 {
            start: at,
            kind,
            flags,
            flags_at,
            header_end,
            end: header_end + data,
            name,
        });
        at = header_end + data;
    }
    found
}

/// CRC32 (the IEEE one), bit by bit: a header is a few dozen bytes.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// Sets a RAR 5 header's one-byte flags and its checksum to match.
fn reflag(bytes: &mut [u8], block: &Block5, flags: u64) {
    assert!(block.flags < 0x80 && flags < 0x80, "one-byte flags");
    bytes[block.flags_at] = u8::try_from(flags).unwrap();
    reseal(bytes, block);
}

fn reseal(bytes: &mut [u8], block: &Block5) {
    let crc = crc32(&bytes[block.start + 4..block.header_end]);
    bytes[block.start..block.start + 4].copy_from_slice(&crc.to_le_bytes());
}

fn name_of<'a>(bytes: &'a [u8], block: &Block5) -> &'a [u8] {
    let (start, end) = block.name.expect("a file block");
    &bytes[start..end]
}

/// `bytes` with the block written a second time, straight after itself.
fn doubled(bytes: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut out = bytes[..end].to_vec();
    out.extend_from_slice(&bytes[start..end]);
    out.extend_from_slice(&bytes[end..]);
    out
}

// ---- the older container's blocks ---------------------------------------

/// The first file block (type 0x74) of a RAR 1.5 to 4.x archive: where it
/// starts and where its data ends.
fn first_file_block4(bytes: &[u8]) -> (usize, usize) {
    assert_eq!(&bytes[..7], b"Rar!\x1a\x07\x00", "the older signature");
    let mut at = 7;
    loop {
        let kind = bytes[at + 2];
        let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
        let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
        let add = if kind == 0x74 || flags & 0x8000 != 0 {
            u32::from_le_bytes(bytes[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        if kind == 0x74 {
            return (at, at + size + add);
        }
        at += size + add;
    }
}

// ---- reading a run ------------------------------------------------------

/// The names a run's standard output closes with `OK`, each once, as the
/// archive spells them (the destination taken off).
fn ok_names(out: &Output, dest: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(&out.stdout).replace('\x08', "");
    let mut names = Vec::new();
    for line in text.lines() {
        let Some(line) = line.trim_end().strip_suffix("OK") else {
            continue;
        };
        let (Some(verb), Some(rest)) = (line.get(..12), line.get(12..)) else {
            continue;
        };
        // A member's line, or its line in a later volume; not `Creating`.
        if !matches!(verb.trim(), "Extracting" | "Testing" | "...") {
            continue;
        }
        let name = rest.split("  ").next().unwrap_or("").trim();
        let name = name.strip_prefix(dest).unwrap_or(name).replace('\\', "/");
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Every file under `root`, by its path with `/`, and its bytes.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, into);
            } else {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                into.insert(name, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, root, &mut found);
    found
}

/// What a shape is expected to deliver.
struct Expect<'a> {
    /// Every member's own bytes, by name.
    own: &'a BTreeMap<String, Vec<u8>>,
    /// The members the run does not deliver: neither written nor `OK`.
    not_delivered: &'a [&'a str],
    /// The exit code of `x` and of `t`.
    exit: i32,
}

/// `x` and `t` at every width, and what both must hold.
fn check(bench: &Bench, first: &str, expect: &Expect<'_>) {
    for width in WIDTHS {
        let out_dir = bench.path("out");
        let _ = std::fs::remove_dir_all(&out_dir);
        let ran = bench.run(&bench.unrar, &["x", "-y", "-p-", width, first, "out/"]);
        let written = tree(&out_dir);
        // The rule itself, first and whatever else is true of the run: a
        // file on disk holds the bytes of the member of its name.
        for (name, bytes) in &written {
            let own = expect.own.get(name).unwrap_or_else(|| {
                panic!("{width}: {name} is no member\n{}", said(&ran));
            });
            assert!(
                bytes == own,
                "{width}: {name} holds {} bytes that are not its own ({} expected)\n{}",
                bytes.len(),
                own.len(),
                said(&ran)
            );
        }
        // And a line that ends `OK` names a file that is there and right.
        let oks = ok_names(&ran, "out/");
        for name in &oks {
            assert!(
                written.contains_key(name),
                "{width}: {name} is called OK and is not on disk\n{}",
                said(&ran)
            );
        }
        let delivered: Vec<&String> = expect
            .own
            .keys()
            .filter(|name| !expect.not_delivered.contains(&name.as_str()))
            .collect();
        for name in &delivered {
            assert!(
                written.contains_key(*name) && oks.contains(name),
                "{width}: {name} is not delivered\n{}",
                said(&ran)
            );
        }
        for name in expect.not_delivered {
            assert!(
                !written.contains_key(*name) && !oks.iter().any(|ok| ok == name),
                "{width}: {name} is delivered\n{}",
                said(&ran)
            );
        }
        assert_eq!(
            ran.status.code(),
            Some(expect.exit),
            "{width}: {}",
            said(&ran)
        );

        let tested = bench.run(&bench.unrar, &["t", "-p-", width, first]);
        // Of the files, `t` calls OK the ones `x` delivers and no other (a
        // directory has a line of its own there).
        let oks = ok_names(&tested, "");
        for name in expect.own.keys() {
            assert_eq!(
                oks.contains(name),
                delivered.contains(&name),
                "{width}: `t` and {name}\n{}",
                said(&tested)
            );
        }
        assert_eq!(
            tested.status.code(),
            Some(expect.exit),
            "{width}: `t` {}",
            said(&tested)
        );
    }
}

/// One member asked for by name gets its own bytes and no other file is
/// written: the selection is by plan entry, so a plan out of step with the
/// engine wrote a neighbour under the name asked for.
fn check_selected(bench: &Bench, first: &str, name: &str, own: &BTreeMap<String, Vec<u8>>) {
    for width in WIDTHS {
        let out_dir = bench.path("one");
        let _ = std::fs::remove_dir_all(&out_dir);
        let ran = bench.run(
            &bench.unrar,
            &["x", "-y", "-p-", width, first, name, "one/"],
        );
        let written = tree(&out_dir);
        assert_eq!(
            written.keys().collect::<Vec<_>>(),
            vec![name],
            "{width}: {}",
            said(&ran)
        );
        assert!(
            written[name] == own[name],
            "{width}: {name}\n{}",
            said(&ran)
        );
        assert_eq!(ran.status.code(), Some(0), "{width}: {}", said(&ran));
    }
}

/// `p` writes every member's bytes, in archive order, and nothing else.
fn check_printed(bench: &Bench, first: &str, order: &[&str], own: &BTreeMap<String, Vec<u8>>) {
    for width in WIDTHS {
        let ran = bench.run(&bench.unrar, &["p", "-inul", "-p-", width, first]);
        let whole: Vec<u8> = order.iter().flat_map(|name| own[*name].clone()).collect();
        assert!(
            ran.stdout == whole,
            "{width}: `p` wrote {} bytes, {} expected",
            ran.stdout.len(),
            whole.len()
        );
        assert_eq!(ran.status.code(), Some(0), "{width}: `p`");
    }
}

fn all_names() -> Vec<&'static str> {
    MEMBERS.iter().map(|(name, _)| *name).collect()
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

// ---- the shapes ---------------------------------------------------------

/// Shape (c): a PLAIN RAR 5 archive, no volumes, with one extra file block
/// that carries "split before" and an earlier member's name (the third
/// member's block written twice, the second copy flagged). The engine
/// opens it as a member of its own and the plan had folded it into the
/// third member's entry: the fourth to seventh files held the member
/// before's bytes, each called `OK`.
#[test]
fn plain_rar5_with_a_stray_split_before_block() {
    let bench = Bench::new("plain");
    let own = members();
    let archive = write_rar5(&bench, false).remove(0);
    let bytes = std::fs::read(&archive).unwrap();
    let files: Vec<Block5> = blocks5(&bytes).into_iter().filter(Block5::file).collect();
    assert_eq!(files.len(), MEMBERS.len());
    let third = &files[2];
    assert_eq!(name_of(&bytes, third), b"f2_c.bin");
    let mut edited = doubled(&bytes, third.start, third.end);
    let copy = blocks5(&edited)
        .into_iter()
        .find(|block| block.start == third.end)
        .unwrap();
    reflag(&mut edited, &copy, copy.flags | HF_SPLIT_BEFORE);
    std::fs::write(&archive, edited).unwrap();

    let first = file_name(&archive);
    let expect = Expect {
        own: &own,
        not_delivered: &[],
        exit: 0,
    };
    check(&bench, &first, &expect);
    check_selected(&bench, &first, "f6_g.bin", &own);
    check_printed(&bench, &first, &all_names(), &own);
}

/// The volume of a set whose first file block ends a member begun in the
/// volume before: its index, bytes and that block.
fn closing_continuation(set: &[PathBuf]) -> (usize, Vec<u8>, Block5) {
    for (index, path) in set.iter().enumerate().skip(1) {
        let bytes = std::fs::read(path).unwrap();
        let first = blocks5(&bytes).into_iter().find(Block5::file).unwrap();
        if first.split_before() && !first.split_after() {
            return (index, bytes, first);
        }
    }
    panic!("no volume opens with the end of a member");
}

/// Shape (b): a RAR 5 volume set with a continuation block written twice.
/// The second copy is a file header flagged "split before" under the name
/// of a member the first copy completed.
#[test]
fn rar5_set_with_a_continuation_block_twice() {
    let bench = Bench::new("twice");
    let own = members();
    let set = write_rar5(&bench, true);
    let (index, bytes, block) = closing_continuation(&set);
    std::fs::write(&set[index], doubled(&bytes, block.start, block.end)).unwrap();

    let first = file_name(&set[0]);
    let expect = Expect {
        own: &own,
        not_delivered: &[],
        exit: 0,
    };
    check(&bench, &first, &expect);
    check_selected(&bench, &first, "f6_g.bin", &own);
    check_printed(&bench, &first, &all_names(), &own);
}

/// Shape (d), ONE FLAG BIT: "split after" cleared on the first fragment of
/// a member that continues. The engine ends the member there and opens
/// its continuation as a member of its own, where the plan had one entry.
/// That member is not delivered (its checksum fails: unrar 7.23 calls its
/// first fragment `OK`, which this tool does not); every other member is.
#[test]
fn rar5_set_with_split_after_cleared() {
    let bench = Bench::new("bit");
    let own = members();
    let set = write_rar5(&bench, true);
    // The second member that begins in one volume and runs into the next,
    // so members stand on both sides of the edit.
    let mut heads = Vec::new();
    for path in &set {
        let bytes = std::fs::read(path).unwrap();
        for block in blocks5(&bytes) {
            if block.file() && block.split_after() && !block.split_before() {
                heads.push((path.clone(), bytes.clone(), block));
            }
        }
    }
    let (path, mut bytes, block) = heads.swap_remove(1);
    let cut = String::from_utf8(name_of(&bytes, &block).to_vec()).unwrap();
    reflag(&mut bytes, &block, block.flags & !HF_SPLIT_AFTER);
    std::fs::write(&path, bytes).unwrap();

    let first = file_name(&set[0]);
    let expect = Expect {
        own: &own,
        not_delivered: &[cut.as_str()],
        exit: 3,
    };
    check(&bench, &first, &expect);
    check_selected(&bench, &first, "f6_g.bin", &own);
}

/// A "split after" block written twice: the engine joins the first copy
/// to the next volume and never reaches the second, which the plan had
/// counted as a member (one entry LONG, so members held the NEXT member's
/// bytes). unrar 7.23: every file right, `All OK`.
#[test]
fn rar5_set_with_a_split_after_block_twice() {
    let bench = Bench::new("after");
    let own = members();
    let set = write_rar5(&bench, true);
    let mut heads = Vec::new();
    for path in &set {
        let bytes = std::fs::read(path).unwrap();
        for block in blocks5(&bytes) {
            if block.file() && block.split_after() && !block.split_before() {
                heads.push((path.clone(), bytes.clone(), block));
            }
        }
    }
    let (path, bytes, block) = heads.swap_remove(1);
    std::fs::write(&path, doubled(&bytes, block.start, block.end)).unwrap();

    let first = file_name(&set[0]);
    let expect = Expect {
        own: &own,
        not_delivered: &[],
        exit: 0,
    };
    check(&bench, &first, &expect);
    check_selected(&bench, &first, "f6_g.bin", &own);
    check_printed(&bench, &first, &all_names(), &own);
}

/// A member's header given an earlier member's name and "split before":
/// unrar 7.23 passes it over without a word (that member is not
/// extracted) and delivers the rest, `All OK`.
#[test]
fn rar5_member_renamed_to_an_earlier_name_and_flagged() {
    let bench = Bench::new("renamed");
    let own = members();
    let archive = write_rar5(&bench, false).remove(0);
    let mut bytes = std::fs::read(&archive).unwrap();
    let files: Vec<Block5> = blocks5(&bytes).into_iter().filter(Block5::file).collect();
    let second = &files[1];
    let (start, end) = second.name.unwrap();
    assert_eq!(&bytes[start..end], b"f1_b.bin");
    bytes[start..end].copy_from_slice(b"f0_a.bin");
    reflag(&mut bytes, second, second.flags | HF_SPLIT_BEFORE);
    std::fs::write(&archive, bytes).unwrap();

    let first = file_name(&archive);
    let expect = Expect {
        own: &own,
        not_delivered: &["f1_b.bin"],
        exit: 0,
    };
    check(&bench, &first, &expect);
    check_selected(&bench, &first, "f6_g.bin", &own);
}

/// Shape (a), the older container: a committed volume set with the first
/// file block of one volume, a continuation, written twice. `volumes` are
/// the set's files in order and `doubled_at` the one edited. The members'
/// own bytes are what the set extracts to untouched.
fn old_set_with_a_continuation_twice(tag: &str, volumes: &[&str], doubled_at: usize) {
    let bench = Bench::new(tag);
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/archives");
    for name in volumes {
        std::fs::copy(source.join(name), bench.path(name)).unwrap();
    }
    let whole = bench.run(
        &bench.unrar,
        &["x", "-y", "-p-", "-mt1", volumes[0], "whole/"],
    );
    assert_eq!(whole.status.code(), Some(0), "untouched: {}", said(&whole));
    let own = tree(&bench.path("whole"));
    assert!(own.len() >= 6, "the set's files: {:?}", own.keys());

    let path = bench.path(volumes[doubled_at]);
    let bytes = std::fs::read(&path).unwrap();
    let (start, end) = first_file_block4(&bytes);
    assert_eq!(bytes[start + 3] & 0x01, 0x01, "a continuation block");
    std::fs::write(&path, doubled(&bytes, start, end)).unwrap();

    let expect = Expect {
        own: &own,
        not_delivered: &[],
        exit: 0,
    };
    check(&bench, volumes[0], &expect);
}

/// RAR 1.5 (DOS RAR 1.55): SWEEP2 item 51's own input, made here.
#[test]
fn rar15_set_with_a_continuation_block_twice() {
    old_set_with_a_continuation_twice(
        "d155",
        &[
            "d155_vol.rar",
            "d155_vol.r00",
            "d155_vol.r01",
            "d155_vol.r02",
        ],
        1,
    );
}

/// RAR 2.0 (DOS RAR 2.50).
#[test]
fn rar20_set_with_a_continuation_block_twice() {
    old_set_with_a_continuation_twice(
        "d250",
        &[
            "d250_vol.rar",
            "d250_vol.r00",
            "d250_vol.r01",
            "d250_vol.r02",
        ],
        1,
    );
}

/// RAR 2.9 (rar 4.20).
#[test]
fn rar29_set_with_a_continuation_block_twice() {
    old_set_with_a_continuation_twice(
        "r420",
        &[
            "r420_vol.part1.rar",
            "r420_vol.part2.rar",
            "r420_vol.part3.rar",
        ],
        1,
    );
}
