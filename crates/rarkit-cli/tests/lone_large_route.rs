//! ONE LARGE STORED MEMBER BESIDE SMALL ONES takes the walk
//! (`dialect::unrar::extract::lone_large_stored`), through the whole
//! command, in a build that reads the knobs.
//!
//! The rule is a route and nothing else: which of the engine's two drivers
//! extracts the set. What must hold is that the route is the one the rule
//! names for each shape, and that NO BYTE AND NO VERDICT moves with it. The
//! shipped floor is a gibibyte, so the floor is stated small here
//! (`RARFAST_LONE_LARGE_KIB`) and the route read from the line
//! `RARFAST_ROUTE_SAY=1` prints; every case also runs with the floor as
//! shipped, where a set this small keeps the pool, and its outputs are the
//! same bytes.
//!
//! Those knobs exist only under the feature `read-depth-knob`;
//! The knob test runner (`make test-knob-spawn`) builds it and runs this:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test lone_large_route
//! ```
//!
//! It runs on every system: a set in SMALL VOLUMES (none over the wide
//! read's floor) walks on all of them, and one archive on none.
#![cfg(feature = "read-depth-knob")]

use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// The floor the cases state: 1 MiB.
const FLOOR_KIB: &str = "1024";
const MIB: usize = 1 << 20;

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
}

/// Noise a stored member is made of (a linear congruential stream).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("rarfast-lone-large-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // A copy named `unrar` is how the binary picks that dialect.
        let unrar = dir.join("unrar");
        copy_executable(&rarfast(), &unrar);
        Self { dir, unrar }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join("src").join(name), bytes).unwrap();
    }

    /// `rarfast a <switches> <archive> <files>` in the source directory.
    fn create(&self, switches: &[&str], archive: &str, files: &[&str]) {
        let out = output_of(
            Command::new(rarfast())
                .arg("a")
                .args(switches)
                .args(["-idq", &format!("../{archive}")])
                .args(files)
                .current_dir(self.dir.join("src")),
        )
        .expect("rarfast a runs");
        assert!(
            out.status.success(),
            "rarfast a {switches:?} {archive}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `unrar <args>` with the route said, the floor stated (`None`: as
    /// shipped) and `RARFAST_POOL` as given.
    fn unrar(&self, args: &[&str], floor: Option<&str>, pool: Option<&str>) -> Output {
        let mut command = Command::new(&self.unrar);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("RARFAST_ROUTE_SAY", "1")
            .env_remove("RARFAST_LONE_LARGE_KIB")
            .env_remove("RARFAST_POOL");
        if let Some(floor) = floor {
            command.env("RARFAST_LONE_LARGE_KIB", floor);
        }
        if let Some(pool) = pool {
            command.env("RARFAST_POOL", pool);
        }
        output_of(&mut command).expect("unrar runs")
    }

    /// `x` of `archive` into a fresh directory `into`.
    fn extract(
        &self,
        archive: &str,
        into: &str,
        extra: &[&str],
        floor: Option<&str>,
        pool: Option<&str>,
    ) -> Output {
        let dest = self.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let mut args = vec!["x", "-idq", "-y"];
        args.extend_from_slice(extra);
        let target = format!("{into}/");
        args.push(archive);
        args.push(&target);
        self.unrar(&args, floor, pool)
    }

    fn same(&self, into: &str, names: &[&str]) {
        for name in names {
            let want = std::fs::read(self.dir.join("src").join(name)).unwrap();
            let got = std::fs::read(self.dir.join(into).join(name))
                .unwrap_or_else(|e| panic!("{into}/{name}: {e}"));
            assert!(want == got, "{into}/{name} differs from its source");
        }
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the run said of its route: `(route, lone large)`. The line may
/// follow a complaint that ended without a newline.
fn route(out: &Output) -> (String, bool) {
    let text = String::from_utf8_lossy(&out.stderr);
    let line = text
        .lines()
        .filter_map(|line| line.split_once("rarfast route: ").map(|(_, rest)| rest))
        .next_back()
        .unwrap_or_else(|| panic!("no route line in {text:?}"));
    let (route, lone) = line
        .split_once("; lone large ")
        .expect("the line's two halves");
    let (lone, _packed) = lone
        .split_once("; lone packed ")
        .expect("the line's third part");
    (route.to_string(), lone.trim() == "true")
}

/// Whether the run said its set is one large COMPRESSED member beside
/// small ones (`dialect::unrar::extract::lone_large_packed`).
fn packed(out: &Output) -> bool {
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .filter_map(|line| line.split_once("; lone packed ").map(|(_, rest)| rest))
        .next_back()
        .unwrap_or_else(|| panic!("no route line in {text:?}"))
        .trim()
        == "true"
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what}: {:?} {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The `<stem>.part*.rar` name in the bench that sorts lowest: the
/// volume a read of the set is started from.
fn lowest_volume(bench: &Bench, stem: &str) -> String {
    let mut firsts: Vec<String> = std::fs::read_dir(&bench.dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!("{stem}.part")) && n.ends_with(".rar"))
        .collect();
    firsts.sort();
    firsts.first().expect("a first volume").clone()
}

/// The big member beside small files: 3 MiB of noise, a sample of 32 KiB,
/// an .nfo and an .srt.
fn big(bench: &Bench) -> [&'static str; 4] {
    bench.write("full.mkv", &noise(3 * MIB + 4321, 11));
    bench.write("sample.mkv", &noise(32 << 10, 12));
    bench.write("full.nfo", b"release notes\n");
    bench.write(
        "full.srt",
        &b"1\n00:00:01,000 --> 00:00:02,000\nline\n\n".repeat(40),
    );
    ["full.mkv", "sample.mkv", "full.nfo", "full.srt"]
}

#[test]
fn a_big_member_beside_small_files_walks_and_writes_the_same_bytes() {
    let bench = Bench::new("full");
    let names = big(&bench);
    bench.create(&["-m0"], "one.rar", &names);
    bench.create(&["-m0", "-v500k"], "vols.rar", &names);
    for (archive, tag) in [("one.rar", "one"), ("vols.part01.rar", "vols")] {
        let archive = if tag == "vols" {
            lowest_volume(&bench, "vols")
        } else {
            archive.to_string()
        };
        // The rule: the walk for small volumes, and one archive is not the
        // rule's.
        let by_rule = bench.extract(&archive, &format!("{tag}-rule"), &[], Some(FLOOR_KIB), None);
        ok(&by_rule, "the rule");
        let taken = tag == "vols";
        let walks = if taken { "walk" } else { "pool" };
        assert_eq!(route(&by_rule), (walks.to_string(), taken), "{archive}");
        bench.same(&format!("{tag}-rule"), &names);
        // The floor as shipped (a gibibyte): this small set keeps the pool.
        let shipped = bench.extract(&archive, &format!("{tag}-shipped"), &[], None, None);
        ok(&shipped, "the floor as shipped");
        assert_eq!(route(&shipped), ("pool".to_string(), false), "{archive}");
        bench.same(&format!("{tag}-shipped"), &names);
        // RARFAST_POOL wins over the rule, either way.
        let forced = bench.extract(
            &archive,
            &format!("{tag}-pool"),
            &[],
            Some(FLOOR_KIB),
            Some("1"),
        );
        ok(&forced, "the pool forced");
        assert_eq!(route(&forced), ("pool".to_string(), taken), "{archive}");
        bench.same(&format!("{tag}-pool"), &names);
        // The three runs said the same on stdout.
        assert_eq!(by_rule.stdout, shipped.stdout, "{archive}");
        assert_eq!(by_rule.stdout, forced.stdout, "{archive}");
        // `t` writes no file and is not asked.
        let tested = bench.unrar(&["t", "-idq", &archive], Some(FLOOR_KIB), None);
        ok(&tested, "t");
        assert!(!route(&tested).1, "t is not the rule's: {archive}");
    }
}

#[test]
fn the_rule_stops_at_a_second_large_member_and_at_one_it_cannot_take() {
    let bench = Bench::new("edges");
    bench.write("a.mkv", &noise(3 * MIB, 21));
    bench.write("b.mkv", &noise(2 * MIB, 22));
    bench.write("c.mkv", &noise(MIB, 23));
    bench.write(
        "text.txt",
        &b"the same line of text again and again\n".repeat(120_000),
    );
    bench.write("note.nfo", b"notes\n");
    // Every set in small volumes, where the rule lives.
    let set = |switches: &[&str], stem: &str, files: &[&str]| {
        let mut all = vec!["-v500k"];
        all.extend_from_slice(switches);
        bench.create(&all, &format!("{stem}.rar"), files);
        lowest_volume(&bench, stem)
    };
    // Two large members beside a small one: the pool, which runs them abreast.
    let two = set(&["-m0"], "two", &["a.mkv", "b.mkv", "note.nfo"]);
    let out = bench.extract(&two, "two", &[], Some(FLOOR_KIB), None);
    ok(&out, "two large members");
    assert_eq!(route(&out), ("pool".to_string(), false));
    bench.same("two", &["a.mkv", "b.mkv", "note.nfo"]);
    // Only one of them selected: the rule reads what the command extracts.
    let out = bench.extract(&two, "picked", &["-xb.mkv"], Some(FLOOR_KIB), None);
    ok(&out, "one large member selected");
    assert_eq!(route(&out), ("walk".to_string(), true));
    bench.same("picked", &["a.mkv", "note.nfo"]);
    // The same member under the floor.
    let out = bench.extract(&two, "under", &["-xb.mkv"], Some("4096"), None);
    ok(&out, "under the floor");
    assert!(!route(&out).1);
    bench.same("under", &["a.mkv", "note.nfo"]);
    // The rest over a quarter of the large member (1 MiB beside 3 MiB).
    let third = set(&["-m0"], "third", &["a.mkv", "c.mkv"]);
    let out = bench.extract(&third, "third", &[], Some(FLOOR_KIB), None);
    ok(&out, "the rest over a quarter");
    assert!(!route(&out).1);
    bench.same("third", &["a.mkv", "c.mkv"]);
    // The large member COMPRESSED: its decode is the pool's.
    let packed = set(&["-m3"], "packed", &["text.txt", "note.nfo"]);
    let out = bench.extract(&packed, "packed", &[], Some(FLOOR_KIB), None);
    ok(&out, "a compressed large member");
    assert!(!route(&out).1);
    bench.same("packed", &["text.txt", "note.nfo"]);
    // The large member ENCRYPTED: its cipher is the pool's.
    let locked = set(&["-m0", "-psecret"], "locked", &["a.mkv", "note.nfo"]);
    let out = bench.extract(&locked, "locked", &["-psecret"], Some(FLOOR_KIB), None);
    ok(&out, "an encrypted large member");
    assert!(!route(&out).1);
    bench.same("locked", &["a.mkv", "note.nfo"]);
    // The large member under BLAKE2sp: taken on Linux alone
    // (`extract::LONE_LARGE_BLAKE2SP`), each system on its own rows.
    let hashed = set(&["-m0", "-htb"], "hashed", &["a.mkv", "note.nfo"]);
    let out = bench.extract(&hashed, "hashed", &[], Some(FLOOR_KIB), None);
    ok(&out, "a BLAKE2sp large member");
    assert_eq!(route(&out).1, cfg!(target_os = "linux"));
    bench.same("hashed", &["a.mkv", "note.nfo"]);
}

/// Text that compresses: lines that differ, `len` bytes of them.
fn lines(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut n = seed;
    while out.len() < len {
        out.extend_from_slice(format!("line {n} of the notes, said once more\n").as_bytes());
        n = n.wrapping_mul(31).wrapping_add(7);
    }
    out.truncate(len);
    out
}

#[test]
fn a_compressed_big_member_beside_small_files_walks_as_one_archive() {
    let bench = Bench::new("packed");
    bench.write("full.mkv", &lines(3 * MIB + 4321, 31));
    bench.write("sample.mkv", &lines(32 << 10, 32));
    bench.write("full.nfo", b"release notes\n");
    bench.write("second.mkv", &lines(3 * MIB, 33));
    let names = ["full.mkv", "sample.mkv", "full.nfo"];
    bench.create(&["-m3"], "one.rar", &names);
    // The rule: one large compressed member beside small ones walks, with
    // no floor stated; it is not the stored rule's.
    let by_rule = bench.extract("one.rar", "rule", &[], None, None);
    ok(&by_rule, "the rule");
    assert_eq!(route(&by_rule), ("walk".to_string(), false));
    assert!(packed(&by_rule));
    bench.same("rule", &names);
    // RARFAST_POOL wins over the rule, and the bytes and the text are the
    // same by both routes.
    let forced = bench.extract("one.rar", "pool", &[], None, Some("1"));
    ok(&forced, "the pool forced");
    assert_eq!(route(&forced), ("pool".to_string(), false));
    bench.same("pool", &names);
    assert_eq!(by_rule.stdout, forced.stdout);
    // `t` writes no file and is not asked.
    let tested = bench.unrar(&["t", "-idq", "one.rar"], None, None);
    ok(&tested, "t");
    assert!(!packed(&tested));
    assert_eq!(route(&tested).0, "pool");
    // Two large members: the pool, which runs them abreast; one of them
    // picked out with the small files walks again.
    let all = ["full.mkv", "second.mkv", "sample.mkv", "full.nfo"];
    bench.create(&["-m3"], "two.rar", &all);
    let out = bench.extract("two.rar", "two", &[], None, None);
    ok(&out, "two large members");
    assert_eq!(route(&out), ("pool".to_string(), false));
    assert!(!packed(&out));
    bench.same("two", &all);
    let out = bench.extract("two.rar", "picked", &["-xsecond.mkv"], None, None);
    ok(&out, "one large member selected");
    assert_eq!(route(&out).0, "walk");
    assert!(packed(&out));
    bench.same("picked", &names);
    // The same big member STORED as one archive is neither rule's.
    bench.create(&["-m0"], "stored.rar", &names);
    let out = bench.extract("stored.rar", "stored", &[], None, None);
    ok(&out, "a stored big member");
    assert!(!packed(&out));
    assert!(!route(&out).1);
    bench.same("stored", &names);
}
