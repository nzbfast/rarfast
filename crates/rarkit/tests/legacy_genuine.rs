//! The 81 genuine legacy archives of `fixtures/legacy/`, extracted through
//! the public `extract` and compared with REFERENCE `unrar` 7.23.
//!
//! These are RARLAB's own writers' output: RAR 1.40.2 beta, RAR 1.55,
//! RAR 2.50, RAR 3.93, RAR 4.20 and RAR 5.50 (`fixtures/legacy/README.md`). The reference is the right second arm for them, for two
//! reasons the manifest records itself: it is the format's own authority,
//! and on TWELVE of these fixtures - every legacy multi-volume set and
//! both `.rev` sets - the old engine fails where the reference succeeds
//! (`old_engine` column `rc=3 ... DIFFERS` against `unrar_7_23` `rc=0`).
//! A differential that used only the old engine would be blind to exactly
//! the archives this corpus was made for.
//!
//! The test skips itself, with a printed line, when `unrar` is not on
//! PATH or the corpus is not in the checkout.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, Password, RangeSource, ReadOptions, Sink,
};

fn corpus() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy"
    ))
}

/// One row of `MANIFEST.tsv`.
struct Fixture {
    id: String,
    format: String,
    volumes: Vec<String>,
    password: Option<String>,
    /// What the manifest records reference `unrar` 7.23 did.
    reference: String,
    /// What it records the old engine did.
    old_engine: String,
}

fn manifest() -> Vec<Fixture> {
    let Ok(text) = std::fs::read_to_string(corpus().join("MANIFEST.tsv")) else {
        return Vec::new();
    };
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let columns: Vec<&str> = header.split('\t').collect();
    let at = |name: &str| columns.iter().position(|c| *c == name);
    let (
        Some(id),
        Some(format),
        Some(archive),
        Some(volumes),
        Some(password),
        Some(reference),
        Some(old),
    ) = (
        at("id"),
        at("format"),
        at("archive"),
        at("volumes"),
        at("password"),
        at("unrar_7_23"),
        at("old_engine"),
    )
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        let Some(first) = fields.get(archive) else {
            continue;
        };
        // The first volume is the `archive` column; the rest of the set is
        // the `volumes` column minus that one and minus every `.rev`,
        // which is spec L's business and never an entry point.
        let mut rest: Vec<String> = fields
            .get(volumes)
            .map(|v| {
                v.split(';')
                    .filter(|n| !n.is_empty() && *n != *first && !n.ends_with(".rev"))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        rest.sort();
        let mut names = vec![(*first).to_string()];
        names.extend(rest);
        out.push(Fixture {
            id: fields.get(id).copied().unwrap_or("").to_string(),
            format: fields.get(format).copied().unwrap_or("").to_string(),
            volumes: names,
            password: fields
                .get(password)
                .filter(|p| !p.is_empty())
                .map(|p| (*p).to_string()),
            reference: fields.get(reference).copied().unwrap_or("").to_string(),
            old_engine: fields.get(old).copied().unwrap_or("").to_string(),
        });
    }
    out
}

/// What this crate's sink kept.
#[derive(Default)]
struct Collect {
    files: BTreeMap<String, Vec<u8>>,
    failures: Vec<String>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        let name = String::from_utf8_lossy(member.name).into_owned();
        if outcome.checksum_ok == Some(false) {
            self.failures.push(name.clone());
        }
        if let Some(bytes) = out {
            self.files.insert(name, bytes);
        }
        Ok(())
    }
}

/// Every regular file reference `unrar` wrote, by its path relative to the
/// destination, with backslashes converted the way this crate converts
/// them (spec F question 3).
fn walk(root: &Path, at: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(at) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, into);
        } else if let Ok(bytes) = std::fs::read(&path) {
            let name = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            into.insert(name, bytes);
        }
    }
}

/// Extract one set with reference `unrar`, or `None` when it refused.
fn reference_extract(fixture: &Fixture, dest: &Path) -> Option<BTreeMap<String, Vec<u8>>> {
    std::fs::create_dir_all(dest).ok()?;
    let archive = corpus().join("archives").join(&fixture.volumes[0]);
    let password = match &fixture.password {
        Some(password) => format!("-p{password}"),
        None => "-p-".to_string(),
    };
    let status = Command::new("unrar")
        .arg("x")
        .arg("-y")
        .arg("-idq")
        .arg(password)
        .arg(&archive)
        .arg(format!("{}/", dest.display()))
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let mut files = BTreeMap::new();
    walk(dest, dest, &mut files);
    Some(files)
}

fn ours(fixture: &Fixture) -> (rarkit::Result<rarkit::ExtractReport>, Collect) {
    let mut sources: Vec<Arc<dyn RangeSource>> = Vec::new();
    for name in &fixture.volumes {
        match std::fs::read(corpus().join("archives").join(name)) {
            Ok(bytes) => sources.push(Arc::new(bytes)),
            Err(_) => {
                return (
                    Err(rarkit::Error::new(rarkit::ErrorKind::NotAnArchive)),
                    Collect::default(),
                )
            }
        }
    }
    let mut options = ReadOptions::default();
    if let Some(password) = &fixture.password {
        options.password = Some(Password::from(password.as_str()));
    }
    let mut sink = Collect::default();
    let report = extract(sources, &options, &mut sink, &mut ());
    (report, sink)
}

#[test]
fn every_genuine_legacy_archive_agrees_with_reference_unrar() {
    let fixtures = manifest();
    if fixtures.is_empty() {
        eprintln!("fixtures/legacy is not in this checkout: skipped");
        return;
    }
    if Command::new("unrar").arg("-iver").status().is_err() {
        eprintln!("reference `unrar` is not on PATH: skipped");
        return;
    }
    let root = std::env::temp_dir().join(format!("rarkit-legacy-{}", std::process::id()));
    let mut compared = 0usize;
    let mut members = 0usize;
    let mut differences: Vec<String> = Vec::new();
    let mut pinned: Vec<String> = Vec::new();
    let mut renamed: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let dest = root.join(&fixture.id);
        let _ = std::fs::remove_dir_all(&dest);
        let Some(theirs) = reference_extract(fixture, &dest) else {
            differences.push(format!(
                "{}: reference `unrar` refused it, though the manifest says {}",
                fixture.id, fixture.reference
            ));
            continue;
        };
        if std::env::var_os("RARKIT_TRACE").is_some() {
            eprintln!(
                "-- {} ({}) {:?}",
                fixture.id, fixture.format, fixture.volumes
            );
        }
        let (report, mine) = ours(fixture);
        compared += 1;
        match report {
            Ok(_) => {}
            Err(error) => {
                differences.push(format!("{} ({}): {error}", fixture.id, fixture.format));
                continue;
            }
        }
        if !mine.failures.is_empty() {
            differences.push(format!(
                "{} ({}): members failed their own checksum: {:?}",
                fixture.id, fixture.format, mine.failures
            ));
            continue;
        }
        let mut unmatched: Vec<(&String, &Vec<u8>)> = Vec::new();
        for (name, bytes) in &theirs {
            members += 1;
            match mine.files.get(name) {
                Some(got) if got == bytes => {}
                Some(got) => differences.push(format!(
                    "{}: {name}: {} bytes here, {} from the reference",
                    fixture.id,
                    got.len(),
                    bytes.len()
                )),
                // Held back rather than reported: on a box whose 8-bit
                // charset cannot spell the name, the reference's spelling
                // of a member is not the same string as ours and a
                // name-keyed lookup cannot find it. `spelt_differently`
                // decides whether that is what happened.
                None => unmatched.push((name, bytes)),
            }
        }
        for (name, bytes) in unmatched {
            match spelt_differently(name, bytes, &mine.files, &theirs) {
                Some(ours) => renamed.push(format!(
                    "{} ({}): the reference wrote {name:?} where this package gives {ours:?}; \
                     the two are byte for byte the same {} bytes",
                    fixture.id,
                    fixture.format,
                    bytes.len()
                )),
                None => differences.push(format!(
                    "{}: {name} is not in this package's output: {:?}",
                    fixture.id,
                    mine.files.keys().collect::<Vec<_>>()
                )),
            }
        }
        // Where the OLD ENGINE cannot read what the reference can, this
        // package siding with the reference is the finding, not a bug.
        if fixture.old_engine.contains("DIFFERS") {
            pinned.push(format!(
                "{} ({}): this package agrees with the reference; the old engine gives `{}`",
                fixture.id, fixture.format, fixture.old_engine
            ));
        }
        let _ = std::fs::remove_dir_all(&dest);
    }
    let _ = std::fs::remove_dir_all(&root);

    println!("== genuine legacy corpus ==");
    println!("archives compared: {compared} of {}", fixtures.len());
    println!("members agreeing with reference unrar 7.23: {members}");
    println!(
        "archives the old engine cannot read and this package can: {}",
        pinned.len()
    );
    for line in &pinned {
        println!("  {line}");
    }
    println!(
        "members the reference could not spell on this platform: {}",
        renamed.len()
    );
    for line in &renamed {
        println!("  SPELT DIFFERENTLY: {line}");
    }
    for line in &differences {
        println!("  DIFFERS: {line}");
    }
    assert!(
        differences.is_empty(),
        "{} archives differ from reference unrar",
        differences.len()
    );
}

/// Every archive comment in the corpus, against what reference `unrar l`
/// prints.
///
/// **The defect this pins.** `read/archive.rs::read_comment` tested a RAR
/// 1.5 to 4.x comment's method byte against 0, and that family spells
/// STORED 0x30, so every RAR 4 archive with a comment reported none. Two
/// things came out of measuring it rather than assuming it:
///
/// 1. the raw byte is the wrong thing to test at all, because the
///    containers spell it differently - the flag is normalised by the
///    parser that read the block now (`CommentSpan::codec`);
/// 2. **not one comment in this corpus is stored.** `rar -z` COMPRESSES
///    the comment: `d155_cmt` carries method 0x34 at unpack version 15,
///    `d250_cmt` 0x34 at version 20, `r550_cmt` 0x33 at version 29. So
///    fixing the byte alone would still have reported no comment on all
///    three, and what reaches the reference's answer is decoding them,
///    which this crate's own decoders now do.
#[test]
fn every_archive_comment_matches_reference_unrar() {
    let fixtures = manifest();
    if fixtures.is_empty() {
        eprintln!("fixtures/legacy is not in this checkout: skipped");
        return;
    }
    if Command::new("unrar").arg("-iver").status().is_err() {
        eprintln!("reference `unrar` is not on PATH: skipped");
        return;
    }

    let mut differences: Vec<String> = Vec::new();
    let mut with_comment = 0usize;
    let mut compared = 0usize;
    for fixture in &fixtures {
        // A header-encrypted archive makes `unrar l` ask for a password
        // on the terminal rather than answer, so the password ones are
        // not this test's; `crypto.rs` owns them.
        if fixture.password.is_some() {
            continue;
        }
        let path = corpus().join("archives").join(&fixture.volumes[0]);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(listed) = Command::new("unrar").arg("l").arg(&path).output() else {
            continue;
        };
        if !listed.status.success() {
            continue;
        }
        compared += 1;
        let theirs = comment_in(&String::from_utf8_lossy(&listed.stdout));

        let source: Arc<dyn RangeSource> = Arc::new(bytes);
        let archive = match rarkit::Archive::open(source, &ReadOptions::default()) {
            Ok(archive) => archive,
            Err(error) => {
                differences.push(format!("{}: open: {error}", fixture.id));
                continue;
            }
        };
        let ours = archive.comment().map(normalise);

        match (&theirs, &ours) {
            (None, None) => {}
            (Some(_), Some(_)) => with_comment += 1,
            _ => {}
        }
        if theirs != ours {
            differences.push(format!(
                "{} ({}): the reference prints {theirs:?} and this crate answers {ours:?}",
                fixture.id, fixture.format
            ));
        }
    }

    assert!(
        differences.is_empty(),
        "{} of {compared} archives disagree with reference `unrar l`:\n{}",
        differences.len(),
        differences.join("\n")
    );
    assert!(
        with_comment >= 3,
        "only {with_comment} archives were found to have a comment at all, \
         so this test proved nothing"
    );
    eprintln!("{compared} archives compared, {with_comment} of them with a comment");
}

/// The name THIS package gives a member the reference wrote under a
/// different spelling, or `None` when the member is genuinely missing.
///
/// **What this is for, measured on a Windows desktop on 22 Sep 2026 rather than
/// assumed.** `r393_x` and `r420_x` each hold one member whose name is
/// stored as 8-bit bytes with no Unicode name beside them, and those
/// bytes are UTF-8: this package hands them back as stored and spells
/// the member `naam-met-accenten-éèü-ñ.txt` with its four accents. The
/// reference cannot. On a box whose OEM code page is IBM437 it resolves
/// the same stored bytes through that page, best-fits the result into
/// the ANSI page, and arrives at nine characters beginning `+` where it
/// should have four accented ones. It then uses that spelling
/// EVERYWHERE, in the name it writes to disk and in its own `lb`
/// listing alike, so there is no output of the reference's that carries
/// the name it meant and nothing here can recover one:
/// `-scf`, `-sca`, `-sco` and `chcp 65001` were each measured and each
/// changes only the encoding the same mangled characters are printed
/// in. On a Mac, whose charset is UTF-8, the reference spells it
/// correctly and no member reaches this function at all.
///
/// So the member is matched by its CONTENT instead, under three
/// conditions that keep the test's teeth:
///
/// 1. exactly ONE of our unmatched members has those bytes, so no
///    ambiguity is resolved by guessing;
/// 2. BOTH spellings are non-ASCII, because an ASCII name is one every
///    platform can spell and a difference in one is a real difference;
/// 3. the bytes are equal, not merely the same length.
///
/// A member that fails any of the three is reported as missing, which
/// is what it was before this function existed.
fn spelt_differently<'a>(
    their_name: &str,
    their_bytes: &[u8],
    ours: &'a BTreeMap<String, Vec<u8>>,
    theirs: &BTreeMap<String, Vec<u8>>,
) -> Option<&'a String> {
    if their_name.is_ascii() {
        return None;
    }
    let mut found: Option<&String> = None;
    for (name, bytes) in ours {
        if theirs.contains_key(name) || name.is_ascii() || bytes != their_bytes {
            continue;
        }
        if found.is_some() {
            // Two of ours carry these bytes: which one the reference
            // meant is a guess, and this function does not guess.
            return None;
        }
        found = Some(name);
    }
    found
}

/// The comment reference `unrar l` printed, or `None` when it printed
/// none. It sits between an `Archive comment:` line and the `Archive:`
/// line that begins the listing proper.
///
/// **The listing's LINE ENDINGS are the platform's, and the markers this
/// searches for are lines.** The reference's C runtime writes `\r\n` on
/// Windows, so the box prints `Archive comment:\r\n` where a Mac
/// prints `Archive comment:\n`; a search for the bare `\n` form then
/// finds nothing and this function answered `None` for every archive
/// that has a comment at all. That is what failed `d155_cmt`, `d250_cmt`
/// and `r550_cmt` on a Windows desktop on 22 Sep 2026, three of 72, with the
/// reference reported as printing no comment. Fold the endings BEFORE
/// looking for either marker. The comment's own text is folded again by
/// `normalise`, which is where the archive's stored `\r\n` is handled;
/// this fold is about finding the markers.
fn comment_in(listing: &str) -> Option<String> {
    let listing = listing.replace("\r\n", "\n");
    let after = listing.split_once("Archive comment:\n")?.1;
    let text = after.split_once("\nArchive: ")?.0;
    Some(normalise(text.trim_end_matches('\n').as_bytes()))
}

/// Line endings folded and trailing blank lines dropped, because the
/// reference prints a comment through a terminal and this crate hands
/// back the archive's own bytes. The corpus's comments end `\r\n`, and
/// the reference's own printing leaves a bare `\r` on the last line.
fn normalise(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .trim_end_matches(['\n', '\r'])
        .to_string()
}
