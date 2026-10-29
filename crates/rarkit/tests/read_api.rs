//! The read-API facts a technical listing needs, each compared against
//! reference `unrar` 7.23 on the same archive.
//!
//! Spec F parses all of them and the API did not carry them:
//! `MemberInfo::dictionary` (3.2.6, 3.3.6, 3.4.2), `MemberInfo::solid`
//! (3.6), `MemberInfo::algorithm_version` (3.2.6, 3.3.5),
//! `Archive::services` (3.2.9) and `ReadOptions::tolerant_tail` (3.5.5 and
//! 4.6, where the reference lists what arrived).
//!
//! Every expectation here is a CAPTURE: the test runs `unrar lt` or
//! `unrar lta` on the archive it is checking and reads the answer out of
//! the reference's own output. With no `unrar` on the box the test skips
//! BY NAME rather than asserting a remembered figure.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use rarkit::{Archive, Format, MemberInfo, Method, RangeSource, ReadOptions};

fn vectors() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/archives"
    ))
}

fn legacy() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives"
    ))
}

fn open(path: &PathBuf) -> Archive {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let src: Arc<dyn RangeSource> = Arc::new(bytes);
    Archive::open(src, &ReadOptions::default())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One entry of the reference's technical listing, as a map of its own
/// labels to their values.
type Entry = BTreeMap<String, String>;

/// Run `unrar <command>` on `path` and return one map per entry, in the
/// order the reference printed them. `None` when there is no `unrar`.
fn unrar_technical(command: &str, path: &PathBuf) -> Option<Vec<Entry>> {
    let out = Command::new("unrar").arg(command).arg(path).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut entries: Vec<Entry> = Vec::new();
    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.trim();
        let value = value.trim();
        // A member's block starts at its `Name` line, and every line under
        // it belongs to that member. Lines before the first one are the
        // banner and the archive's own.
        if label == "Name" {
            entries.push(Entry::new());
        }
        if let Some(entry) = entries.last_mut() {
            entry.insert(label.to_owned(), value.to_owned());
        }
    }
    Some(entries)
}

/// The reference's own spelling of a dictionary size: the largest unit that
/// divides it evenly.
fn dictionary_clause(bytes: u64) -> String {
    if bytes >= 1 << 30 && bytes.is_multiple_of(1 << 30) {
        format!("{}g", bytes >> 30)
    } else if bytes >= 1 << 20 && bytes.is_multiple_of(1 << 20) {
        format!("{}m", bytes >> 20)
    } else {
        format!("{}k", bytes >> 10)
    }
}

/// The `-m` and `-md=` half of the reference's compression clause, built
/// from what the API now reports.
fn our_clause(member: &MemberInfo<'_>) -> String {
    let level = match member.method {
        Method::Stored => 0,
        Method::Compressed { level, .. } => level,
    };
    match member.dictionary {
        Some(bytes) => format!("-m{level} -md={}", dictionary_clause(bytes)),
        None => format!("-m{level}"),
    }
}

/// The reference's compression clause without its family prefix.
fn reference_clause(entry: &Entry) -> String {
    let whole = entry.get("Compression").map(String::as_str).unwrap_or("");
    match whole.find(" -m") {
        Some(at) => whole[at + 1..].to_owned(),
        None => whole.to_owned(),
    }
}

/// The `(vNN)` the reference prints, which is the algorithm version for
/// every generation but RAR 1.3.
fn reference_version(entry: &Entry) -> Option<u32> {
    let whole = entry.get("Compression")?;
    let open = whole.find("(v")?;
    let close = whole[open..].find(')')? + open;
    whole[open + 2..close].parse().ok()
}

const ARCHIVES: &[&str] = &[
    "f01_stored.rar",
    "f02_dirs.rar",
    "f03_m3.rar",
    "f04_solid.rar",
    "f05_blake.rar",
    "f06_comment.rar",
    "f09_rr.rar",
    "f10_qo.rar",
    "r420_m5.rar",
    "D155_M5.RAR",
    "D250_M5.RAR",
    "D140_M5.RAR",
];

const LEGACY: &[&str] = &[
    "d140_m0.rar",
    "d155_m0.rar",
    "d250_m0.rar",
    "d250_m3.rar",
    "d250_sol.rar",
    "d155_sol.rar",
    "r420_solid.rar",
];

fn every_archive() -> Vec<PathBuf> {
    ARCHIVES
        .iter()
        .map(|name| vectors().join(name))
        .chain(LEGACY.iter().map(|name| legacy().join(name)))
        .collect()
}

/// Spec F 3.2.6, 3.3.6 and 3.4.2: the dictionary size a header declares,
/// whatever the method, and none at all for a directory.
///
/// A STORED member declares one, which is why the field is not
/// `Method::Compressed`'s alone: the reference prints `-m0 -md=128k` for a
/// stored RAR 5 member and `-m0 -md=64k` for a stored RAR 1.3, 1.5 or 2.0
/// one.
#[test]
fn the_dictionary_clause_matches_the_reference_on_every_member() {
    let mut checked = 0usize;
    let mut stored_with_dictionary = 0usize;
    for path in every_archive() {
        let Some(entries) = unrar_technical("lt", &path) else {
            eprintln!("SKIPPED the_dictionary_clause_matches_the_reference_on_every_member: no unrar on this box");
            return;
        };
        let archive = open(&path);
        let members: Vec<MemberInfo<'_>> = archive.members().collect();
        assert_eq!(
            members.len(),
            entries.len(),
            "{}: member count",
            path.display()
        );
        for (member, entry) in members.iter().zip(&entries) {
            assert_eq!(
                our_clause(member),
                reference_clause(entry),
                "{}: {}",
                path.display(),
                member.name_lossy()
            );
            if matches!(member.method, Method::Stored) && member.dictionary.is_some() {
                stored_with_dictionary += 1;
            }
            checked += 1;
        }
    }
    assert!(checked > 80, "only {checked} members checked");
    assert!(
        stored_with_dictionary > 20,
        "only {stored_with_dictionary} stored members carried a dictionary, so the \
         case the field exists for is not covered"
    );
}

/// Spec F 3.2.6 and 3.3.5: the algorithm version each family stores.
///
/// RAR 5 keeps a compression version of which 0 is the only accepted value
/// and the reference prints `(v50)` for it; the RAR 1.5 to 4.x family keeps
/// the unpack version and the reference prints it as it stands. The RAR 1.3
/// container declares 2 and the reference prints `(v13)`, which is the
/// reference labelling the CONTAINER and not the header's field: that one
/// is measured here rather than asserted as agreement.
#[test]
fn the_algorithm_version_is_what_each_family_stores() {
    for path in every_archive() {
        let Some(entries) = unrar_technical("lt", &path) else {
            eprintln!(
                "SKIPPED the_algorithm_version_is_what_each_family_stores: no unrar on this box"
            );
            return;
        };
        let archive = open(&path);
        let format = archive.format();
        for (member, entry) in archive.members().zip(&entries) {
            let printed = reference_version(entry).expect("the reference prints a version");
            match format {
                Format::Rar5 => {
                    assert_eq!(member.algorithm_version, 0, "{}", path.display());
                    assert_eq!(printed, 50, "{}", path.display());
                }
                Format::Rar13 => {
                    assert_eq!(member.algorithm_version, 2, "{}", path.display());
                    assert_eq!(
                        printed,
                        13,
                        "{}: the reference labels the container",
                        path.display()
                    );
                }
                _ => assert_eq!(
                    member.algorithm_version,
                    printed,
                    "{}: {}",
                    path.display(),
                    member.name_lossy()
                ),
            }
        }
    }
}

/// Spec F 3.6: the per-member solid bit as the header stores it.
///
/// The reference prints `Flags: solid` from the same bit, so the two agree
/// member for member - including on `d155_sol.rar`, a GENUINE solid DOS RAR
/// 1.55 archive whose writer never sets the bit, where neither prints it
/// although the archive's own solid flag is set. That is the erratum in
/// 3.6: the archive flag governs the CHAIN there, and this field is the
/// header's.
#[test]
fn the_solid_flag_matches_the_reference_member_for_member() {
    let mut with_bit = 0usize;
    let mut solid_archives = 0usize;
    for path in every_archive() {
        let Some(entries) = unrar_technical("lt", &path) else {
            eprintln!("SKIPPED the_solid_flag_matches_the_reference_member_for_member: no unrar on this box");
            return;
        };
        let archive = open(&path);
        if archive.is_solid() {
            solid_archives += 1;
        }
        for (member, entry) in archive.members().zip(&entries) {
            let printed = entry
                .get("Flags")
                .is_some_and(|flags| flags.split(',').any(|f| f.trim() == "solid"));
            assert_eq!(
                member.solid,
                printed,
                "{}: {}",
                path.display(),
                member.name_lossy()
            );
            if member.solid {
                with_bit += 1;
            }
        }
    }
    assert!(with_bit > 10, "only {with_bit} members carried the bit");
    assert!(solid_archives >= 3, "only {solid_archives} solid archives");
}

/// A genuine solid DOS RAR 1.55 archive sets the ARCHIVE flag and no member
/// bit at all, and a DOS RAR 2.50 one sets both (spec F 3.6's erratum). The
/// two are checked against each other so the field cannot quietly become
/// the effective chain rule.
#[test]
fn the_oldest_writer_sets_the_archive_flag_and_no_member_bit() {
    let d155 = open(&legacy().join("d155_sol.rar"));
    assert!(d155.is_solid(), "d155_sol.rar declares itself solid");
    assert_eq!(
        d155.members().filter(|m| m.solid).count(),
        0,
        "DOS RAR 1.55 never sets the per-member bit"
    );
    let d250 = open(&legacy().join("d250_sol.rar"));
    assert!(d250.is_solid());
    assert!(
        d250.members().filter(|m| m.solid).count() >= 8,
        "DOS RAR 2.50 sets it on every member after the first"
    );
}

/// Spec F 3.2.9: a service record is not a member, and a technical listing
/// names it. `unrar lta` prints one entry per service, in archive order
/// among the members, with sizes and a compression clause of its own, and
/// for the recovery record a percentage.
#[test]
fn the_service_records_match_the_reference_technical_listing() {
    for name in ["f06_comment.rar", "f09_rr.rar", "f10_qo.rar"] {
        let path = vectors().join(name);
        let Some(entries) = unrar_technical("lta", &path) else {
            eprintln!("SKIPPED the_service_records_match_the_reference_technical_listing: no unrar on this box");
            return;
        };
        let archive = open(&path);
        // The reference's own entries, in its order, tagged with whether it
        // called each one a service.
        let services: Vec<&Entry> = entries
            .iter()
            .filter(|e| e.get("Type").map(String::as_str) == Some("Service"))
            .collect();
        let ours: Vec<rarkit::ServiceInfo<'_>> = archive.services().collect();
        assert_eq!(
            ours.len(),
            services.len(),
            "{name}: service count, reference said {:?}",
            services
                .iter()
                .map(|e| e.get("Name").cloned().unwrap_or_default())
                .collect::<Vec<_>>()
        );
        for (svc, entry) in ours.iter().zip(&services) {
            assert_eq!(
                svc.header.name_lossy().as_ref(),
                entry.get("Name").unwrap(),
                "{name}: service name"
            );
            assert_eq!(
                svc.header.unpacked_size.unwrap_or(0).to_string(),
                *entry.get("Size").unwrap(),
                "{name}: {} size",
                svc.header.name_lossy()
            );
            assert_eq!(
                svc.header.packed_size.to_string(),
                *entry.get("Packed size").unwrap(),
                "{name}: {} packed size",
                svc.header.name_lossy()
            );
            assert_eq!(
                our_clause(&svc.header),
                reference_clause(entry),
                "{name}: {} compression",
                svc.header.name_lossy()
            );
            match entry.get("RR%") {
                Some(printed) => assert_eq!(
                    format!("{}%", svc.recovery_percent.expect("a percentage")),
                    *printed,
                    "{name}: the recovery percentage"
                ),
                None => assert!(
                    svc.recovery_percent.is_none(),
                    "{name}: {} carries a percentage the reference does not print",
                    svc.header.name_lossy()
                ),
            }
        }
        // A service is never a member, and `before_member` puts the two
        // back into the order the reference printed them.
        let members: Vec<String> = archive.members().map(|m| m.name_lossy().into()).collect();
        for svc in &ours {
            let name_text: String = svc.header.name_lossy().into();
            assert!(
                !members.contains(&name_text),
                "{name}: {name_text} is listed as a member"
            );
            assert!(svc.before_member as usize <= members.len());
        }
        let mut merged: Vec<String> = Vec::new();
        let mut at = 0usize;
        for svc in &ours {
            while at < svc.before_member as usize {
                merged.push(members[at].clone());
                at += 1;
            }
            merged.push(svc.header.name_lossy().into());
        }
        merged.extend_from_slice(&members[at..]);
        let printed: Vec<String> = entries
            .iter()
            .map(|e| e.get("Name").cloned().unwrap_or_default())
            .collect();
        assert_eq!(merged, printed, "{name}: archive order");
    }
}

/// Spec F 3.5.5 and 4.6: an archive whose last member runs past the end of
/// the file. Without `tolerant_tail` the open is `Truncated`, which is the
/// specification as written; with it the members parsed before the damage
/// are kept and the reason is reported through `Archive::tail`.
///
/// The reference lists the member, prints `Unexpected end of archive` and
/// exits 1, which is what the option is for.
#[test]
fn a_tolerant_tail_keeps_the_members_before_the_damage() {
    let path = vectors().join("f13_truncated.rar");
    let bytes = std::fs::read(&path).unwrap();
    let src: Arc<dyn RangeSource> = Arc::new(bytes.clone());
    let strict = Archive::open(src, &ReadOptions::default());
    assert!(
        matches!(
            strict.as_ref().err().map(rarkit::Error::kind),
            Some(rarkit::ErrorKind::Truncated)
        ),
        "without the option the open is Truncated, was {:?}",
        strict.as_ref().err()
    );

    let src: Arc<dyn RangeSource> = Arc::new(bytes);
    let archive = Archive::open(src, &ReadOptions::default().with_tolerant_tail(true))
        .expect("a tolerant tail opens it");
    let names: Vec<String> = archive.members().map(|m| m.name_lossy().into()).collect();
    assert!(
        archive.tail().is_some(),
        "the reason the walk stopped is reported"
    );

    let Some(out) = Command::new("unrar").arg("l").arg(&path).output().ok() else {
        eprintln!("SKIPPED the reference half of a_tolerant_tail_keeps_the_members_before_the_damage: no unrar on this box");
        return;
    };
    // The reference prints the listing on stdout and the complaint on
    // stderr, so both halves of its answer are needed here.
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(
        text.contains("Unexpected end of archive"),
        "the reference says the archive ends early: {text}"
    );
    for name in &names {
        assert!(
            text.contains(name.as_str()),
            "the reference lists {name} too: {text}"
        );
    }
    assert!(
        !names.is_empty(),
        "the members before the damage are the point of the option"
    );
}

/// An undamaged archive has no tail, with the option on or off, and the
/// option changes nothing else about what is parsed.
#[test]
fn a_sound_archive_has_no_tail() {
    for name in ARCHIVES {
        let path = vectors().join(name);
        let bytes = std::fs::read(&path).unwrap();
        let src: Arc<dyn RangeSource> = Arc::new(bytes.clone());
        let plain = Archive::open(src, &ReadOptions::default()).unwrap();
        let src: Arc<dyn RangeSource> = Arc::new(bytes);
        let tolerant =
            Archive::open(src, &ReadOptions::default().with_tolerant_tail(true)).unwrap();
        assert!(tolerant.tail().is_none(), "{name}");
        assert_eq!(
            plain.members().map(|m| m.name.to_vec()).collect::<Vec<_>>(),
            tolerant
                .members()
                .map(|m| m.name.to_vec())
                .collect::<Vec<_>>(),
            "{name}: the option changes nothing on a sound archive"
        );
    }
}
