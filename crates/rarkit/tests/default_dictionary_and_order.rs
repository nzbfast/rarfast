//! The default dictionary (spec G 3.8.1) and the order a solid archive's
//! members are written in.
//!
//! The order lists below are reference `rar` 7.23's own, from `rar a -s
//! -m3` then `rar lb` over trees of these names (probes of the
//! default dictionary and the solid order);
//! a member's size breaks a tie of names, so sizes here are chosen to
//! reproduce the probe.

use std::sync::Arc;

use rarkit::{
    Archive, MemberOrder, MemberSortKey, MemberSpec, MemoryPolicy, Payload, RangeSource,
    ReadOptions, WriteMethod, WriteOptions, Writer,
};

const MIB: u64 = 1 << 20;

/// A member to write: its name, its bytes, and whether it is a directory.
type Member = (String, Vec<u8>, bool);

fn names_of(archive: &[u8]) -> Vec<String> {
    let opened = Archive::open(
        Arc::new(archive.to_vec()) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .unwrap();
    opened
        .members()
        .map(|m| String::from_utf8(m.name.to_vec()).unwrap())
        .collect()
}

fn dictionary_of(archive: &[u8]) -> Option<u64> {
    let opened = Archive::open(
        Arc::new(archive.to_vec()) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .unwrap();
    let found = opened.members().find(|m| !m.is_directory)?.dictionary;
    found
}

/// Writes `members` (name, bytes, directory) and hands back the archive.
fn write(options: WriteOptions, members: &[Member]) -> Vec<u8> {
    let mut writer = Writer::new(options).unwrap();
    for (name, data, dir) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(if *dir { &[] } else { data }),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: *dir,
            })
            .unwrap();
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).unwrap();
    out
}

fn compressed(level: u8, solid: bool) -> WriteOptions {
    WriteOptions {
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid,
        ..WriteOptions::default()
    }
}

/// Files of `len` bytes, text enough to compress, each distinct.
fn file(name: &str, len: usize) -> Member {
    let data: Vec<u8> = format!("{name} ").bytes().cycle().take(len).collect();
    (name.to_owned(), data, false)
}

fn dir(name: &str) -> Member {
    (name.to_owned(), Vec::new(), true)
}

/// rar 7.23's first probe tree, added in a scrambled order, comes out in
/// the order `rar lb` listed it.
fn probe_tree() -> (Vec<Member>, Vec<&'static str>) {
    let members = vec![
        dir("t"),
        file("t/z.txt", 30),
        dir("t/a"),
        file("t/a/q.txt", 22),
        file("t/.hidden", 20),
        file("t/b.c", 16),
        file("t/a/b.c", 25),
        file("t/Makefile", 20),
        dir("t/a/sub"),
        file("t/a/sub/k.txt", 22),
        file("t/a/sub/aa.c", 24),
        file("t/x.tar.gz", 21),
        file("t/y.gz", 18),
        file("t/a.txt", 18),
        file("t/b/a.txt", 21),
        dir("t/b"),
        file("t/b/zz", 17),
        file("t/noext", 18),
        file("t/a/noext2", 21),
        file("t/M.TXT", 19),
        dir("t/C"),
        file("t/C/a.TXT", 21),
        file("t/C/b.h", 19),
        file("t/a/x y.Txt", 23),
        file("t/b.txt.bak", 22),
        file("t/a/Zed.c", 21),
        file("t/a.c", 17),
    ];
    let order = vec![
        "t/Makefile",
        "t/noext",
        "t/a/noext2",
        "t/b/zz",
        "t/M.TXT",
        "t/C/a.TXT",
        "t/a/x y.Txt",
        "t/b.txt.bak",
        "t/a/Zed.c",
        "t/a.c",
        "t/a/sub/aa.c",
        "t/b.c",
        "t/a/b.c",
        "t/x.tar.gz",
        "t/y.gz",
        "t/C/b.h",
        "t/.hidden",
        "t/a.txt",
        "t/b/a.txt",
        "t/a/sub/k.txt",
        "t/a/q.txt",
        "t/z.txt",
        "t/a/sub",
        "t/C",
        "t/a",
        "t/b",
        "t",
    ];
    (members, order)
}

#[test]
fn a_solid_compressed_archive_is_ordered_as_rar_orders_it() {
    let (members, order) = probe_tree();
    let archive = write(compressed(3, true), &members);
    assert_eq!(names_of(&archive), order);
}

#[test]
fn as_added_keeps_the_order_of_the_add_calls() {
    let (members, _) = probe_tree();
    let mut options = compressed(3, true);
    options.order = MemberOrder::AsAdded;
    let archive = write(options, &members);
    let added: Vec<&str> = members.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(names_of(&archive), added);
}

/// Only a solid COMPRESSED archive is reordered: rar 7.23 keeps the scan
/// order for a non-solid archive and for `-s -m0`.
#[test]
fn non_solid_and_stored_archives_keep_the_order_given() {
    let (members, _) = probe_tree();
    let added: Vec<&str> = members.iter().map(|m| m.0.as_str()).collect();
    let stored_solid = WriteOptions {
        solid: true,
        ..WriteOptions::default()
    };
    for options in [compressed(3, false), stored_solid] {
        assert_eq!(names_of(&write(options, &members)), added);
    }
}

/// The tie keys, each as a probe showed it: equal names break by size
/// and then by path; a whole last component, not its stem; case counts;
/// a trailing dot sorts after no dot at all; directories deepest first.
#[test]
fn the_sort_key_breaks_ties_as_rar_does() {
    let mut keys = vec![
        ("0.x", 1, false),
        ("e..", 1, false),
        ("d.", 1, false),
        ("b.", 1, false),
        ("c", 1, false),
        ("a", 1, false),
        ("a.txt", 2, false),
        ("a-.txt", 2, false),
        ("_u.txt", 9, false),
        ("B.txt", 9, false),
        ("m/B.txt", 5, false),
        ("q/s.dat", 5, false),
        ("s.dat", 5, false),
        ("d.x/s.dat", 5, false),
        ("p/s.dat", 5, false),
        ("d.x", 0, true),
        ("q", 0, true),
        ("p", 0, true),
        ("a/x/deep", 0, true),
        ("t", 0, true),
    ];
    keys.sort_by(|l, r| {
        MemberSortKey::of(l.0.as_bytes(), l.1, l.2).cmp(&MemberSortKey::of(
            r.0.as_bytes(),
            r.1,
            r.2,
        ))
    });
    let got: Vec<&str> = keys.iter().map(|k| k.0).collect();
    assert_eq!(
        got,
        [
            "a",
            "c",
            "b.",
            "d.",
            "e..",
            "d.x/s.dat",
            "p/s.dat",
            "q/s.dat",
            "s.dat",
            "m/B.txt",
            "B.txt",
            "_u.txt",
            "a-.txt",
            "a.txt",
            "0.x",
            "a/x/deep",
            "p",
            "q",
            "t",
            "d.x",
        ]
    );
}

/// The default is a ceiling the fit brings down: a small input never
/// pays for it.
#[test]
fn the_default_dictionary_is_fitted_to_the_input() {
    let small = write(
        compressed(3, true),
        &[file("a.txt", 1000), file("b.txt", 1000)],
    );
    assert_eq!(dictionary_of(&small), Some(128 << 10));

    // 600 KiB solid in total: 1 MiB declared.
    let members: Vec<_> = (0..3)
        .map(|i| file(&format!("m{i}.txt"), 200 << 10))
        .collect();
    assert_eq!(
        dictionary_of(&write(compressed(1, true), &members)),
        Some(MIB)
    );
    // The same members non-solid reach 200 KiB each: 256 KiB declared.
    assert_eq!(
        dictionary_of(&write(compressed(1, false), &members)),
        Some(256 << 10)
    );

    // 10 MiB solid: the solid default of 32 MiB, fitted to 16 MiB.
    let members: Vec<_> = (0..5)
        .map(|i| file(&format!("m{i}.txt"), 2 * MIB as usize))
        .collect();
    assert_eq!(
        dictionary_of(&write(compressed(3, true), &members)),
        Some(16 * MIB)
    );
    // Level 1 solid keeps the general default: 2 MiB whole.
    assert_eq!(
        dictionary_of(&write(compressed(1, true), &members)),
        Some(2 * MIB)
    );
    // The same members non-solid reach 2 MiB each: level 2's default
    // of 2 MiB whole.
    assert_eq!(
        dictionary_of(&write(compressed(2, false), &members)),
        Some(2 * MIB)
    );
}

/// A policy smaller than the default reduces the DEFAULT rather than
/// refusing it (spec G 3.8.1 step 2), whereas a dictionary the caller
/// named over the policy is still refused.
#[test]
fn a_small_policy_reduces_the_default_and_refuses_a_named_dictionary() {
    let memory = MemoryPolicy {
        max_dictionary: 700 << 10,
        ..MemoryPolicy::default()
    };
    let members: Vec<_> = (0..5)
        .map(|i| file(&format!("m{i}.txt"), 2 * MIB as usize))
        .collect();
    let options = WriteOptions {
        memory,
        ..compressed(1, true)
    };
    assert_eq!(dictionary_of(&write(options, &members)), Some(512 << 10));

    let named = WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(2 * MIB),
        },
        memory,
        ..WriteOptions::default()
    };
    assert!(Writer::new(named).is_err());

    // A stored archive under the same policy is not refused either.
    assert!(Writer::new(WriteOptions {
        memory,
        ..WriteOptions::default()
    })
    .is_ok());
}

/// Sorts `(name, size, directory)` triples by [`MemberSortKey`].
fn sorted(mut keys: Vec<(&'static str, u64, bool)>) -> Vec<&'static str> {
    keys.sort_by(|l, r| {
        MemberSortKey::of(l.0.as_bytes(), l.1, l.2).cmp(&MemberSortKey::of(
            r.0.as_bytes(),
            r.1,
            r.2,
        ))
    });
    keys.into_iter().map(|k| k.0).collect()
}

/// SPEC-G 3.9.1's second probe row: base names and paths, equal sizes
/// wherever base names tie, and a 100,000 byte `zbig.txt` after a 2 byte
/// `e.txt`, because size counts only after the base name.
#[test]
fn spec_g_391_base_name_and_path_row() {
    let want = [
        "in/x..",
        "in/a.gz",
        "in/a.tar.gz",
        "in/a0.gz",
        "in/Z.txt",
        "in/a b.txt",
        "in/a-.txt",
        "in/a.txt",
        "in/aa/a.txt",
        "in/mm/a.txt",
        "in/zz/a.txt",
        "in/zz/yy/a.txt",
        "in/ab.txt",
        "in/e.txt",
        "in/zz/y.txt",
        "in/zbig.txt",
        "in/\u{e9}.txt",
        "in/..x",
    ];
    let mut keys: Vec<(&'static str, u64, bool)> = want
        .iter()
        .rev()
        .map(|n| (*n, if *n == "in/zbig.txt" { 100_000 } else { 2 }, false))
        .collect();
    keys.rotate_left(7);
    assert_eq!(sorted(keys), want);
}

/// SPEC-G 3.9.1's third probe row: directories deepest first, then by
/// extension and base name, a dot in a directory's name an extension.
#[test]
fn spec_g_391_directory_row() {
    let want = [
        "in/b/c/d", "in/zz/b", "in/b/c", "in/a/e", "in/a.y/q", "in/B2", "in/a", "in/b", "in/zz",
        "in/c.x", "in/a.y", "in",
    ];
    let keys: Vec<(&'static str, u64, bool)> = [
        "in/b/c/d", "in/a/e", "in/a.y/q", "in/zz/b", "in/b/c", "in/c.x", "in/B2", "in/a", "in/a.y",
        "in/zz", "in/b", "in",
    ]
    .iter()
    .map(|n| (*n, 0, true))
    .collect();
    assert_eq!(sorted(keys), want);
}
