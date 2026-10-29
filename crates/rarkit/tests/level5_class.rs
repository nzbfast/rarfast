//! Level 5 by class (SPEC-H3 8.1) through the public `Writer`: a member
//! that is not lone takes level 3's lazy parse over the hash chains at 80
//! links where its first megabyte reads few far links a byte and where it
//! is under a megabyte; the lazy parse over the tree otherwise; a solid run
//! takes its FIRST member's class for every member of it, the chains at 72
//! links or the tree; and `WriteOptions::level5_tree` keeps the tree for every one.
//!
//! Which plan a member took is pinned at the encoder, byte for byte against
//! the spelled plans
//! (`encode::tests::a_level_5_member_takes_the_chains_or_the_tree_by_the_reading_of_its_head`).
//! What is pinned here is that the class reaches the writer in every SHAPE
//! it writes: one member and many, bytes in memory and a reader, a member
//! of one window and of several, a solid set, a volume set, an encrypted
//! set, the RAR 4 family, any width; that the option moves level 5 and
//! nothing else; and that every archive reads back.
//!
//! A member's class is read off the default against the option: where the
//! two archives differ the member took the chains, and where they are the
//! same it kept the tree.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, Password, Payload,
    RangeSource, Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};
use std::sync::Arc;

const MIB: usize = 1 << 20;
const SECRET: &str = "level five";

/// Text whose head reads NEAR: the shared text's own 32 words, each of
/// which comes round so often that a chain is spent inside the window
/// it starts in (measured 11 Oct 2026: 2.6 far links a byte, where the
/// cut-off is 7.0).
fn near(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::chatter(seed, len)
}

/// Text whose head reads FAR: a vocabulary of 32,768 words, most of them
/// met again only megabytes on, the way a word list reads (measured
/// 11 Oct 2026: 16.0 far links a byte and next to no long match in the head).
fn far(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::chatter_of(seed, 1 << 15, len)
}

/// [`far`] text with one of 256 phrases of 24 letters after every twenty
/// words: it reads as far as [`far`] does, and a greedy parse of its head
/// takes thousands of long matches where [`far`]'s takes next to none.
fn far_phrased(len: usize, seed: u64) -> Vec<u8> {
    let words = far(len, seed);
    let phrases: Vec<Vec<u8>> = (0..256u32)
        .map(|phrase| {
            let mut letters = rarkit_testdata::Seeded::new(u64::from(phrase));
            (0..24).map(|_| b'A' + letters.below(26) as u8).collect()
        })
        .collect();
    let mut text = Vec::with_capacity(len + 64);
    let mut pick = rarkit_testdata::Seeded::new(seed);
    for (index, word) in words.split(|&byte| byte == b' ').enumerate() {
        if text.len() >= len {
            break;
        }
        text.extend_from_slice(word);
        text.push(b' ');
        if index % 20 == 19 {
            text.extend_from_slice(&phrases[pick.index(phrases.len())]);
            text.push(b' ');
        }
    }
    text.resize(len, b' ');
    text
}

#[derive(Clone, Copy)]
struct Arm {
    level: u8,
    rar4: bool,
    solid: bool,
    reader: bool,
    tree: bool,
    optimal: bool,
    /// `WriteOptions::level5_far_links_only`: the class without its second
    /// statistic.
    far_only: bool,
    workers: usize,
    password: bool,
    /// A volume cap, for a volume set.
    volume: Option<u64>,
}

const DEFAULT: Arm = Arm {
    level: 5,
    rar4: false,
    solid: false,
    reader: false,
    tree: false,
    optimal: false,
    far_only: false,
    workers: 4,
    password: false,
    volume: None,
};

/// The archive's volumes, read back against `members` before they are
/// handed over.
fn write(arm: Arm, members: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        format: if arm.rar4 {
            WriteFormat::Rar4(Rar4Version::V29)
        } else {
            WriteFormat::Rar5
        },
        method: WriteMethod::Compressed {
            level: arm.level,
            dictionary: None,
        },
        // The RAR 4 family writes no filter record (SPEC-J).
        filters: if arm.rar4 {
            FilterPolicy::Off
        } else {
            FilterPolicy::default()
        },
        solid: arm.solid,
        order: rarkit::MemberOrder::AsAdded,
        level5_tree: arm.tree,
        level5_optimal: arm.optimal,
        level5_far_links_only: arm.far_only,
        entropy: Entropy::Seeded([9; 32]),
        workers: Some(arm.workers),
        password: arm.password.then(|| Password::from(SECRET)),
        volume_size: arm.volume,
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.bin").into_bytes())
        .collect();
    let mut readers: Vec<&[u8]> = members.iter().map(|m| &m[..]).collect();
    for ((bytes, name), reader) in members.iter().zip(&names).zip(readers.iter_mut()) {
        let payload = if arm.reader {
            Payload::Reader {
                reader,
                size: bytes.len() as u64,
                crc32: None,
            }
        } else {
            Payload::Bytes(bytes)
        };
        writer
            .add(MemberSpec {
                name,
                payload,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let volumes = if arm.volume.is_some() {
        let mut out: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut out).expect("finish_volumes");
        out
    } else {
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("write");
        vec![out]
    };
    reads_back(arm, &volumes, members);
    volumes
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(arm: Arm, volumes: &[Vec<u8>], members: &[Vec<u8>]) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|volume| Arc::new(volume.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options =
        ReadOptions::default().with_password(arm.password.then(|| Password::from(SECRET)));
    let mut sink = Collect::default();
    extract(sources, &options, &mut sink, &mut ()).expect("read back");
    assert!(sink.0 == members, "the archive reads back as its members");
}

/// Whether the member set takes the chains under `arm`: the default's
/// archive differs from the tree option's.
fn takes_chains(arm: Arm, members: &[Vec<u8>]) -> bool {
    write(arm, members) != write(Arm { tree: true, ..arm }, members)
}

#[test]
fn a_member_takes_the_chains_or_keeps_the_tree_by_its_head_from_bytes_and_from_a_reader() {
    // One member of one window, and one of several windows (the default
    // dictionary at level 5 is 2 MiB), each from bytes in memory and from
    // a reader, RAR 5 and the RAR 4 family.
    for rar4 in [false, true] {
        for len in [MIB + 200_000, 5 * MIB + 77] {
            let (near, far) = (vec![near(len, 3)], vec![far(len, 5)]);
            for reader in [false, true] {
                let arm = Arm {
                    rar4,
                    reader,
                    ..DEFAULT
                };
                assert!(
                    takes_chains(arm, &near),
                    "rar4 {rar4}, {len} bytes, reader {reader}: a near member takes the chains"
                );
                assert!(
                    !takes_chains(arm, &far),
                    "rar4 {rar4}, {len} bytes, reader {reader}: a far member keeps the tree"
                );
            }
        }
        // A member of one window is one packed stream from either payload.
        for member in [vec![near(MIB + 200_000, 3)], vec![far(MIB + 200_000, 5)]] {
            let arm = Arm { rar4, ..DEFAULT };
            assert!(
                write(arm, &member)
                    == write(
                        Arm {
                            reader: true,
                            ..arm
                        },
                        &member
                    ),
                "rar4 {rar4}: bytes and a reader write one archive"
            );
        }
    }
}

#[test]
fn the_head_decides_and_a_member_under_a_megabyte_takes_the_chains() {
    // The class is the first megabyte's: far bytes behind a near head take
    // the chains, near bytes behind a far head keep the tree.
    let mut near_headed = near(MIB, 3);
    near_headed.extend_from_slice(&far(2 * MIB, 5));
    let mut far_headed = far(MIB, 5);
    far_headed.extend_from_slice(&near(2 * MIB, 3));
    for reader in [false, true] {
        let arm = Arm { reader, ..DEFAULT };
        assert!(takes_chains(arm, &[near_headed.clone()]), "a near head");
        assert!(!takes_chains(arm, &[far_headed.clone()]), "a far head");
        // Past the lone bound and under a megabyte there is no reading,
        // and the member takes the chains whatever it holds.
        assert!(
            takes_chains(arm, &[far(600_000, 7)]),
            "reader {reader}: a far member under a megabyte"
        );
        assert!(
            takes_chains(arm, &[far(MIB - 1, 7)]),
            "reader {reader}: one byte under a megabyte"
        );
        assert!(
            !takes_chains(arm, &[far(MIB, 7)]),
            "reader {reader}: a megabyte is read"
        );
        // A lone member has its lone effort either way.
        assert!(
            !takes_chains(arm, &[far(262_144, 7)]),
            "reader {reader}: a lone member is not the option's"
        );
    }
}

#[test]
fn many_members_take_their_own_classes_at_any_width() {
    // A set of both classes and both sizes beside lone members, which the
    // worker team and the writing thread share: each member's class is
    // its own, so the archive is one archive at every width and from
    // either payload kind where every member is one window.
    let set = vec![
        near(MIB + 5, 11),
        far(300_000, 12),
        far(MIB + 300_000, 13),
        near(90_000, 14),
        near(700_000, 15),
        far(MIB + 9, 16),
        near(MIB + 400_000, 17),
    ];
    let reference = write(DEFAULT, &set);
    for workers in [1, 2, 8, 16] {
        for reader in [false, true] {
            let arm = Arm {
                workers,
                reader,
                ..DEFAULT
            };
            assert!(
                write(arm, &set) == reference,
                "{workers} workers, reader {reader}"
            );
        }
    }
    assert!(takes_chains(DEFAULT, &set));
    // Each far member of a megabyte or more keeps the tree in that set:
    // the set without its chain-class members is the option's archive.
    let trees = vec![far(MIB + 300_000, 13), far(MIB + 9, 16)];
    assert!(!takes_chains(DEFAULT, &trees));
}

#[test]
fn a_solid_run_takes_its_first_members_class() {
    // A run has one plan, and it is its FIRST member's, read as a
    // non-solid member is: a megabyte or more reading at or over the
    // cut-off keeps the tree for the whole run, the members after it
    // included; a first member reading under it, or under a megabyte,
    // leaves the run on the chains whatever follows. Through both of the
    // writer's solid walks: a member longer than a window (the default
    // dictionary at level 5 is 2 MiB) is fed a window at a time, and
    // members of at most a window are staged together as a batch.
    for rar4 in [false, true] {
        for reader in [false, true] {
            let arm = Arm {
                rar4,
                reader,
                solid: true,
                ..DEFAULT
            };
            for (name, set) in [
                (
                    "a far first member under a megabyte",
                    vec![far(300_000, 21), far(MIB + 40_000, 22)],
                ),
                ("near", vec![near(300_000, 23), near(MIB + 40_000, 24)]),
                (
                    "a near first member of several windows, far after it",
                    vec![near(3 * MIB, 27), far(MIB + 40_000, 22)],
                ),
                (
                    "small far members",
                    vec![far(100_000, 41), far(150_000, 42), far(200_000, 43)],
                ),
            ] {
                assert!(
                    takes_chains(arm, &set),
                    "rar4 {rar4}, reader {reader}, {name}: the run takes the chains"
                );
            }
            for (name, set) in [
                ("one far member of several windows", vec![far(3 * MIB, 25)]),
                (
                    "a far first member of several windows, near after it",
                    vec![far(3 * MIB, 25), near(300_000, 23), near(MIB + 40_000, 24)],
                ),
                (
                    "a far first member of one window, staged with what follows",
                    vec![far(MIB + 200_000, 29), far(100_000, 41), near(100_000, 44)],
                ),
            ] {
                assert!(
                    !takes_chains(arm, &set),
                    "rar4 {rar4}, reader {reader}, {name}: the run keeps the tree"
                );
            }
            // And it is one archive at any width, whichever class.
            for set in [
                vec![far(300_000, 21), near(MIB + 40_000, 24), far(500_000, 26)],
                vec![
                    far(MIB + 200_000, 29),
                    near(MIB + 40_000, 24),
                    far(500_000, 26),
                ],
            ] {
                let reference = write(arm, &set);
                for workers in [1, 8] {
                    assert!(write(Arm { workers, ..arm }, &set) == reference);
                }
            }
        }
    }
    // An encrypted solid set takes the same classes.
    let arm = Arm {
        solid: true,
        password: true,
        ..DEFAULT
    };
    assert!(!takes_chains(arm, &[far(3 * MIB, 25), near(300_000, 23)]));
    assert!(takes_chains(arm, &[near(3 * MIB, 27), far(300_000, 21)]));
}

#[test]
fn a_volume_set_and_an_encrypted_set_take_the_class() {
    let near = vec![near(3 * MIB, 31), near(400_000, 32)];
    let far = vec![far(3 * MIB, 33)];
    for (name, arm) in [
        (
            "volumes",
            Arm {
                volume: Some(300_000),
                ..DEFAULT
            },
        ),
        (
            "volumes from a reader",
            Arm {
                volume: Some(300_000),
                reader: true,
                ..DEFAULT
            },
        ),
        (
            "solid volumes",
            Arm {
                volume: Some(300_000),
                solid: true,
                ..DEFAULT
            },
        ),
        (
            "encrypted",
            Arm {
                password: true,
                ..DEFAULT
            },
        ),
        (
            "encrypted from a reader",
            Arm {
                password: true,
                reader: true,
                ..DEFAULT
            },
        ),
        (
            "rar4 volumes",
            Arm {
                volume: Some(300_000),
                rar4: true,
                ..DEFAULT
            },
        ),
    ] {
        assert!(takes_chains(arm, &near), "{name}: a near set");
        assert!(
            !takes_chains(arm, &far),
            "{name}: a far member keeps the tree, as a solid run's first member too"
        );
        if arm.volume.is_some() {
            assert!(write(arm, &far).len() > 1, "{name}: more volumes than one");
        }
    }
}

#[test]
fn the_tree_option_moves_level_5_only_and_the_optimal_option_overrides_it() {
    let set = vec![near(MIB + 200_000, 41), far(600_000, 42), near(50_000, 43)];
    for rar4 in [false, true] {
        for solid in [false, true] {
            for level in 1u8..=4 {
                let arm = Arm {
                    level,
                    rar4,
                    solid,
                    ..DEFAULT
                };
                assert!(
                    !takes_chains(arm, &set),
                    "rar4 {rar4}, solid {solid}: the option moved a byte at level {level}"
                );
            }
            let arm = Arm {
                rar4,
                solid,
                ..DEFAULT
            };
            let optimal = write(
                Arm {
                    optimal: true,
                    ..arm
                },
                &set,
            );
            assert!(
                optimal
                    == write(
                        Arm {
                            optimal: true,
                            tree: true,
                            ..arm
                        },
                        &set
                    ),
                "rar4 {rar4}, solid {solid}: level5_optimal overrides level5_tree"
            );
            assert!(optimal != write(arm, &set));
            assert!(optimal != write(Arm { tree: true, ..arm }, &set));
        }
    }
}

#[test]
fn the_second_statistic_moves_a_far_member_with_long_matches_and_nothing_else() {
    // SPEC-H3 8.1, the class's second statistic. A member whose head reads
    // far takes the chains all the same where the head holds long matches
    // enough; a far member with none keeps the tree. Against
    // `WriteOptions::level5_far_links_only` (the class as it was), every
    // member whose class does not move writes the same archive, byte for
    // byte: a near member, one under a megabyte, a lone one, every other
    // level. In every shape: bytes and a reader, one window and several,
    // any width, RAR 5 and the RAR 4 family, a solid run (by its first
    // member), a volume set, an encrypted set. The two options that take
    // the class away override both.
    //
    // `on` is the default; `off` is the option, far links alone.
    let on = DEFAULT;
    const OFF: Arm = Arm {
        far_only: true,
        ..DEFAULT
    };
    for rar4 in [false, true] {
        for len in [MIB + 200_000, 5 * MIB + 77] {
            let phrased = vec![far_phrased(len, 5)];
            let plain = vec![far(len, 5)];
            let near = vec![near(len, 3)];
            for reader in [false, true] {
                let (off, on) = (
                    Arm {
                        rar4,
                        reader,
                        ..OFF
                    },
                    Arm { rar4, reader, ..on },
                );
                let what = format!("rar4 {rar4}, {len} bytes, reader {reader}");
                assert!(
                    !takes_chains(off, &phrased),
                    "{what}: off, far links alone keep the tree"
                );
                assert!(
                    takes_chains(on, &phrased),
                    "{what}: on, long matches take the chains"
                );
                assert!(
                    !takes_chains(on, &plain),
                    "{what}: a far member with no long match keeps the tree"
                );
                assert!(
                    write(on, &plain) == write(off, &plain),
                    "{what}: and writes the archive it wrote"
                );
                assert!(
                    write(on, &near) == write(off, &near),
                    "{what}: a near member writes the archive it wrote"
                );
            }
        }
        let arm = Arm { rar4, ..on };
        let member = vec![far_phrased(MIB + 200_000, 5)];
        assert!(
            write(arm, &member)
                == write(
                    Arm {
                        reader: true,
                        ..arm
                    },
                    &member
                ),
            "rar4 {rar4}: bytes and a reader write one archive"
        );
    }
    // Under a megabyte and lone: unread, and the option reads nothing.
    for len in [600_000, MIB - 1, 262_144, 90_000] {
        let member = vec![far_phrased(len, 9)];
        assert!(
            write(on, &member) == write(OFF, &member),
            "{len} bytes: an unread member writes the archive it wrote"
        );
    }
    // Many members of every class, at any width and from either payload:
    // one archive, and only the member whose class moved differs from the
    // default's.
    let set = vec![
        near(MIB + 5, 11),
        far(300_000, 12),
        far(MIB + 300_000, 13),
        far_phrased(MIB + 100_000, 18),
        near(90_000, 14),
        far_phrased(700_000, 19),
        near(MIB + 400_000, 17),
    ];
    let reference = write(on, &set);
    assert!(reference != write(OFF, &set), "one member's class moved");
    for workers in [1, 2, 8, 16] {
        for reader in [false, true] {
            assert!(
                write(
                    Arm {
                        workers,
                        reader,
                        ..on
                    },
                    &set
                ) == reference,
                "{workers} workers, reader {reader}"
            );
        }
    }
    let mut unmoved = set.clone();
    unmoved.remove(3);
    assert!(
        write(on, &unmoved) == write(OFF, &unmoved),
        "without the member whose class moves, the archive it wrote"
    );
    // A solid run goes by its first member: far with long matches, the
    // run leaves the tree; far with none, or small, the run it was.
    for rar4 in [false, true] {
        for reader in [false, true] {
            let (off, on) = (
                Arm {
                    rar4,
                    reader,
                    solid: true,
                    ..OFF
                },
                Arm {
                    rar4,
                    reader,
                    solid: true,
                    ..on
                },
            );
            let what = format!("rar4 {rar4}, reader {reader}");
            for len in [MIB + 200_000, 3 * MIB] {
                let phrased_first = vec![far_phrased(len, 21), far(400_000, 22), near(500_000, 23)];
                assert!(
                    !takes_chains(off, &phrased_first) && takes_chains(on, &phrased_first),
                    "{what}, {len}: a run whose first member holds long matches takes the chains"
                );
                let plain_first = vec![far(len, 24), far_phrased(MIB + 9, 25), near(500_000, 26)];
                assert!(
                    write(on, &plain_first) == write(off, &plain_first),
                    "{what}, {len}: a run whose first member holds none is the run it was"
                );
            }
            let small_first = vec![far_phrased(300_000, 27), far_phrased(2 * MIB, 28)];
            assert!(
                write(on, &small_first) == write(off, &small_first),
                "{what}: a run whose first member is not read is the run it was"
            );
        }
    }
    // A volume set and an encrypted set.
    let members = [far_phrased(MIB + 300_000, 31), far(MIB + 300_000, 32)];
    for (name, shape) in [
        (
            "a volume set",
            Arm {
                volume: Some(400_000),
                ..DEFAULT
            },
        ),
        (
            "an encrypted set",
            Arm {
                password: true,
                ..DEFAULT
            },
        ),
        (
            "a solid volume set",
            Arm {
                volume: Some(400_000),
                solid: true,
                ..DEFAULT
            },
        ),
    ] {
        for rar4 in [false, true] {
            let on = Arm { rar4, ..shape };
            let off = Arm {
                far_only: true,
                ..on
            };
            let (first, second) = (vec![members[0].clone()], vec![members[1].clone()]);
            assert!(
                takes_chains(on, &first) && !takes_chains(off, &first),
                "{name}, rar4 {rar4}: the member with long matches moves"
            );
            if !shape.password {
                // An encrypted archive draws its salts in member order, so
                // two archives are compared by their sizes there.
                assert!(
                    write(on, &second) == write(off, &second),
                    "{name}, rar4 {rar4}: the member with none does not"
                );
            } else {
                assert_eq!(
                    write(on, &second)[0].len(),
                    write(off, &second)[0].len(),
                    "{name}, rar4 {rar4}: the member with none does not"
                );
            }
        }
    }
    // Levels 1 to 4 read nothing and move no byte; the tree option and the
    // optimal option each override it at level 5.
    let member = vec![far_phrased(MIB + 200_000, 41)];
    for level in 1u8..=4 {
        let arm = Arm { level, ..DEFAULT };
        assert!(
            write(
                Arm {
                    far_only: true,
                    ..arm
                },
                &member
            ) == write(arm, &member),
            "level {level}"
        );
    }
    for solid in [false, true] {
        let tree = Arm {
            tree: true,
            solid,
            ..DEFAULT
        };
        assert!(
            write(
                Arm {
                    far_only: true,
                    ..tree
                },
                &member
            ) == write(tree, &member),
            "solid {solid}: the tree option overrides both"
        );
        let optimal = Arm {
            optimal: true,
            solid,
            ..DEFAULT
        };
        assert!(
            write(
                Arm {
                    far_only: true,
                    ..optimal
                },
                &member
            ) == write(optimal, &member),
            "solid {solid}: the optimal option overrides both"
        );
    }
}
