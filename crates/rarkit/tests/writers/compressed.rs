//! Spec G 3.8 and 1.2: the compressed path, through spec H3's encoders.

use super::*;

/// A compressed member reads back as itself, at every level the API
/// offers, in both families, through rarkit's own reader and through
/// reference `unrar t`.
#[test]
fn a_compressed_member_reads_back_at_every_level() {
    let data = compressible(300_000);
    let dir = std::env::temp_dir().join(format!("rarkit-gm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        for level in 1..=5u8 {
            let archive = write_one(
                WriteOptions {
                    format,
                    filters: filters_for(format),
                    method: rarkit::WriteMethod::Compressed {
                        level,
                        dictionary: None,
                    },
                    host_os: rarkit::HostOs::Unix,
                    ..WriteOptions::default()
                },
                &[Member {
                    name: b"text.txt".to_vec(),
                    is_directory: false,
                    data: data.clone(),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                }],
            );
            assert!(
                (archive.len() as f64) < data.len() as f64 * 0.7,
                "{format:?} -m{level}: {} bytes for {} of text, which is not compression",
                archive.len(),
                data.len()
            );

            // Oracle 2 of spec G 6.1: this crate's own reader, which
            // could not be used when package G landed because no LZ
            // decoder was wired to the extract path. One is now, so the
            // round trip runs here.
            let back = read_back_bytes(vec![archive.clone()]);
            assert_eq!(back.len(), 1, "{format:?} -m{level}: member count");
            assert_eq!(
                back[0].data, data,
                "{format:?} -m{level}: rarkit read other bytes back"
            );

            let Some(unrar) = unrar() else {
                eprintln!("SKIPPED: reference unrar is not on PATH");
                return;
            };
            let work = dir.join(format!("{format:?}_m{level}"));
            std::fs::create_dir_all(&work).unwrap();
            let path = work.join("a.rar");
            std::fs::write(&path, &archive).unwrap();
            let out = Command::new(unrar)
                .arg("t")
                .arg("-inul")
                .arg(&path)
                .output()
                .expect("unrar t");
            assert!(
                out.status.success(),
                "{format:?} -m{level}: unrar t exited {:?}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
            // And the bytes it gets out are the bytes that went in.
            let out = Command::new(unrar)
                .arg("x")
                .arg("-inul")
                .arg("-y")
                .arg(&path)
                .current_dir(&work)
                .output()
                .expect("unrar x");
            assert!(out.status.success(), "{format:?} -m{level}: unrar x failed");
            assert_eq!(
                std::fs::read(work.join("text.txt")).unwrap(),
                data,
                "{format:?} -m{level}: unrar extracted other bytes"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec G 3.9 and spec H3 section 4: a SOLID compressed set reads back
/// as itself, through this crate's reader and through reference `unrar`.
///
/// **This is what spec H3's erratum of 19 Sep 2026 unblocked.** The seam
/// used to refuse a solid set by name, because the encoder entry took a
/// member's whole input and offered nowhere to pass the state a solid
/// member continues from; section 4 now names that state and the entry
/// carries it, so the refusal is gone and this is the test that says the
/// carrying is real.
///
/// The members are deliberately the SAME text repeated with a small
/// change each time, because that is the shape a solid set exists for: a
/// member that is nearly the member before it should cost almost nothing
/// once the history crosses. The size assertion is what would fail if the
/// history did not actually cross, and the round trips are what would
/// fail if it crossed WRONG.
#[test]
fn a_solid_compressed_set_reads_back_in_both_families() {
    let base = compressible(8_000);
    let members: Vec<Member> = (0..6)
        .map(|index| {
            let mut data = base.clone();
            data.extend_from_slice(format!("\nmember {index} ends here\n").as_bytes());
            Member {
                name: format!("m{index}.txt").into_bytes(),
                is_directory: false,
                data,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
            }
        })
        .collect();
    let dir = std::env::temp_dir().join(format!("rarkit-gs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let options = |solid: bool| WriteOptions {
            format,
            method: rarkit::WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            solid,
            // Ordering is not what this test is about: keep the add order.
            order: rarkit::MemberOrder::AsAdded,
            filters: filters_for(format),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        };
        let plain = write_one(options(false), &members);
        let solid = write_one(options(true), &members);

        assert_eq!(
            read_back_bytes(vec![solid.clone()]),
            members,
            "{format:?}: a solid set did not read back through rarkit"
        );
        // The history crossed: six nearly identical members cost far less
        // solid than they do apart.
        assert!(
            solid.len() * 2 < plain.len(),
            "{format:?}: solid {} bytes against non solid {}, so no history crossed",
            solid.len(),
            plain.len()
        );

        let Some(unrar) = unrar() else {
            continue;
        };
        let work = dir.join(format!("{format:?}"));
        std::fs::create_dir_all(&work).unwrap();
        let path = work.join("a.rar");
        std::fs::write(&path, &solid).unwrap();
        let out = Command::new(unrar)
            .arg("x")
            .arg("-inul")
            .arg("-y")
            .arg(&path)
            .current_dir(&work)
            .output()
            .expect("unrar x");
        assert!(
            out.status.success(),
            "{format:?}: unrar x on a solid set exited {:?}",
            out.status.code()
        );
        for member in &members {
            let name = String::from_utf8_lossy(&member.name).into_owned();
            assert_eq!(
                std::fs::read(work.join(&name)).unwrap(),
                member.data,
                "{format:?}: unrar extracted other bytes for {name}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A solid member whose first byte would land in a NEW volume: the run
/// ends before it is compressed, not after.
///
/// **Found by the `write_volumes` fuzz target**, on a two member solid
/// RAR 3.0 set whose first member's packed bytes fill a volume to the
/// byte. The walk used to open the next volume part way through the
/// second member, AFTER the encoder had been told the member continues
/// the first: the encode carried the history and the header, built after
/// the boundary cleared the run, said the member was not solid. A
/// decoder told that resets its window, and the first match into the
/// history came back `Rar3(DistanceOutOfRange)`. The member opens its
/// volume up front now, so the encode and the header cannot disagree.
#[test]
fn a_solid_member_that_starts_a_volume_is_not_encoded_as_if_it_did_not() {
    // The exact shape the fuzzer found, kept rather than re-derived: the
    // first member's packed bytes have to fill the volume exactly, and
    // that is a property of these bytes at this level.
    let first: Vec<u8> = vec![
        2, 2, 15, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 33, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2,
    ];
    let second: Vec<u8> = vec![
        2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 73, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        150, 159, 159, 115,
    ];
    let wanted: Vec<Member> = [&first, &second]
        .iter()
        .map(|data| Member {
            name: b"\x02\x02\x02".to_vec(),
            is_directory: false,
            data: (*data).clone(),
            mtime: None,
            attributes: 512,
            host_os: rarkit::HostOs::Unix,
        })
        .collect();

    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V30),
        method: rarkit::WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid: true,
        // Ordering is not what this test is about: keep the add order.
        order: rarkit::MemberOrder::AsAdded,
        volume_size: Some(33),
        filters: rarkit::FilterPolicy::Off,
        comment: Some(vec![2, 2]),
        lock: true,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for member in &wanted {
        writer
            .add(MemberSpec {
                name: &member.name,
                payload: Payload::Bytes(&member.data),
                mtime: None,
                attributes: member.attributes,
                host_os: member.host_os,
                is_directory: false,
            })
            .expect("add");
    }
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut volumes).expect("finish_volumes");
    assert_eq!(
        read_back_bytes(volumes),
        wanted,
        "a solid member that starts a volume did not read back"
    );
}

/// A solid set cut over VOLUMES, where spec G 3.9's run ends at every
/// boundary and begins again in the next volume.
#[test]
fn a_solid_set_survives_a_volume_cut() {
    let base = compressible(90_000);
    let members: Vec<Member> = (0..6)
        .map(|index| {
            let mut data = base.clone();
            data.extend_from_slice(format!("\nmember {index}\n").as_bytes());
            Member {
                name: format!("m{index}.txt").into_bytes(),
                is_directory: false,
                data,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
            }
        })
        .collect();

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let mut writer = Writer::new(WriteOptions {
            format,
            method: rarkit::WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            solid: true,
            // Ordering is not what this test is about: keep the add order.
            order: rarkit::MemberOrder::AsAdded,
            volume_size: Some(8_000),
            filters: filters_for(format),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        })
        .expect("options");
        for member in &members {
            writer
                .add(MemberSpec {
                    name: &member.name,
                    payload: Payload::Bytes(&member.data),
                    mtime: member.mtime,
                    attributes: member.attributes,
                    host_os: member.host_os,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
        assert!(report.volumes > 1, "{format:?}: one volume");
        assert_eq!(
            read_back_bytes(volumes),
            members,
            "{format:?}: a solid volume set did not read back"
        );
    }
}

/// Spec G 3.9: an EMPTY member inside a solid set does not break the
/// chain for the members after it.
///
/// A member of no bytes is never compressed - `Run::member` only calls
/// the encoder for `size > 0` - so it is a STORED member in the middle
/// of a solid set, which is the case that section names in as many
/// words. What could go wrong is what spec H3 section 4 made possible to
/// get wrong once the encoder began carrying an index: the empty member
/// could end the run, so that the member after it is HEADED solid and
/// encoded as if it were not, which is the defect `write_volumes` found
/// at a volume boundary in the same area. Empty members sit first, in
/// the middle and last here, because those are three different places in
/// the walk: before any history exists, across a history that has to
/// survive them, and where the set ends. That the history did survive is
/// asserted and not assumed: the set is checked against the same members
/// written NON solid.
#[test]
fn an_empty_member_inside_a_solid_set_does_not_break_the_chain() {
    let base = compressible(8_000);
    let body = |index: usize| {
        let mut data = base.clone();
        data.extend_from_slice(format!("\nmember {index} ends here\n").as_bytes());
        data
    };
    // Empty at 0, at 3 and at 7, which is first, middle and last.
    let members: Vec<Member> = (0..8)
        .map(|index| Member {
            name: format!("e{index}.txt").into_bytes(),
            is_directory: false,
            data: if matches!(index, 0 | 3 | 7) {
                Vec::new()
            } else {
                body(index)
            },
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
        })
        .collect();
    let dir = std::env::temp_dir().join(format!("rarkit-gse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (format, level) in [
        (WriteFormat::Rar5, 3u8),
        (WriteFormat::Rar5, 5),
        (WriteFormat::Rar4(Rar4Version::V40), 3),
        (WriteFormat::Rar4(Rar4Version::V40), 5),
    ] {
        let solid = write_one(
            WriteOptions {
                format,
                method: rarkit::WriteMethod::Compressed {
                    level,
                    dictionary: None,
                },
                solid: true,
                // Ordering is not what this test is about: keep the add order.
                order: rarkit::MemberOrder::AsAdded,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            },
            &members,
        );
        assert_eq!(
            read_back_bytes(vec![solid.clone()]),
            members,
            "{format:?} m{level}: a solid set with empty members did not read back"
        );
        // The history crossed the empty members: five nearly identical
        // bodies cost far less solid than they do apart.
        let plain = write_one(
            WriteOptions {
                format,
                method: rarkit::WriteMethod::Compressed {
                    level,
                    dictionary: None,
                },
                solid: false,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            },
            &members,
        );
        assert!(
            solid.len() * 2 < plain.len(),
            "{format:?} m{level}: solid {} bytes against non solid {}, so the empty members broke the chain",
            solid.len(),
            plain.len()
        );

        let Some(unrar) = unrar() else {
            continue;
        };
        let work = dir.join(format!("{format:?}-m{level}"));
        std::fs::create_dir_all(&work).unwrap();
        let path = work.join("a.rar");
        std::fs::write(&path, &solid).unwrap();
        let out = Command::new(unrar)
            .arg("x")
            .arg("-inul")
            .arg("-y")
            .arg(&path)
            .current_dir(&work)
            .output()
            .expect("unrar x");
        assert!(
            out.status.success(),
            "{format:?} m{level}: unrar x on a solid set with empty members exited {:?}",
            out.status.code()
        );
        for member in &members {
            let name = String::from_utf8_lossy(&member.name).into_owned();
            assert_eq!(
                std::fs::read(work.join(&name)).unwrap(),
                member.data,
                "{format:?} m{level}: unrar extracted other bytes for {name}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec H3 section 4: the index the match finder keeps over a solid
/// set's history CARRIES between its members, and the run buffer that
/// holds that history is bounded, so a long enough set SLIDES it.
///
/// A slide is the one place a run starts its index over: it keeps the
/// dictionary the decoder still holds and walks that again. This set is
/// sized to force one - 120 members of 8 KB over the smallest dictionary
/// the format has, which is 960 KB of output through a buffer of five of
/// those dictionaries - so that the seam is exercised rather than
/// reasoned about. The members are SMALL on purpose: it was
/// measured that a set of 120 KB members saves almost nothing at level 3,
/// because the one enormous match sits behind thousands of nearer
/// occurrences of its own three byte prefix, and that is a match finder
/// reach question and not this one. What is asserted is what a solid set
/// has to satisfy on either side of a slide: every member reads back,
/// reference `unrar` agrees, and the history still crosses.
///
/// Levels 3 and 5, because they are the two MATCH FINDERS: level 3 runs
/// the hash chains and level 5 the carried binary tree, and a run's
/// index carries through each of them by its own code.
#[test]
fn a_solid_set_longer_than_the_run_buffer_slides_and_still_crosses() {
    let base = compressible(8_000);
    let members: Vec<Member> = (0..120)
        .map(|index| {
            let mut data = base.clone();
            data.extend_from_slice(format!("\nmember {index} ends here\n").as_bytes());
            Member {
                name: format!("s{index}.txt").into_bytes(),
                is_directory: false,
                data,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
            }
        })
        .collect();
    let dir = std::env::temp_dir().join(format!("rarkit-gsl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (format, level) in [
        (WriteFormat::Rar5, 3u8),
        (WriteFormat::Rar5, 5),
        (WriteFormat::Rar4(Rar4Version::V40), 3),
        (WriteFormat::Rar4(Rar4Version::V40), 5),
    ] {
        let options = |solid: bool| WriteOptions {
            format,
            method: rarkit::WriteMethod::Compressed {
                level,
                dictionary: Some(128 << 10),
            },
            solid,
            // Ordering is not what this test is about: keep the add order.
            order: rarkit::MemberOrder::AsAdded,
            filters: filters_for(format),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        };
        let plain = write_one(options(false), &members);
        let solid = write_one(options(true), &members);
        // The same options twice give the same archive: a slide is a
        // function of the byte counts and never of timing (API promise
        // 6, spec H3 section 4).
        assert_eq!(
            solid,
            write_one(options(true), &members),
            "{format:?}: a solid set over a sliding buffer is not deterministic"
        );
        assert_eq!(
            read_back_bytes(vec![solid.clone()]),
            members,
            "{format:?}: a solid set over a sliding buffer did not read back"
        );
        assert!(
            solid.len() * 2 < plain.len(),
            "{format:?}: solid {} bytes against non solid {}, so no history crossed a slide",
            solid.len(),
            plain.len()
        );

        let Some(unrar) = unrar() else {
            continue;
        };
        let work = dir.join(format!("{format:?}-m{level}"));
        std::fs::create_dir_all(&work).unwrap();
        let path = work.join("a.rar");
        std::fs::write(&path, &solid).unwrap();
        let out = Command::new(unrar)
            .arg("x")
            .arg("-inul")
            .arg("-y")
            .arg(&path)
            .current_dir(&work)
            .output()
            .expect("unrar x");
        assert!(
            out.status.success(),
            "{format:?} m{level}: unrar x on a slid solid set exited {:?}",
            out.status.code()
        );
        for member in &members {
            let name = String::from_utf8_lossy(&member.name).into_owned();
            assert_eq!(
                std::fs::read(work.join(&name)).unwrap(),
                member.data,
                "{format:?}: unrar extracted other bytes for {name}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The lead encoder's match finder at levels 1 to 3, in bytes, as spec G
/// 3.5's restated finder term states it and `WriteReport::peak_working_memory`
/// counts it since 28 Sep 2026: 2^20 heads, FIXED at every
/// dictionary, and a four-byte link a position over
/// `min(pow2(max(2 * D, 16 Mi)), pow2(max(S, 64 Ki)))` positions. `S` is
/// what a windowed run sizes its finder from, the history it may carry:
/// the dictionary, and the slack of four dictionaries (or one window, if
/// larger) it runs into before it slides. The window is the dictionary
/// clamped to 256 KiB and 8 MiB (spec G 3.7.3).
///
/// A function of the dictionary alone, never of the member, which is why
/// the two bounds below can subtract it and still assert that the member
/// is not held.
fn windowed_chains_bytes(dictionary: u64) -> u64 {
    let window = dictionary.clamp(256 << 10, 8 << 20);
    let span = dictionary + (4 * dictionary).max(window);
    let links = (2 * dictionary)
        .max(16 << 20)
        .next_power_of_two()
        .min(span.max(1 << 16).next_power_of_two());
    4 * (1 << 20) + 4 * links
}

/// The lead encoder's parses in flight for a windowed member whose window
/// is ONE parse block (a dictionary of 256 KiB or less), in bytes, as the
/// encoder charges them and `WriteReport::peak_working_memory` states them
/// since 28 Sep 2026 (SPEC-API 8.2's parse wave row): one parse's scratch, which is a block's
/// tokens at eight bytes a position, its price tables (16 KiB at most) and,
/// at levels 3 and up, the optimal parse's window (at most 1 MiB), and the
/// block's output (the block and 512 bytes). A function of the level,
/// never of the member.
fn one_block_flight_bytes(level: u8) -> u64 {
    let block = 256u64 << 10;
    let optimal = if level >= 3 { 1 << 20 } else { 0 };
    8 * block + (16 << 10) + optimal + block + 512
}

/// Spec H3 8.3, structural requirement 1: "working memory is bounded in
/// bytes and is independent of the input size beyond the dictionary".
///
/// `a_compressed_reader_payload_is_encoded_in_windows` asserts the
/// weaker thing next door - that a member is not HELD whole - which a
/// run whose buffer grew with the member would still satisfy. This one
/// asserts the requirement as it is written, and it is the test that
/// would have caught a carried history buffer sized from the member
/// rather than from the dictionary.
///
/// The one part of the figure that does follow the member is the PACKED
/// output buffer, because a member header's packed size field IS its
/// length, which `Run::packed` names as an open item.
/// So what is asserted flat is the figure MINUS the archive, the archive
/// standing in for that buffer; it overstates it slightly, by the
/// headers and the end block, which only makes the assertion harder to
/// pass. Measured 19 Sep 2026 at a 128 KiB dictionary: 1,966,463 bytes
/// for a 1 MiB member, 1,968,117 for 4 MiB and 1,973,841 for 16 MiB, so
/// a SIXTEENFOLD member moved it by 7,378 bytes.
///
/// Since 28 Sep 2026 the figure also states the lead encoder's finder
/// ([`windowed_chains_bytes`]: 8 MiB at 128 KiB, 4 MiB of heads and 1 Mi
/// links), which is sized from the dictionary and not the member; the
/// run's buffers are asserted as before, above that term (measured: a 1
/// MiB member, 10,354,709 bytes, which is 1,966,101 plus 8 MiB). It also
/// states the parse in flight ([`one_block_flight_bytes`]), set aside the
/// same way (10,940,609 bytes with it).
#[test]
fn a_compressed_run_holds_the_dictionary_and_never_the_member() {
    let remainder = |format: WriteFormat, bytes: usize, dictionary: u64| -> u64 {
        let data = compressible(bytes);
        let mut source = std::io::Cursor::new(data.clone());
        let mut writer = Writer::new(WriteOptions {
            format,
            method: rarkit::WriteMethod::Compressed {
                // Level 1 rather than 3: what is measured here is the
                // run's buffers, which every level shares, and level 1
                // is what makes a 16 MiB member affordable on every
                // `make ci`.
                level: 1,
                dictionary: Some(dictionary),
            },
            filters: filters_for(format),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        })
        .unwrap();
        writer
            .add(MemberSpec {
                // Through a READER, which is the windowed path of spec G
                // 3.7.3 and the one a solid set shares its machinery
                // with: a slice payload could be held without anyone
                // noticing.
                name: b"m.txt",
                payload: Payload::Reader {
                    reader: &mut source,
                    size: data.len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
        let mut archive = Vec::new();
        let report = writer.finish_into(&mut archive).expect("a windowed encode");
        report
            .peak_working_memory
            .saturating_sub(archive.len() as u64)
    };

    const SMALL: u64 = 128 << 10;
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let sizes = [1 << 20usize, 4 << 20, 16 << 20];
        let held: Vec<u64> = sizes.iter().map(|&n| remainder(format, n, SMALL)).collect();
        // The two members of several waves are compared with each other:
        // every parse slot of a wave has been used by the time they end.
        // The 1 MiB member is ONE wave of four blocks, and the outputs its
        // parses keep are stated as they are touched: beside other writes
        // in this process (the tests of this binary run at once) the
        // thread that drives a wave takes a queued block itself
        // (`Engine::chains_sliding`, since 1 Oct 2026), and a block it
        // took did not need a kept output of its own. So the
        // short member may state up to three kept outputs LESS than the
        // long ones, and never more than 64 KiB above them. (Met on a
        // loaded 32-core box and at sixteen copies of this binary at
        // once: 11,142,292 bytes for 1 MiB against 11,401,588 for 4 MiB,
        // one kept output of a 256 KiB block and 512 bytes.)
        //
        // Decided 1 Oct 2026: the writer is
        // right to state what was touched, and this test had assumed a
        // fixed schedule. By the log the behaviour began with an
        // earlier change (as many sliding writes at once
        // as their pool has threads must end, so a pass beside others
        // takes a block as soon as one is queued); a later one changed
        // only WHEN it takes one (past its share of the pool, or after a
        // short patience). Counted on the 32-core box, twenty runs each:
        // 6 failures before that later one, 7 at it, none with this change.
        // A run whose memory follows the member still fails here:
        // with the largest member's length planted into the stated sum
        // the 1 MiB member read 12,450,261 bytes under long ones of
        // 15,596,607, and the test failed.
        let kept_output = (256u64 << 10) + 512;
        let least = held[1].min(held[2]);
        for (bytes, got) in sizes.iter().zip(&held) {
            assert!(
                *got < least + (64 << 10),
                "{format:?}: a {bytes} byte member held {got} bytes against {least} for the \
                 smaller of the long ones, so the run's memory follows the member"
            );
            assert!(
                *got + 3 * kept_output + (64 << 10) > least,
                "{format:?}: a {bytes} byte member held {got} bytes, more than a wave's kept \
                 outputs under the {least} of the long ones"
            );
            // Stated in bytes, and stated against the DICTIONARY: the
            // run's buffers are the dictionary, the slack over it and
            // one window, and at a 128 KiB dictionary that is under
            // 2.5 MiB whatever the member is; beside them the finder,
            // whose term follows the dictionary too, and the parse in
            // flight, whose term follows the level.
            // And since 1 Oct 2026 the store rule's judge, which the run
            // keeps and now STATES (`write::store::Judges::held_bytes`): a
            // member of 1 MiB and more is sampled, by one judge here, 2
            // MiB of tables and 16 KiB beside them whatever the member is.
            const JUDGE_BYTES: u64 = (2 << 20) + (16 << 10);
            assert!(
                *got < 5 * (SMALL << 2)
                    + windowed_chains_bytes(SMALL)
                    + one_block_flight_bytes(1)
                    + JUDGE_BYTES,
                "{format:?}: a {bytes} byte member held {got} bytes at a {SMALL} byte dictionary"
            );
        }
        // And it is the DICTIONARY that the bound follows, which is what
        // makes it a bound rather than a constant that happens to fit.
        let wide = remainder(format, 4 << 20, 1 << 20);
        assert!(
            wide > held[1],
            "{format:?}: the same member held {wide} bytes at a 1 MiB dictionary against \
             {} at a 128 KiB one, so the bound does not follow the dictionary",
            held[1]
        );
    }
}

/// Spec G 3.7.3: a compressed member whose bytes arrive through a reader
/// is encoded a WINDOW at a time, and what comes out is a member.
///
/// The dictionary is named small on purpose, because the window follows
/// it: a 4 MiB member over a 256 KiB window is sixteen windows and
/// fifteen seams, which is the case a single-window test would not
/// reach. The member is larger than the run's fixed buffers for the same
/// reason: "the input is never held" is only visible above them. What is
/// asserted is what a member has to satisfy - rarkit reads it back, and
/// so does reference `unrar` - and NOT that it is byte-identical to the
/// same member encoded whole, because it is not: a match cannot reach
/// across a window's start, and that is what a window costs.
#[test]
fn a_compressed_reader_payload_is_encoded_in_windows() {
    let data = compressible(4 << 20);
    let dir = std::env::temp_dir().join(format!("rarkit-gw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        for stated in [false, true] {
            let mut source = std::io::Cursor::new(data.clone());
            let mut writer = Writer::new(WriteOptions {
                format,
                method: rarkit::WriteMethod::Compressed {
                    level: 3,
                    dictionary: Some(256 << 10),
                },
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            })
            .unwrap();
            writer
                .add(MemberSpec {
                    name: b"windowed.txt",
                    payload: Payload::Reader {
                        reader: &mut source,
                        size: data.len() as u64,
                        crc32: stated.then(|| rarkit::checksum::crc32(&data)),
                    },
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .unwrap();
            let mut archive = Vec::new();
            // The SEGMENT TEAM held to one engine, so that this still says
            // what it was written to say of the WALK, that it encodes in
            // windows and does not hold the input: with no ceiling named
            // the team holds a stretch an engine (SPEC-G 3.7.3's default
            // mode), which `tests/team_memory.rs` bounds.
            let report = rarkit::internals::writers::with_segment_width(1, || {
                writer.finish_into(&mut archive)
            })
            .expect("a windowed encode");
            assert!(
                (archive.len() as f64) < data.len() as f64 * 0.7,
                "{format:?} stated={stated}: {} bytes for {} of text",
                archive.len(),
                data.len()
            );
            // The INPUT is never held: what the run holds of the member
            // is one window, and the window follows the dictionary.
            // The figure also states the lead's finder (12 MiB here: 4
            // MiB of heads and 2 Mi links for the 1.25 MiB of history
            // a 256 KiB dictionary carries), which follows the
            // dictionary and not the member, so it is set aside.
            let finder = windowed_chains_bytes(256 << 10);
            assert!(
                report.peak_working_memory >= finder,
                "{format:?}: {} stated, under the finder's own {finder}",
                report.peak_working_memory
            );
            // And the parse in flight, at most one block's: the window is
            // one parse block.
            let flight = one_block_flight_bytes(3);
            assert!(
                report.peak_working_memory.saturating_sub(finder + flight) < data.len() as u64,
                "{format:?}: a {} byte member was written holding {} bytes, {finder} of \
                 them its finder and at most {flight} its parse",
                data.len(),
                report.peak_working_memory
            );

            let back = read_back_bytes(vec![archive.clone()]);
            assert_eq!(back.len(), 1, "{format:?} stated={stated}: member count");
            assert_eq!(
                back[0].data, data,
                "{format:?} stated={stated}: rarkit read other bytes back"
            );

            let Some(unrar) = unrar() else {
                continue;
            };
            let work = dir.join(format!("{format:?}_{stated}"));
            std::fs::create_dir_all(&work).unwrap();
            let path = work.join("a.rar");
            std::fs::write(&path, &archive).unwrap();
            let out = Command::new(unrar)
                .arg("t")
                .arg("-inul")
                .arg(&path)
                .output()
                .expect("unrar t");
            assert!(
                out.status.success(),
                "{format:?} stated={stated}: unrar t exited {:?}",
                out.status.code()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A reader that states the WRONG checksum for a compressed member is
/// refused, as it is for a stored one: the promise is about the unpacked
/// bytes and the writer checks it against the bytes that passed.
#[test]
fn a_wrong_checksum_on_a_compressed_reader_is_refused() {
    let data = compressible(300_000);
    let mut source = std::io::Cursor::new(data.clone());
    let mut writer = Writer::new(WriteOptions {
        method: rarkit::WriteMethod::Compressed {
            level: 1,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .unwrap();
    writer
        .add(MemberSpec {
            name: b"a.txt",
            payload: Payload::Reader {
                reader: &mut source,
                size: data.len() as u64,
                crc32: Some(rarkit::checksum::crc32(&data) ^ 1),
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .unwrap();
    let error = writer.finish_into(Vec::new()).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            rarkit::ErrorKind::Corrupt(rarkit::Corruption::Checksum)
        ),
        "a wrong checksum on a compressed reader gave {error}"
    );
}

/// Every compressed SHAPE, written by rarkit and read back by rarkit.
///
/// The test above walks the levels on one member in one archive. This one
/// walks the shapes the writer puts a compressed member INTO - several
/// members, a volume set, a member cipher, an encrypted header - in both
/// families and at the ends of the level range, because each of those is
/// a different path through `write::engine` and a compressed member is
/// the payload none of them had when package G landed.
///
/// Spec G 3.9's SOLID sets have their own two tests above, because what
/// they have to prove is that a history CROSSED and not only that the
/// bytes came back.
#[test]
fn every_compressed_shape_reads_back_through_rarkit() {
    /// `count` members cut out of `data`, named in order.
    fn members(data: &[u8], count: usize) -> Vec<Member> {
        let each = data.len() / count;
        (0..count)
            .map(|index| {
                let end = if index + 1 == count {
                    data.len()
                } else {
                    (index + 1) * each
                };
                Member {
                    name: format!("m{index:02}.txt").into_bytes(),
                    is_directory: false,
                    data: data[index * each..end].to_vec(),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                }
            })
            .collect()
    }

    let data = compressible(400_000);
    let formats = [
        WriteFormat::Rar5,
        WriteFormat::Rar4(Rar4Version::V29),
        WriteFormat::Rar4(Rar4Version::V30),
        WriteFormat::Rar4(Rar4Version::V40),
    ];
    for format in formats {
        for level in [1u8, 3, 5] {
            let method = rarkit::WriteMethod::Compressed {
                level,
                dictionary: None,
            };
            let base = || WriteOptions {
                format,
                method,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            };

            // Several members in one archive.
            let wanted = members(&data, 7);
            let archive = write_one(base(), &wanted);
            let back = read_back_bytes(vec![archive]);
            assert_eq!(
                back, wanted,
                "{format:?} -m{level}: seven compressed members did not come back"
            );

            // The same members cut over a volume set. The cut lands in
            // the middle of a compressed member's PACKED bytes, which is
            // the one shape a compressed volume set has that a stored one
            // does not.
            let mut writer = Writer::new(WriteOptions {
                volume_size: Some(40_000),
                ..base()
            })
            .expect("volume options");
            for member in &wanted {
                writer
                    .add(MemberSpec {
                        name: &member.name,
                        payload: Payload::Bytes(&member.data),
                        mtime: member.mtime,
                        attributes: member.attributes,
                        host_os: member.host_os,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            assert!(
                report.volumes > 1,
                "{format:?} -m{level}: the volume leg wrote one volume"
            );
            assert_eq!(
                read_back_bytes(volumes),
                wanted,
                "{format:?} -m{level}: a compressed volume set did not come back"
            );

            // Encrypted, and encrypted headers on top of that. The
            // cipher sits between the encoder and the output, so a
            // compressed member is the case that says the two are in the
            // right order.
            for headers in [false, true] {
                let archive = write_one(
                    WriteOptions {
                        password: Some(Password::new(b"a-compressed-shape".to_vec())),
                        encrypt_headers: headers,
                        entropy: rarkit::Entropy::Seeded([0x5A; 32]),
                        ..base()
                    },
                    &wanted,
                );
                let sources: Vec<Arc<dyn RangeSource>> =
                    vec![Arc::new(archive) as Arc<dyn RangeSource>];
                let options = ReadOptions::default()
                    .with_password(Some(Password::new(b"a-compressed-shape".to_vec())));
                let mut sink = Collect::default();
                extract(sources, &options, &mut sink, &mut NoProgress).unwrap_or_else(|e| {
                    panic!("{format:?} -m{level} headers={headers}: reading back: {e}")
                });
                assert_eq!(
                    sink.members, wanted,
                    "{format:?} -m{level} headers={headers}: did not come back"
                );
            }
        }
    }
}

#[test]
fn a_solid_set_is_the_same_archive_whether_its_members_are_batched_or_not() {
    // The writer stages a run of solid members and encodes them as ONE
    // wave, so the parse stays wide across the member boundaries instead
    // of joining at every one of them (measured: a 512 KiB
    // solid member is two parse blocks, and the create legs' solid arm
    // ran 1.90x parallel where the same bytes in one member ran 10.63x,
    // for the same CPU). A batch may not move a byte of the archive.
    //
    // The arm that does NOT batch is a READER payload, which is pulled
    // once and so is encoded a member at a time (`Run::may_batch` says
    // why). The two arms are the same members, the same options and the
    // same bytes, so the archives have to be identical to the byte.
    let base = compressible(30_000);
    let members: Vec<Member> = (0..40)
        .map(|index| {
            let mut data = base.clone();
            data.extend_from_slice(format!("\nmember {index} ends here\n").as_bytes());
            Member {
                name: format!("b{index}.txt").into_bytes(),
                is_directory: false,
                data,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
            }
        })
        .collect();

    for (format, level) in [
        (WriteFormat::Rar5, 1u8),
        (WriteFormat::Rar5, 3),
        (WriteFormat::Rar5, 5),
        (WriteFormat::Rar4(Rar4Version::V40), 3),
        (WriteFormat::Rar4(Rar4Version::V40), 5),
    ] {
        let options = || WriteOptions {
            format,
            method: rarkit::WriteMethod::Compressed {
                level,
                dictionary: Some(1 << 20),
            },
            solid: true,
            // Ordering is not what this test is about: keep the add order.
            order: rarkit::MemberOrder::AsAdded,
            filters: filters_for(format),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        };
        let batched = write_one(options(), &members);

        let mut readers: Vec<std::io::Cursor<&[u8]>> = members
            .iter()
            .map(|member| std::io::Cursor::new(member.data.as_slice()))
            .collect();
        let mut writer = Writer::new(options()).expect("options");
        let mut slots = readers.iter_mut();
        for member in &members {
            writer
                .add(MemberSpec {
                    name: &member.name,
                    payload: Payload::Reader {
                        reader: slots.next().expect("one reader per member"),
                        size: member.data.len() as u64,
                        crc32: None,
                    },
                    mtime: member.mtime,
                    attributes: member.attributes,
                    host_os: member.host_os,
                    is_directory: member.is_directory,
                })
                .expect("add");
        }
        let mut apiece = Vec::new();
        writer.finish_into(&mut apiece).expect("finish");

        assert_eq!(
            batched.len(),
            apiece.len(),
            "{format:?} level {level}: a batched solid set is a different length"
        );
        assert!(
            batched == apiece,
            "{format:?} level {level}: batching the solid set moved a byte"
        );
        assert_eq!(
            read_back_bytes(vec![batched.clone()]),
            members,
            "{format:?} level {level}: the batched solid set did not read back"
        );
        // Deterministic, which a wider wave is the obvious threat to.
        assert_eq!(
            batched,
            write_one(options(), &members),
            "{format:?} level {level}: a batched solid set is not deterministic"
        );
    }
}
