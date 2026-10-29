//! The volume budget counted as the whole volume FILE (spec G 3.10, read
//! for the budget the reference's `-v<size>` means, and this crate's
//! `WriteOptions::volume_file_size`).
//!
//! **What the reference does, measured here against `rar` 7.23 on
//! 19 Sep 2026 and pinned by the shapes below.** `-v<size>` caps the
//! volume FILE, not its payload: every volume but the last is EXACTLY
//! `<size>` bytes and the last is whatever is left. It reaches "exactly"
//! by reserving room for the quick-open block and the inline recovery
//! record it might still write and then zero padding whatever it did not
//! use, so a `-v12288b` volume over one stored member is 12,288 bytes of
//! which 9 are zeros after the end block.
//!
//! **What rarkit does, and where it differs on purpose.** A volume is at
//! most the cap and is not padded up to it (spec G 3.10.6 and question
//! 5): the trailing zeros are not a block, every reader skips them, and a
//! poster pays for them. So the promise these tests hold rarkit to is the
//! one a caller splitting for a medium or an upload actually needs - NO
//! VOLUME IS EVER LONGER THAN THE CAP - and not byte identity with the
//! reference, which spec G does not claim for a volume set.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, Payload, RangeSource, ReadOptions, Result, Sink,
    WriteFormat, WriteOptions, Writer,
};

/// Collects each member's name and bytes, in archive order.
#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1 = bytes;
        }
        Ok(())
    }
}

/// Reads a volume set back through this crate's own reader.
fn read_back(volumes: Vec<Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .into_iter()
        .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

/// The RAR 4 family refuses a filter REQUEST (SPEC-J), so a
/// RAR 4 caller has to say `Off` where RAR 5 takes the default.
fn filters_for(format: WriteFormat) -> rarkit::FilterPolicy {
    if matches!(format, WriteFormat::Rar4(_)) {
        rarkit::FilterPolicy::Off
    } else {
        rarkit::FilterPolicy::default()
    }
}

/// Deterministic bytes that an encoder cannot shrink much: a plain
/// multiplicative generator, so a compressed set really is a SET.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Deterministic bytes that do not compress to nothing.
fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 7 + usize::from(seed) * 31 + 3) % 251) as u8)
        .collect()
}

/// Writes `members` under `options` and hands back the volumes.
fn volumes_of(options: WriteOptions, members: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    out
}

#[test]
fn no_volume_is_ever_longer_than_the_file_cap() {
    // The defect this budget exists to fix: `WriteOptions::volume_size`
    // is PAYLOAD bytes, so a caller who asked for 12,288 got 12,347. The
    // cap below is the whole file and nothing may cross it, over every
    // shape the writer can reach without the combinations `Writer::new`
    // refuses.
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        for cap in [1_024u64, 4_096, 12_288, 20_000, 65_536] {
            for members in [1usize, 2, 7] {
                let list: Vec<(Vec<u8>, Vec<u8>)> = (0..members)
                    .map(|k| {
                        (
                            format!("m{k}.bin").into_bytes(),
                            bytes(30_000 / members, k as u8),
                        )
                    })
                    .collect();
                let options = WriteOptions {
                    format,
                    filters: filters_for(format),
                    volume_file_size: Some(cap),
                    host_os: rarkit::HostOs::Unix,
                    ..WriteOptions::default()
                };
                let volumes = volumes_of(options, &list);
                // A cap larger than the whole archive gives ONE volume,
                // which is what the reference does too (`-v65536b` over
                // 30,000 bytes writes a single file, measured 19 Sep
                // 2026); the cap still binds it.
                assert!(!volumes.is_empty(), "{format:?} cap {cap}: something");
                if cap < 30_000 {
                    assert!(volumes.len() > 1, "{format:?} cap {cap}: a set");
                }
                for (index, volume) in volumes.iter().enumerate() {
                    assert!(
                        volume.len() as u64 <= cap,
                        "{format:?} cap {cap}, {members} members: volume {index} is {} bytes",
                        volume.len()
                    );
                }
            }
        }
    }
}

#[test]
fn the_payload_budget_still_means_payload_bytes() {
    // SPEC-API section 7 defines `volume_size` as payload bytes and the
    // field keeps that meaning: this is the OVERSHOOT, measured, so that
    // the two budgets cannot be confused for one another and so that a
    // caller reading this file can see what each one buys.
    let data = bytes(30_000, 1);
    let payload = volumes_of(
        WriteOptions {
            volume_size: Some(12_288),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[(b"m0.bin".to_vec(), data.clone())],
    );
    let file = volumes_of(
        WriteOptions {
            volume_file_size: Some(12_288),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[(b"m0.bin".to_vec(), data.clone())],
    );
    assert!(
        payload[0].len() as u64 > 12_288,
        "the payload budget overshoots the file size by its headers: {} bytes",
        payload[0].len()
    );
    assert!(file[0].len() as u64 <= 12_288, "the file budget does not");
    assert!(
        file.len() >= payload.len(),
        "a file cap fits no more payload per volume than a payload cap of the same figure"
    );
}

#[test]
fn only_the_last_volume_of_a_set_is_short() {
    // The reference's shape, which rarkit keeps: every volume but the
    // last is filled as far as the cap allows, and the last is whatever
    // the archive had left. Without padding "as far as the cap allows"
    // is within one member header of the cap rather than exactly it, so
    // the window below is what a non-final volume may leave unused.
    let data = bytes(100_000, 2);
    let cap = 12_288u64;
    let volumes = volumes_of(
        WriteOptions {
            volume_file_size: Some(cap),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[(b"m0.bin".to_vec(), data)],
    );
    assert!(volumes.len() > 2);
    for (index, volume) in volumes.iter().enumerate() {
        if index + 1 == volumes.len() {
            continue;
        }
        let unused = cap - volume.len() as u64;
        assert!(
            unused < 64,
            "volume {index} left {unused} bytes of its {cap} byte cap unused"
        );
    }
}

#[test]
fn a_file_capped_set_reads_back_to_the_source_bytes() {
    // A budget that produced volumes nothing could join would be no use.
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let one = bytes(40_000, 3);
        let two = bytes(9_000, 4);
        let volumes = volumes_of(
            WriteOptions {
                format,
                filters: filters_for(format),
                volume_file_size: Some(8_192),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            },
            &[
                (b"one.bin".to_vec(), one.clone()),
                (b"two.bin".to_vec(), two.clone()),
            ],
        );
        let got = read_back(volumes);
        assert_eq!(got.len(), 2, "{format:?}");
        assert_eq!(got[0].1, one, "{format:?}: the first member joins");
        assert_eq!(got[1].1, two, "{format:?}: the second member joins");
    }
}

#[test]
fn a_cap_too_small_for_a_volumes_own_blocks_is_refused_by_new() {
    // Spec G section 4's `volume_size` row, read for the budget that
    // counts the whole file: at least one payload byte must fit beside
    // the volume's own blocks, and the caller learns it from `new`.
    let refused = Writer::new(WriteOptions {
        volume_file_size: Some(16),
        ..WriteOptions::default()
    });
    assert!(refused.is_err(), "a 16 byte volume file cannot exist");
}

#[test]
fn the_two_budgets_together_are_refused() {
    let refused = Writer::new(WriteOptions {
        volume_size: Some(4_096),
        volume_file_size: Some(4_096),
        ..WriteOptions::default()
    });
    assert!(refused.is_err(), "two ways to say one budget");
}

#[test]
fn the_cap_holds_with_an_inline_recovery_record() {
    // A RAR 5 volume set may carry a recovery record per volume (spec G
    // 3.11), and the record comes out of the SAME cap as everything else.
    // Its length follows the protected region's, which is the volume's
    // own bytes up to the record, so the reserve is taken at the figure
    // the full cap would need: over-reserving is allowed, exceeding the
    // cap is not.
    let data = bytes(120_000, 5);
    let cap = 16_384u64;
    let volumes = volumes_of(
        WriteOptions {
            volume_file_size: Some(cap),
            recovery_percent: Some(5),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[(b"m0.bin".to_vec(), data.clone())],
    );
    assert!(volumes.len() > 2, "a set of several volumes");
    for (index, volume) in volumes.iter().enumerate() {
        assert!(
            volume.len() as u64 <= cap,
            "volume {index} with a recovery record is {} bytes against a {cap} byte cap",
            volume.len()
        );
    }
    let got = read_back(volumes);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, data, "the joined bytes");
}

#[test]
fn the_cap_holds_with_an_encrypted_member() {
    // An encrypted member's fragments are whole cipher blocks and its
    // last is padded, so the room a fragment takes is not the room its
    // payload asked for. The cap still binds.
    let data = bytes(60_000, 6);
    let cap = 8_192u64;
    let volumes = volumes_of(
        WriteOptions {
            volume_file_size: Some(cap),
            password: Some(rarkit::Password::new("a password")),
            entropy: rarkit::Entropy::Seeded([7; 32]),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[(b"m0.bin".to_vec(), data)],
    );
    assert!(volumes.len() > 2);
    for (index, volume) in volumes.iter().enumerate() {
        assert!(
            volume.len() as u64 <= cap,
            "encrypted volume {index} is {} bytes against a {cap} byte cap",
            volume.len()
        );
    }
}

#[test]
fn the_cap_holds_with_encrypted_headers() {
    // Under header encryption every block after the first lands in the
    // volume as its framing's prefix and the header padded to a whole
    // cipher block, so a header costs more than its image. Until 29 Sep
    // 2026 the budget reserved the IMAGE, and a `-hp` set capped at
    // 120,000 bytes wrote volumes of 120,030. Both families, with and
    // without the RAR 5 recovery record, one member and several.
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let recoveries: &[Option<u32>] = match format {
            WriteFormat::Rar5 => &[None, Some(3), Some(10)],
            // The RAR 4 family refuses a recovery record on a split set.
            WriteFormat::Rar4(_) => &[None],
        };
        for &recovery_percent in recoveries {
            for cap in [2_048u64, 8_192, 20_000] {
                for members in [1usize, 7] {
                    let list: Vec<(Vec<u8>, Vec<u8>)> = (0..members)
                        .map(|k| {
                            (
                                format!("m{k}.bin").into_bytes(),
                                noise(60_000 / members, k as u64 + 11),
                            )
                        })
                        .collect();
                    let options = WriteOptions {
                        format,
                        filters: filters_for(format),
                        volume_file_size: Some(cap),
                        password: Some(rarkit::Password::new("a password")),
                        encrypt_headers: true,
                        recovery_percent,
                        entropy: rarkit::Entropy::Seeded([9; 32]),
                        host_os: rarkit::HostOs::Unix,
                        ..WriteOptions::default()
                    };
                    let volumes = volumes_of(options, &list);
                    let what =
                        format!("{format:?} rr {recovery_percent:?} cap {cap}, {members} members");
                    assert!(volumes.len() > 2, "{what}: a set of several");
                    for (index, volume) in volumes.iter().enumerate() {
                        assert!(
                            volume.len() as u64 <= cap,
                            "{what}: volume {index} is {} bytes",
                            volume.len()
                        );
                    }
                    assert_eq!(read_back_with("a password", volumes), list, "{what}");
                }
            }
        }
    }
}

/// [`read_back`] with a password, for a set whose headers are encrypted.
fn read_back_with(password: &str, volumes: Vec<Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .into_iter()
        .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
        .collect();
    let opts = ReadOptions::default().with_password(Some(rarkit::Password::from(password)));
    let mut sink = Collect::default();
    extract(sources, &opts, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

#[test]
fn the_cap_holds_for_a_compressed_set() {
    // The fragment walk cuts the PACKED bytes, not the member's, so the
    // budget has to bind on what the encoder produced.
    let data = noise(200_000, 8);
    let cap = 12_288u64;
    let volumes = volumes_of(
        WriteOptions {
            method: rarkit::WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            volume_file_size: Some(cap),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[(b"m0.bin".to_vec(), data.clone())],
    );
    assert!(volumes.len() > 1, "a compressed set");
    for (index, volume) in volumes.iter().enumerate() {
        assert!(
            volume.len() as u64 <= cap,
            "compressed volume {index} is {} bytes against a {cap} byte cap",
            volume.len()
        );
    }
    let got = read_back(volumes);
    assert_eq!(got[0].1, data, "the joined bytes");
}

// ---------------------------------------------------------------------
// Spec G 6.1 oracle 1: reference unrar accepts what the budget produces.

/// Whether reference `unrar` is on PATH, so a row can SKIP BY NAME
/// instead of passing quietly.
fn unrar() -> Option<&'static str> {
    std::process::Command::new("unrar")
        .output()
        .ok()
        .map(|_| "unrar")
}

#[test]
fn reference_unrar_accepts_a_file_capped_set() {
    let Some(unrar) = unrar() else {
        eprintln!("SKIPPED: reference unrar is not on PATH");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-vb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (label, format, cap, recovery) in [
        ("r5", WriteFormat::Rar5, 4_096u64, None),
        ("r5rr", WriteFormat::Rar5, 16_384, Some(5u32)),
        (
            "r4",
            WriteFormat::Rar4(rarkit::Rar4Version::V40),
            4_096,
            None,
        ),
    ] {
        let one = noise(50_000, 11);
        let two = bytes(3_000, 12);
        let volumes = volumes_of(
            WriteOptions {
                format,
                filters: filters_for(format),
                volume_file_size: Some(cap),
                recovery_percent: recovery,
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            },
            &[
                (b"one.bin".to_vec(), one.clone()),
                (b"two.bin".to_vec(), two.clone()),
            ],
        );
        for (index, volume) in volumes.iter().enumerate() {
            assert!(
                volume.len() as u64 <= cap,
                "{label}: volume {index} is {} bytes against a {cap} byte cap",
                volume.len()
            );
        }
        let stem = format!("{label}cap");
        let total = volumes.len() as u32;
        for (index, volume) in volumes.iter().enumerate() {
            let name = rarkit::volume_file_name(
                &stem,
                index as u32,
                total,
                rarkit::VolumeNaming::Numbered,
            );
            std::fs::write(dir.join(name), volume).unwrap();
        }
        let first = rarkit::volume_file_name(&stem, 0, total, rarkit::VolumeNaming::Numbered);
        let out = std::process::Command::new(unrar)
            .arg("t")
            .arg("-inul")
            .arg(dir.join(first))
            .output()
            .expect("unrar t");
        assert!(
            out.status.success(),
            "{label}: unrar t on a {cap} byte capped set exited {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_directory_and_an_empty_member_pay_for_their_headers_too() {
    // The fragment walk fits each fragment's header into the cap, but it
    // only runs for a member that HAS bytes: a directory entry and a
    // zero-length member write a header and no payload. Without a check
    // of their own their headers went into the volume with nothing
    // measuring them, and a cap of 81 bytes produced a volume of 104.
    // Found by the `write_members` fuzz target of spec G 6.4.
    let cap = 200u64;
    let options = WriteOptions {
        volume_file_size: Some(cap),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    for name in [
        &b"a-directory-with-a-long-name"[..],
        b"an-empty-member-with-a-long-name.bin",
        b"another-directory-entry-here",
        b"another-empty-one.bin",
    ] {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(b""),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: name.ends_with(b"here") || name.ends_with(b"name"),
            })
            .expect("add");
    }
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut volumes).expect("finish");
    for (index, volume) in volumes.iter().enumerate() {
        assert!(
            volume.len() as u64 <= cap,
            "volume {index} of empty members is {} bytes against a {cap} byte cap",
            volume.len()
        );
    }
    let got = read_back(volumes);
    assert_eq!(got.len(), 4, "every member survives the tight cap");
}

#[test]
fn a_cap_that_cannot_hold_one_members_header_is_refused_not_overflowed() {
    // A cap over the floor `Writer::new` checks can still be too small
    // for a particular member, because `new` has not been told the names
    // yet. The run refuses rather than opening volume after volume or
    // writing one that breaks the cap.
    let mut writer = Writer::new(WriteOptions {
        volume_file_size: Some(70),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("a 70 byte cap is over the floor");
    writer
        .add(MemberSpec {
            name: b"a-name-far-too-long-to-fit-in-a-seventy-byte-volume.bin",
            payload: Payload::Bytes(b"some bytes"),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let refused = writer.finish_volumes(&mut volumes);
    assert!(
        refused.is_err(),
        "the run must refuse a cap it cannot honour"
    );
    for volume in &volumes {
        assert!(
            volume.len() as u64 <= 70,
            "a refused run still wrote a volume over the cap: {} bytes",
            volume.len()
        );
    }
}

#[test]
fn a_comment_that_will_not_fit_the_cap_is_refused() {
    // A comment goes into the first volume and cannot be split, so a cap
    // that cannot hold the head, the comment and the end block is one no
    // run can honour.
    let mut writer = Writer::new(WriteOptions {
        volume_file_size: Some(120),
        comment: Some(vec![b'c'; 4_000]),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    let data = bytes(500, 9);
    writer
        .add(MemberSpec {
            name: b"m.bin",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    assert!(
        writer.finish_volumes(&mut volumes).is_err(),
        "a comment larger than the whole cap must be refused"
    );
}
