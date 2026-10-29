//! Spec H3 section 4: a solid member's first block may
//! decode under the table set the member before it left in force, and the
//! writer carries sets inside rar 7.23's envelope.
//!
//! Which members open a set, the envelope's bounds and the bytes at every
//! width are the encoder's tests (`encode::tests`); this
//! file is the archive's half: solid sets of many small members from one
//! text, written by the library and read back member for member by
//! rarkit's own reader, by the old engine through the oracle (a black
//! box), and by reference `unrar` 7.23 `t` and `x`, which must say nothing
//! on stderr. A row that needs `unrar` SKIPS BY NAME where it is not
//! installed. The RAR 2.9 method writes a fresh set in every member (its
//! carried form is not done yet), so its row is the round trip alone.

use std::io::{Cursor, Write};
use std::process::Command;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, Payload, RangeSource, Rar4Version, ReadOptions,
    Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

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

/// 200 members of 1 KiB, with the envelope's edges (32,767 and 32,768
/// bytes) and empty members among them. Named `.txt` alike, so the solid
/// order (spec G 3.9.1) keeps them in name order.
fn set() -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..200u64)
        .map(|i| {
            let len = match i {
                40 => 32_767,
                41 => 32_768,
                81 | 82 => 0,
                _ => 1024,
            };
            (
                format!("f{i:04}.txt").into_bytes(),
                rarkit_testdata::chatter(11 + i, len),
            )
        })
        .collect()
}

fn options(format: WriteFormat, level: u8) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid: true,
        entropy: rarkit::Entropy::Seeded([148; 32]),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

fn writer_for(members: &[(Vec<u8>, Vec<u8>)], options: WriteOptions) -> Writer<'_> {
    let mut writer = Writer::new(options).expect("options");
    for (name, bytes) in members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    writer
}

/// rarkit's reader and the old engine each give every member back.
fn reads_back(volumes: &[Vec<u8>], members: &[(Vec<u8>, Vec<u8>)], what: &str) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: rarkit reading back: {e}"));
    let mut got = sink.members;
    got.sort();
    let mut want = members.to_vec();
    want.sort();
    assert!(got == want, "{what}: rarkit read a member back differently");

    #[cfg(feature = "oracle-compare")]
    {
        let borrowed: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
        let old: Vec<Vec<u8>> = rarkit_oracle::extract(&borrowed, None)
            .unwrap_or_else(|e| panic!("{what}: the old engine reading it: {e:?}"))
            .into_iter()
            .map(|m| m.data)
            .collect();
        // Every name sorts in `add` order under the solid order (one
        // extension, names in order), so the old engine's list is the set's.
        let want: Vec<Vec<u8>> = members.iter().map(|m| m.1.clone()).collect();
        assert!(
            old == want,
            "{what}: the old engine read a member back differently"
        );
    }
}

fn unrar() -> bool {
    Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Reference `unrar` tests the set from its first volume and extracts it,
/// exit 0 and nothing on stderr, every member equal to its input.
fn unrar_reads(volumes: &[Vec<u8>], members: &[(Vec<u8>, Vec<u8>)], what: &str) {
    if !unrar() {
        eprintln!("SKIPPED {what}: reference unrar is not on PATH");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "rarkit-carry-sets-{}-{}",
        what.replace(|c: char| !c.is_ascii_alphanumeric(), "-"),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("x")).expect("a work directory");
    let total = volumes.len() as u32;
    let names: Vec<std::path::PathBuf> = (0..total)
        .map(|i| {
            dir.join(rarkit::volume_file_name(
                "set",
                i,
                total,
                rarkit::VolumeNaming::default(),
            ))
        })
        .collect();
    for (path, bytes) in names.iter().zip(volumes) {
        std::fs::File::create(path)
            .and_then(|mut f| f.write_all(bytes))
            .expect("a volume");
    }
    for verb in ["t", "x"] {
        let run = Command::new("unrar")
            .args([verb, "-y", "-idq"])
            .arg(&names[0])
            .current_dir(dir.join("x"))
            .output()
            .expect("unrar runs");
        assert!(
            run.status.success() && run.stderr.is_empty(),
            "{what}: unrar {verb} refused it\n{}\n{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }
    for (name, bytes) in members {
        let path = dir.join("x").join(String::from_utf8_lossy(name).as_ref());
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{what}: {path:?}: {e}"));
        assert!(
            &got == bytes,
            "{what}: unrar extracted {path:?} differently"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_solid_rar5_set_with_carried_table_sets_reads_back_everywhere() {
    // Acceptance test 1, the RAR 5 archive: every reader
    // gives every member back.
    let members = set();
    for level in [1, 3, 5] {
        let writer = writer_for(&members, options(WriteFormat::Rar5, level));
        let mut out = Cursor::new(Vec::new());
        writer.finish_seek(&mut out).expect("finish");
        let archive = vec![out.into_inner()];
        let what = format!("rar5 m{level}s");
        reads_back(&archive, &members, &what);
        unrar_reads(&archive, &members, &what);
    }
}

#[test]
fn a_solid_rar5_volume_set_with_carried_table_sets_reads_from_its_first_volume() {
    // Acceptance tests 2 and 4: rarkit restarts a solid run at a volume
    // boundary (spec G 3.9), so the member that starts a later volume
    // opens a set; inside each volume the sets carry, and reference unrar
    // tests the whole set from its first volume.
    let members = set();
    let mut options = options(WriteFormat::Rar5, 3);
    options.volume_file_size = Some(24 * 1024);
    let writer = writer_for(&members, options);
    let mut volumes = Vec::new();
    writer.finish_volumes(&mut volumes).expect("finish_volumes");
    assert!(volumes.len() > 2, "a set of several volumes");
    reads_back(&volumes, &members, "rar5 m3s volumes");
    unrar_reads(&volumes, &members, "rar5 m3s volumes");
}

#[test]
fn a_solid_rar4_set_still_reads_back() {
    // The RAR 2.9 method opens a set in every member until its carried
    // form is built; the round trip holds either way.
    let members = set();
    let writer = writer_for(&members, {
        let mut options = options(WriteFormat::Rar4(Rar4Version::V29), 3);
        options.filters = rarkit::FilterPolicy::Off;
        options
    });
    let mut out = Cursor::new(Vec::new());
    writer.finish_seek(&mut out).expect("finish");
    let archive = vec![out.into_inner()];
    reads_back(&archive, &members, "rar4 m3s");
}
