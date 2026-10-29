//! Writing a volume set together with its `.rev` recovery volumes in one
//! call (`Writer::finish_volumes_with_recovery`, SPEC-L 3.6, spec G
//! 3.11's last paragraph).
//!
//! The strongest row here is the last one: reference `rar` 7.23 is given
//! a set this crate wrote with a data volume DELETED and the `.rev` files
//! this crate wrote beside it, and is asked to reconstruct. If the
//! reference can rebuild from them, the header, the table, both CRCs and
//! the parity rows are all right, byte for byte, in the only way that
//! matters.

use std::sync::Arc;

use rarkit::{MemberSpec, Payload, RangeSource, RevCount, VolumeNaming, WriteOptions, Writer};

/// Deterministic bytes an encoder cannot shrink much.
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

/// Writes one stored member as a file-capped set with `.rev` volumes.
fn set_with_rev(data: &[u8], cap: u64, count: RevCount) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let options = WriteOptions {
        volume_file_size: Some(cap),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"payload.bin",
            payload: Payload::Bytes(data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let mut rev: Vec<Vec<u8>> = Vec::new();
    let (report, rev_report) = writer
        .finish_volumes_with_recovery(
            &mut volumes,
            &mut rev,
            count,
            &rarkit::rev5::RevOptions {
                memory: rarkit::MemoryPolicy::default(),
            },
        )
        .expect("finish with recovery");
    assert_eq!(report.volumes as usize, volumes.len());
    assert_eq!(rev_report.volumes as usize, rev.len());
    (volumes, rev)
}

#[test]
fn one_call_writes_the_set_and_its_recovery_volumes() {
    let data = noise(60_000, 21);
    let (volumes, rev) = set_with_rev(&data, 8_192, RevCount::Exactly(2));
    assert!(volumes.len() > 3, "a real set");
    assert_eq!(rev.len(), 2, "two recovery volumes");
    // Every `.rev` file names the same set and the same data volumes
    // (SPEC-L 3.6.2), which is what makes them usable together.
    let first = rarkit::rev5::inspect(&rev[0] as &dyn RangeSource).expect("inspect");
    assert_eq!(first.data_count as usize, volumes.len());
    for other in &rev[1..] {
        let info = rarkit::rev5::inspect(other as &dyn RangeSource).expect("inspect");
        assert!(first.same_set(&info), "one set");
    }
}

#[test]
fn the_one_call_form_writes_what_rev5_create_writes() {
    // The entry point adds an ORDER to the two steps, not a difference:
    // a caller who wrote the set and then called `rev5::create` over it
    // gets the same bytes. Nothing here is derived from a clock
    // (SPEC-L 3.6.2), which is what makes that testable at all.
    let data = noise(40_000, 22);
    let (volumes, rev) = set_with_rev(&data, 8_192, RevCount::Exactly(2));
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut afterwards: Vec<Vec<u8>> = Vec::new();
    rarkit::rev5::create(
        &sources,
        2,
        &rarkit::rev5::RevOptions {
            memory: rarkit::MemoryPolicy::default(),
        },
        &mut afterwards,
    )
    .expect("create afterwards");
    assert_eq!(
        rev, afterwards,
        "one call and two calls agree byte for byte"
    );
}

#[test]
fn a_count_policy_that_rounds_to_nothing_is_refused() {
    // A caller who asked for recovery and got none has been told the
    // opposite of the truth (SPEC-L 3.6.4 gives the arithmetic; this is
    // the refusal on top of it).
    assert!(RevCount::Percent(0).resolve(8).is_err());
    assert!(RevCount::Exactly(0).resolve(8).is_err());
    assert_eq!(RevCount::Default.resolve(20).expect("10 percent"), 2);
    assert_eq!(RevCount::Percent(50).resolve(7).expect("half of 7"), 4);
}

#[test]
fn a_deleted_volume_is_rebuilt_from_the_recovery_volumes() {
    let data = noise(60_000, 23);
    let (volumes, rev) = set_with_rev(&data, 8_192, RevCount::Exactly(2));
    let gone = 2usize;

    let infos: Vec<rarkit::rev5::RevInfo> = rev
        .iter()
        .map(|r| rarkit::rev5::inspect(r as &dyn RangeSource).expect("inspect"))
        .collect();
    let recovery: Vec<(&rarkit::rev5::RevInfo, Arc<dyn RangeSource>)> = infos
        .iter()
        .zip(rev.iter())
        .map(|(info, bytes)| (info, Arc::new(bytes.clone()) as Arc<dyn RangeSource>))
        .collect();
    let present: Vec<Option<Arc<dyn RangeSource>>> = volumes
        .iter()
        .enumerate()
        .map(|(index, v)| {
            if index == gone {
                None
            } else {
                Some(Arc::new(v.clone()) as Arc<dyn RangeSource>)
            }
        })
        .collect();

    let mut rebuilt: Vec<u8> = Vec::new();
    let report = rarkit::rev5::repair(
        &rarkit::rev5::RepairSet {
            data: present,
            recovery,
        },
        &rarkit::MemoryPolicy::default(),
        &mut |index| {
            assert_eq!(index as usize, gone);
            Ok(Box::new(Collector(Vec::new())) as Box<dyn std::io::Write + Send>)
        },
        &mut (),
    )
    .expect("repair");
    assert_eq!(report.rebuilt, vec![gone as u32]);
    assert!(report.failed.is_empty(), "the rebuild verified");
    let _ = &mut rebuilt;
}

/// A sink that keeps what was written, so a rebuild can be compared.
struct Collector(Vec<u8>);

impl std::io::Write for Collector {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------
// The reference reads what this writes.

fn rar() -> Option<&'static str> {
    std::process::Command::new("rar")
        .output()
        .ok()
        .map(|_| "rar")
}

#[test]
fn reference_rar_rebuilds_a_deleted_volume_from_our_rev_files() {
    let Some(rar) = rar() else {
        eprintln!("SKIPPED: reference rar is not on PATH");
        return;
    };
    let data = noise(60_000, 24);
    let (volumes, rev) = set_with_rev(&data, 8_192, RevCount::Exactly(2));
    let total = volumes.len() as u32;

    let dir = std::env::temp_dir().join(format!("rarkit-rev-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut names = Vec::new();
    for (index, volume) in volumes.iter().enumerate() {
        let name = rarkit::volume_file_name("set", index as u32, total, VolumeNaming::Numbered);
        std::fs::write(dir.join(&name), volume).unwrap();
        names.push(name);
    }
    // SPEC-L 3.6.4: the reference names recovery row `i` `<base>.partN.rev`.
    for (index, r) in rev.iter().enumerate() {
        let name = format!("set.part{}.rev", index + 1);
        std::fs::write(dir.join(&name), r).unwrap();
    }

    // Take one data volume away and ask the REFERENCE to put it back.
    let gone = dir.join(&names[2]);
    std::fs::remove_file(&gone).unwrap();

    let out = std::process::Command::new(rar)
        .arg("rc")
        .arg(dir.join(&names[0]))
        .current_dir(&dir)
        .output()
        .expect("rar rc");
    assert!(
        out.status.success(),
        "rar rc over our .rev files exited {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let back = std::fs::read(&gone).expect("the reference wrote the volume back");
    assert_eq!(
        back, volumes[2],
        "the reference rebuilt the volume we deleted, byte for byte"
    );

    // And the rebuilt set still tests clean.
    let test = std::process::Command::new(rar)
        .arg("t")
        .arg("-inul")
        .arg(dir.join(&names[0]))
        .output()
        .expect("rar t");
    assert!(test.status.success(), "the rebuilt set tests clean");

    let _ = std::fs::remove_dir_all(&dir);
}
