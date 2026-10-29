//! Spec G 3.11: the inline recovery record.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.11: the inline recovery record
// ---------------------------------------------------------------------

/// A recovery record archive is accepted by reference `rar t`, which
/// reports on the record itself, and the record is found where spec G
/// 3.11 puts it.
#[test]
fn an_inline_recovery_record_lands_where_the_specification_puts_it() {
    let members = read_back(&["r5_store.rar"]);
    let dir = std::env::temp_dir().join(format!("rarkit-grr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (label, format) in [
        ("r5", WriteFormat::Rar5),
        ("r4", WriteFormat::Rar4(Rar4Version::V40)),
    ] {
        let options = WriteOptions {
            format,
            filters: filters_for(format),
            recovery_percent: Some(5),
            ..WriteOptions::default()
        };
        let archive = write_one(options, &members);

        // The record is the last block before the end header.
        let opened = Archive::open(
            Arc::new(archive.clone()) as Arc<dyn RangeSource>,
            &ReadOptions::default(),
        )
        .unwrap();
        let kinds: Vec<_> = opened.blocks().map(|b| b.kind).collect();
        assert!(kinds.len() >= 2, "{label}: {} blocks", kinds.len());

        let got = read_back_bytes(vec![archive.clone()]);
        assert_eq!(got.len(), members.len(), "{label}: member count");
        for (want, got) in members.iter().zip(&got) {
            assert_eq!(want.data, got.data, "{label}: the member's bytes");
        }

        if let Some(unrar) = unrar() {
            let path = dir.join(format!("{label}_rr.rar"));
            std::fs::write(&path, &archive).unwrap();
            let out = Command::new(unrar)
                .arg("t")
                .arg("-inul")
                .arg(&path)
                .output()
                .expect("unrar t");
            assert!(
                out.status.success(),
                "{label}: unrar t on a recovery archive exited {:?}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The record this writer builds is a record that REPAIRS: a damaged
/// volume is put back through `recovery::repair_inline` and comes out as
/// the bytes that went in (spec G 6.2).
#[test]
fn a_damaged_volume_is_repaired_from_the_record_this_writer_built() {
    let data: Vec<u8> = (0..60_000u32).map(|i| (i.wrapping_mul(97)) as u8).collect();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let mut writer = Writer::new(WriteOptions {
            format,
            filters: filters_for(format),
            recovery_percent: Some(10),
            ..WriteOptions::default()
        })
        .unwrap();
        writer
            .add(MemberSpec {
                name: b"payload.bin",
                payload: Payload::Bytes(&data),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
        let mut good = Vec::new();
        writer.finish_into(&mut good).unwrap();

        let mut damaged = good.clone();
        for byte in &mut damaged[1_000..1_400] {
            *byte ^= 0xff;
        }
        let mut repaired = Vec::new();
        rarkit::recovery::repair_inline(&damaged, &ReadOptions::default(), &mut repaired)
            .unwrap_or_else(|e| panic!("{format:?}: repairing: {e}"));
        let got = read_back_bytes(vec![repaired]);
        assert_eq!(got.len(), 1, "{format:?}: member count after repair");
        assert_eq!(got[0].data, data, "{format:?}: the repaired bytes");
    }
}
