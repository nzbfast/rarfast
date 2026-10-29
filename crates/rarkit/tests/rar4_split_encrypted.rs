//! A RAR 4 family set that SPLITS an encrypted member: every fragment but
//! the last carries the checksum of its CIPHERTEXT, as RAR 5's does (spec K
//! 3.7.6), which is what reference `unrar` 7.23 checks.
//!
//! Spec G 3.10.2 left the family's rule open and the writer took the
//! plaintext's; reference `unrar` 7.23 answered it, "packed data checksum
//! error in volume ...part2.rar" on such a set (measured 28 Sep 2026), and the
//! rule was set to the ciphertext. This crate's reader agrees with
//! `unrar`: it reads the set back only where the writer follows the rule.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Password, Payload, RangeSource,
    Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &str = "split and sealed";

#[derive(Default)]
struct Collect(Vec<(Vec<u8>, bool)>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0
            .push((out.unwrap_or_default(), outcome.checksum_ok == Some(true)));
        Ok(())
    }
}

fn write(method: WriteMethod, data: &[u8]) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V29),
        method,
        password: Some(Password::new(PASSWORD)),
        entropy: rarkit::Entropy::Seeded([3u8; 32]),
        volume_size: Some(250_000),
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"split.txt",
            payload: Payload::Bytes(data),
            mtime: None,
            attributes: 0o644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut volumes).expect("finish_volumes");
    volumes
}

/// Reference `unrar t` over the set, where `unrar` is on PATH.
fn unrar_tests(volumes: &[Vec<u8>], label: &str) {
    if std::process::Command::new("unrar").output().is_err() {
        eprintln!("{label}: SKIPPED the unrar t arm: unrar is not on PATH");
        return;
    }
    let dir = std::env::temp_dir().join(format!("rarkit-r4split-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, volume) in volumes.iter().enumerate() {
        std::fs::write(dir.join(format!("set.part{}.rar", i + 1)), volume).unwrap();
    }
    let output = std::process::Command::new("unrar")
        .arg("t")
        .arg(format!("-p{PASSWORD}"))
        .arg(dir.join("set.part1.rar"))
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    // Not the status alone: on a fragment whose checksum it disagrees
    // with, unrar prints "packed data checksum error" and still ends "All
    // OK" with a success status. And not stdout alone: that error goes to
    // STDERR, which a reader of stdout never sees.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && !said.contains("checksum error"),
        "{label}: reference unrar t objected to the set:\n{said}"
    );
}

#[test]
fn a_split_encrypted_rar4_member_reads_back_and_passes_unrar() {
    let data = rarkit_testdata::chatter(11, 3_000_000);
    for (label, method) in [
        (
            "compressed",
            WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
        ),
        ("stored", WriteMethod::Stored),
    ] {
        let volumes = write(method, &data);
        assert!(volumes.len() > 2, "{label}: the member was not split");
        let sources: Vec<Arc<dyn RangeSource>> = volumes
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect();
        let mut sink = Collect::default();
        let options = ReadOptions::default().with_password(Some(Password::new(PASSWORD)));
        extract(sources, &options, &mut sink, &mut ())
            .unwrap_or_else(|e| panic!("{label}: reading back: {e}"));
        assert_eq!(sink.0.len(), 1, "{label}: member count");
        assert!(
            sink.0[0].1,
            "{label}: the member failed its checksum on read back"
        );
        assert!(
            sink.0[0].0 == data,
            "{label}: the member came back different"
        );
        unrar_tests(&volumes, label);
    }
}
