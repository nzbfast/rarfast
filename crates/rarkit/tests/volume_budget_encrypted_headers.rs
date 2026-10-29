//! Under ENCRYPTED headers a FILE budget (`WriteOptions::volume_file_size`)
//! holds every volume to its cap, to the byte.
//!
//! An encrypted header is written WRAPPED: its prefix (a RAR 5 header's
//! initialisation vector, a RAR 4 one's salt) and the header zero padded to
//! a whole cipher block (`HeaderKey::wrap`). The budget charged each header
//! at its PLAIN length, so a volume ran over its cap by what the wrapping
//! adds: 70,030 bytes against 70,000, measured 28 Sep 2026. It was
//! judged a defect.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Password, Payload, RangeSource,
    Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &str = "wrapped headers";

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
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

#[test]
fn every_volume_is_at_most_its_cap_under_encrypted_headers() {
    let members: Vec<(Vec<u8>, Vec<u8>)> = (0..5)
        .map(|i| {
            (
                format!("member-{i}.txt").into_bytes(),
                // Text of 4,096 words, which packs to about half: enough
                // left of 1.1 MiB that every cap below cuts a set.
                rarkit_testdata::chatter_of(i as u64 + 1, 1 << 12, 90_000 + i * 70_001),
            )
        })
        .collect();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        for method in [
            WriteMethod::Stored,
            WriteMethod::Compressed {
                level: 1,
                dictionary: None,
            },
        ] {
            for cap in [20_000u64, 70_000, 250_000] {
                let what = format!("{format:?} {method:?} cap={cap}");
                let mut writer = Writer::new(WriteOptions {
                    format,
                    method,
                    password: Some(Password::new(PASSWORD)),
                    encrypt_headers: true,
                    entropy: rarkit::Entropy::Seeded([5u8; 32]),
                    volume_file_size: Some(cap),
                    filters: rarkit::FilterPolicy::Off,
                    host_os: rarkit::HostOs::Unix,
                    ..WriteOptions::default()
                })
                .expect("options");
                for (name, data) in &members {
                    writer
                        .add(MemberSpec {
                            name,
                            payload: Payload::Bytes(data),
                            mtime: None,
                            attributes: 0o644,
                            host_os: rarkit::HostOs::Unix,
                            is_directory: false,
                        })
                        .expect("add");
                }
                let mut volumes: Vec<Vec<u8>> = Vec::new();
                writer.finish_volumes(&mut volumes).expect("finish_volumes");
                assert!(volumes.len() > 1, "{what}: not a set");
                for (i, volume) in volumes.iter().enumerate() {
                    assert!(
                        volume.len() as u64 <= cap,
                        "{what}: volume {i} is {} bytes against a {cap} byte cap",
                        volume.len()
                    );
                }
                let sources: Vec<Arc<dyn RangeSource>> = volumes
                    .iter()
                    .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
                    .collect();
                let mut sink = Collect::default();
                let options = ReadOptions::default().with_password(Some(Password::new(PASSWORD)));
                extract(sources, &options, &mut sink, &mut ())
                    .unwrap_or_else(|e| panic!("{what}: reading back: {e}"));
                let want: Vec<Vec<u8>> = members.iter().map(|m| m.1.clone()).collect();
                assert_eq!(sink.0, want, "{what}: read back");
            }
        }
    }
}
