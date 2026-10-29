//! Spec G 3.13 and SPEC-API 7.1: progress on the write side.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.13 and SPEC-API 7.1: progress on the write side
// ---------------------------------------------------------------------

/// Every report a write made, in order.
#[derive(Default)]
struct Reports {
    /// Each `output` total, in the order they arrived.
    output: Vec<u64>,
    /// Each volume reported complete.
    volumes: Vec<u32>,
    /// Anything `released` was told, which a writer must never call.
    released: Vec<(u32, u64)>,
    /// Fail at the report whose number this is, if any, with this error.
    fail_at: Option<(usize, bool)>,
    made: usize,
}

/// A hook sharing one [`Reports`] with the test that reads it.
#[derive(Clone)]
struct Shared(std::sync::Arc<std::sync::Mutex<Reports>>);

impl rarkit::Progress for Shared {
    fn released(&mut self, volume: u32, offset: u64) -> rarkit::Result<()> {
        self.0.lock().unwrap().released.push((volume, offset));
        Ok(())
    }

    fn volume_done(&mut self, volume: u32) -> rarkit::Result<()> {
        let mut held = self.0.lock().unwrap();
        held.made += 1;
        held.volumes.push(volume);
        Ok(())
    }

    fn output(&mut self, total: u64) -> rarkit::Result<()> {
        let mut held = self.0.lock().unwrap();
        held.made += 1;
        // A stop is `Cancelled` and a hook's own failure is `Caller`,
        // and which one the run ends with is the hook's to choose.
        if let Some((at, cancel)) = held.fail_at {
            if held.made == at {
                return Err(if cancel {
                    rarkit::Error::new(rarkit::ErrorKind::Cancelled)
                } else {
                    rarkit::Error::caller(std::io::Error::other("no further"))
                });
            }
        }
        held.output.push(total);
        Ok(())
    }
}

/// A write reports its payload bytes and its volumes, in order, and a
/// writer never calls `released`.
#[test]
fn a_write_reports_its_payload_bytes_and_its_volumes() {
    let reports = Shared(std::sync::Arc::new(std::sync::Mutex::new(
        Reports::default(),
    )));
    let bodies: Vec<Vec<u8>> = (0..3).map(|i| pseudo(i, 2_500_000)).collect();
    let names: Vec<String> = (0..bodies.len()).map(|i| format!("m{i}.bin")).collect();
    let payload: u64 = bodies.iter().map(|b| b.len() as u64).sum();

    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(3 << 20),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for (index, body) in bodies.iter().enumerate() {
        writer
            .add(MemberSpec {
                name: names[index].as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let mut hook = reports.clone();
    let report = writer
        .finish_volumes_with(&mut volumes, &mut hook)
        .expect("finish");

    let held = reports.0.lock().unwrap();
    assert!(
        held.released.is_empty(),
        "a writer called `released`, which SPEC-API 7.1 says it never does"
    );
    assert_eq!(
        held.volumes,
        (0..report.volumes).collect::<Vec<u32>>(),
        "the volumes were not reported in order"
    );
    assert!(
        held.output.windows(2).all(|pair| pair[0] <= pair[1]),
        "the payload total went backwards: {:?}",
        held.output
    );
    assert_eq!(
        held.output.last().copied(),
        Some(payload),
        "the last total is not the archive's payload"
    );
    // Bounded: at most one per 1 MiB chunk copied, one per member and one
    // per volume, and never one per byte.
    assert!(
        held.made <= (payload as usize) / (1 << 20) + bodies.len() + report.volumes as usize + 8,
        "{} reports for {payload} bytes is not bounded",
        held.made
    );
}

/// A hook that raises its own error ends the run as the CALLER's, and one
/// that asks to stop ends it as `Cancelled`. Two endings, one channel.
#[test]
fn a_progress_hook_ends_the_run_as_caller_or_as_cancelled() {
    for (cancel, wanted) in [(false, "caller"), (true, "cancelled")] {
        let reports = Shared(std::sync::Arc::new(std::sync::Mutex::new(Reports {
            fail_at: Some((2, cancel)),
            ..Reports::default()
        })));
        let body = pseudo(1, 4_000_000);
        let mut writer = Writer::new(WriteOptions {
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"m.bin",
                payload: Payload::Bytes(&body),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut hook = reports.clone();
        let error = writer.finish_into_with(Vec::new(), &mut hook).unwrap_err();
        let got = match error.kind() {
            rarkit::ErrorKind::Caller => "caller",
            rarkit::ErrorKind::Cancelled => "cancelled",
            _ => "other",
        };
        assert_eq!(got, wanted, "a hook asking to stop={cancel} gave {error}");
    }
}
