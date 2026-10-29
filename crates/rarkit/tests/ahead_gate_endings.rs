//! The look-ahead's gate lets go when the extraction ends badly: a worker
//! waiting at it for the caller's writer does not keep the extraction from
//! ending when ANOTHER worker's member ends in a panic.
//!
//! One test, `extract` at a stated width of 3 (the walk and two workers)
//! under the default memory policy, over an archive of about 13 MiB built
//! in memory. The offload floor is lowered to zero and the gate's window
//! set to 1 MiB for the calling thread, so the second member's worker is
//! held with its slot's four chunks decoded.
//!
//! Nothing is timed: the walking thread WAITS, inside its own source, for
//! a worker to be at the gate before it reads the last header, so a slow
//! machine changes how long the test takes and not what it reads.

#![cfg(feature = "parallel")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use rarkit::{
    extract, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// One RAR 5 archive, not solid: a first member of 1 MiB, a second of
/// 12 MiB, and a third of a few KiB so that neither is the last.
fn archive() -> Vec<u8> {
    let bodies = [
        rarkit_testdata::chatter(1, 1 << 20),
        rarkit_testdata::chatter(2, 12 << 20),
        rarkit_testdata::chatter(3, 4096),
    ];
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(1 << 20),
        },
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("the writer takes these options");
    let names: Vec<String> = (0..bodies.len()).map(|i| format!("m{i}.txt")).collect();
    for (name, body) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0o100644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("the writer takes the member");
    }
    let mut out = std::io::Cursor::new(Vec::new());
    writer
        .finish_seek(&mut out)
        .expect("the archive is written");
    out.into_inner()
}

/// A source that panics when a worker reads the FIRST member's packed
/// bytes (the archive's first twentieth holds its start), and that makes
/// the walking thread wait, at its first read in the archive's last KiB,
/// until a worker is at the gate.
struct Staged {
    bytes: Vec<u8>,
    walker: ThreadId,
    waited: AtomicBool,
    /// Whether a worker was at the gate when the walk went on.
    held: Arc<AtomicBool>,
}

impl RangeSource for Staged {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.bytes.len() as u64;
        if std::thread::current().id() != self.walker {
            if offset < len / 20 {
                panic!("this test's source panics on the first member's worker");
            }
        } else if offset + 1024 >= len && !self.waited.swap(true, Ordering::SeqCst) {
            let end = Instant::now() + Duration::from_secs(60);
            while Instant::now() < end {
                if rarkit::probe::seq_ahead_live().1 > 0 {
                    self.held.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let at = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let take = buf.len().min(self.bytes.len() - at);
        buf[..take].copy_from_slice(&self.bytes[at..at + take]);
        Ok(take)
    }

    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

struct Discard;

impl Sink for Discard {
    type Out = std::io::Sink;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }
}

/// With the second member's worker waiting at the gate, the first member's
/// worker panics; the extraction ends, by an error or by the panic reaching
/// the caller, and does not report success.
///
/// What would hang it: the walk takes the first member's fatal ending and
/// stops delivering, so no delivery ever lets the second member's worker
/// through, and the scope that owns that worker never joins. The gate
/// opens for good when the operation fails, which is what this holds.
#[test]
fn a_worker_at_the_gate_does_not_outlive_a_failed_extraction() {
    let (tx, rx) = channel();
    let held = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&held);
    std::thread::spawn(move || {
        rarkit::probe::set_offload_floor(Some(0));
        rarkit::probe::set_seq_ahead(Some(true));
        rarkit::probe::set_seq_ahead_hold(Some(1 << 20));
        // The members are text, which packs well; held all the same here.
        rarkit::probe::set_seq_ahead_hold_packed(Some(true));
        let source = Staged {
            bytes: archive(),
            walker: std::thread::current().id(),
            waited: AtomicBool::new(false),
            held: seen,
        };
        let opts = ReadOptions::default().with_workers(Some(3));
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            extract(
                vec![Arc::new(source) as Arc<dyn RangeSource>],
                &opts,
                &mut Discard,
                &mut (),
            )
        }));
        let _ = tx.send(match ended {
            Ok(result) => Some(result.is_ok()),
            Err(_) => None,
        });
    });
    match rx.recv_timeout(Duration::from_secs(180)) {
        Ok(Some(true)) => panic!("the extraction reported success over a worker that panicked"),
        Ok(_) => {}
        Err(RecvTimeoutError::Timeout) => panic!(
            "the extraction was still running 180 s after a look-ahead worker \
             panicked: a worker is waiting at the gate for a delivery nobody makes"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("the extraction's thread ended unreported"),
    }
    assert!(
        held.load(Ordering::SeqCst),
        "no worker was at the gate when the walk went on: the test held nothing"
    );
}
