//! A panic on a look-ahead worker ENDS the extraction: the walking thread
//! does not wait for ever on a member nobody is decoding any more.
//!
//! The panic here is the caller's own: a `RangeSource` that panics when a
//! thread other than the walking one reads it, which is where a look-ahead
//! worker reads its member's packed bytes.
//!
//! One test, `extract` at a stated width of 2 under the default memory
//! policy over a 1 MiB archive built in memory; the offload floor is
//! lowered to zero for the calling thread, so the members go ahead.

#![cfg(feature = "parallel")]

use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;

use rarkit::{
    extract, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const MEMBERS: usize = 4;
const EACH: usize = 256 << 10;

/// One RAR 5 archive, not solid, of `MEMBERS` compressed members.
fn archive() -> Vec<u8> {
    let bodies: Vec<Vec<u8>> = (0..MEMBERS)
        .map(|i| rarkit_testdata::chatter((i as u32 + 1) as u64, EACH))
        .collect();
    let names: Vec<String> = (0..MEMBERS).map(|i| format!("m{i}.txt")).collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(1 << 20),
        },
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("the writer takes these options");
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

/// A source that serves the walking thread and panics under any other.
struct WalkOnly {
    bytes: Vec<u8>,
    walker: ThreadId,
}

impl RangeSource for WalkOnly {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if std::thread::current().id() != self.walker {
            panic!("this test's source panics on a worker");
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

/// How the extraction ended, as its thread reports it.
#[derive(Debug)]
enum Ended {
    /// It returned, with this error text or none.
    Returned(Option<String>),
    /// It unwound: the worker's panic reached the caller.
    Panicked,
}

/// The extraction ends, by an error or by the worker's panic reaching the
/// caller, inside a bound that is thousands of times its run time.
///
/// Before this was pinned the walking thread waited for ever: the worker
/// that panicked had neither ended its member's slot nor answered, and the
/// answers' channel cannot close while the driver holds a sender of its
/// own, so nothing ever woke the walk and the scope never reached the join
/// that would have raised the panic.
#[test]
fn a_panic_on_a_look_ahead_worker_ends_the_extraction() {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        rarkit::probe::set_offload_floor(Some(0));
        rarkit::probe::set_seq_ahead(Some(true));
        let source = WalkOnly {
            bytes: archive(),
            walker: std::thread::current().id(),
        };
        let opts = ReadOptions::default().with_workers(Some(2));
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            extract(
                vec![Arc::new(source) as Arc<dyn RangeSource>],
                &opts,
                &mut Discard,
                &mut (),
            )
        }));
        let _ = tx.send(match ended {
            Ok(result) => Ended::Returned(result.err().map(|e| e.to_string())),
            Err(_) => Ended::Panicked,
        });
    });
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Ended::Returned(None)) => {
            panic!("the extraction reported success over a worker that panicked")
        }
        Ok(_) => {}
        Err(RecvTimeoutError::Timeout) => panic!(
            "the extraction was still running 30 s after a look-ahead worker \
             panicked: the walking thread is waiting on a member nobody decodes"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("the extraction's thread ended unreported"),
    }
}
