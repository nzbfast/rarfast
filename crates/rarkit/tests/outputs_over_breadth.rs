//! The half of the outputs bound the outputs tests cannot see: with the
//! outputs factor at its default of two, the members DECODING at once are
//! still at most the breadth. Only the members waiting to close, answer in
//! hand, sit above it.
//!
//! In a test binary of its own, with ONE test in it, because the counter
//! that reads it (`rarkit::probe::peak_members`) is process-wide and any
//! other extraction running beside it in the same process would move it.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Result,
};

/// A writer that sleeps on its first write, so answers arrive out of order
/// and early harvesting has something to do.
struct Slow(Option<Duration>);

impl Write for Slow {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(d) = self.0.take() {
            std::thread::sleep(d);
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Sink(std::sync::atomic::AtomicUsize);

impl ParallelSink for Sink {
    type Out = Slow;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Slow>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let delay = n.is_multiple_of(3).then_some(Duration::from_millis(40));
        Ok(Disposition::Write(Slow(delay)))
    }
    fn close(&self, _: &MemberInfo<'_>, _: Option<Slow>, _: &MemberOutcome) -> Result<()> {
        Ok(())
    }
}

#[test]
fn at_the_default_factor_the_members_decoding_at_once_stay_at_the_breadth() {
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::set_outputs_over_breadth(Some(2));
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives/r420_m5.rar"
    ));
    let bytes = std::fs::read(&path).expect("the fixture");
    for breadth in [1usize, 2, 3] {
        rarkit::probe::reset_peak_members();
        let sink = Sink(std::sync::atomic::AtomicUsize::new(0));
        let sources = vec![Arc::new(bytes.clone()) as Arc<dyn RangeSource>];
        extract_parallel(sources, &ReadOptions::default(), &sink, breadth).expect("parallel");
        let peak = rarkit::probe::peak_members();
        assert!(peak >= 1, "nothing was dispatched at breadth {breadth}");
        assert!(
            peak <= breadth,
            "{peak} members were decoding at once at a breadth of {breadth}; the \
             outputs factor may only raise the members OPEN, never those decoding"
        );
    }
}
