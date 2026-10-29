//! The stored split CRC work's direction leg: one test or extract of one
//! volume set through the public API, its wall printed. The P1 cell driver
//! of the CRC combine timing script.
//!
//!     cargo run --release --example g_crc_leg -- verify|write <volumes...>

use std::sync::Arc;
use std::time::Instant;

struct Null;

impl std::io::Write for Null {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Leg {
    write: bool,
    good: u64,
}

impl rarkit::Sink for Leg {
    type Out = Null;
    fn open(&mut self, _m: &rarkit::MemberInfo<'_>) -> rarkit::Result<rarkit::Disposition<Null>> {
        Ok(if self.write {
            rarkit::Disposition::Write(Null)
        } else {
            rarkit::Disposition::Verify
        })
    }
    fn close(
        &mut self,
        _m: &rarkit::MemberInfo<'_>,
        _o: Option<Null>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        if outcome.checksum_ok == Some(true) {
            self.good += 1;
        }
        Ok(())
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let write = args.next().as_deref() == Some("write");
    let vols: Vec<Arc<dyn rarkit::RangeSource>> = args
        .map(|p| Arc::new(std::fs::File::open(&p).expect("volume")) as Arc<dyn rarkit::RangeSource>)
        .collect();
    let mut sink = Leg { write, good: 0 };
    let t = Instant::now();
    let report = rarkit::extract(vols, &rarkit::ReadOptions::default(), &mut sink, &mut ())
        .expect("extracts");
    println!(
        "LEG wall_ms={:.3} good={} bytes={}",
        t.elapsed().as_secs_f64() * 1e3,
        sink.good,
        report.bytes
    );
}
