//! The warm-abreast work's API leg:
//! one check or one print of a volume set through `rarkit::extract`, as a
//! CALLER of the library that is not rarfast, with or without the hint
//! that every volume is already present (`ReadOptions::volumes_present`).
//! It shows what SPEC-API 5.3 costs a caller that says nothing: such a
//! caller is asked for volume `k + 1` only after every byte of `k` is
//! delivered, so a stored member in small volumes is read by a kept team
//! that joins before it crosses; one that says its volumes are present is
//! read as rarfast reads its files.
//!
//!     cargo run --release --example f_abreast_leg -- \
//!         verify|print unsaid|present <volumes...>
//!
//! `print` writes each member to a writer the options say is not a file,
//! which discards it, as `rarfast p > /dev/null` does.

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
    print: bool,
    good: u64,
}

impl rarkit::Sink for Leg {
    type Out = Null;
    fn open(&mut self, _m: &rarkit::MemberInfo<'_>) -> rarkit::Result<rarkit::Disposition<Null>> {
        Ok(if self.print {
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
    let print = match args.next().as_deref() {
        Some("verify") => false,
        Some("print") => true,
        _ => {
            eprintln!("f_abreast_leg verify|print unsaid|present <volumes...>");
            std::process::exit(2);
        }
    };
    let present = args.next().as_deref() == Some("present");
    let vols: Vec<Arc<dyn rarkit::RangeSource>> = args
        .map(|p| Arc::new(std::fs::File::open(&p).expect("volume")) as Arc<dyn rarkit::RangeSource>)
        .collect();
    let options = rarkit::ReadOptions::default()
        .with_sink_is_file(print.then_some(false))
        .with_volumes_present(present);
    let mut sink = Leg { print, good: 0 };
    let t = Instant::now();
    let report = rarkit::extract(vols, &options, &mut sink, &mut ()).expect("extracts");
    println!(
        "LEG wall_ms={:.3} good={} members={} bytes={}",
        t.elapsed().as_secs_f64() * 1e3,
        sink.good,
        report.members,
        report.bytes
    );
    if sink.good != report.members {
        std::process::exit(1);
    }
}
