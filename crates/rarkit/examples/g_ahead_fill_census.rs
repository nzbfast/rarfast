//! The solid chain decode-ahead's reach, by member size.
//!
//! Extracts each archive named on the command line through the shipped
//! read path and, at every member's close, reads how many members the
//! decode-ahead has claimed so far (`probe::ahead_claims`, compiled in only
//! with `h2-probes`). The change across one member says whether that member
//! was applied from tapes decoded ahead. Members are binned by PACKED size,
//! beside the stage's own bound (`AHEAD_MEMBER_MAX`, 1 MiB) and the
//! buffered source's clamp (`MAX_PACKED`, 16 MiB and five bytes).
//!
//!     cargo run --release -p rarkit --features h2-probes \
//!         --example g_ahead_fill_census -- a.rar b.rar

use std::sync::Arc;
use std::time::Instant;

use rarkit::{Disposition, MemberInfo, RangeSource, ReadOptions, Result, Sink};

const CLASSES: [(&str, u64); 6] = [
    ("< 64 KiB", 64 << 10),
    ("64 KiB to 256 KiB", 256 << 10),
    ("256 KiB to 1 MiB", 1 << 20),
    ("1 to 4 MiB", 4 << 20),
    ("4 to 16 MiB", 16 << 20),
    ("16 MiB and over", u64::MAX),
];

#[derive(Default, Clone, Copy)]
struct Class {
    members: u64,
    packed: u64,
    claimed: u64,
    claimed_packed: u64,
}

#[derive(Default)]
struct Census {
    classes: [Class; 6],
    last: u64,
    largest_claimed: u64,
}

impl Sink for Census {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Verify)
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        let now = rarkit::probe::ahead_claims();
        let claimed = now > self.last;
        self.last = now;
        if member.is_directory || member.unpacked_size == Some(0) {
            return Ok(());
        }
        let packed = member.packed_size;
        let at = CLASSES
            .iter()
            .position(|(_, below)| packed < *below)
            .unwrap_or(CLASSES.len() - 1);
        let class = &mut self.classes[at];
        class.members += 1;
        class.packed += packed;
        if claimed {
            class.claimed += 1;
            class.claimed_packed += packed;
            self.largest_claimed = self.largest_claimed.max(packed);
        }
        Ok(())
    }
}

fn main() {
    for path in std::env::args().skip(1) {
        let archive = Arc::new(std::fs::read(&path).expect("the archive reads"));
        rarkit::probe::reset_ahead_claims();
        let mut census = Census::default();
        let at = Instant::now();
        rarkit::extract(
            vec![archive as Arc<dyn RangeSource>],
            &ReadOptions::default(),
            &mut census,
            &mut (),
        )
        .expect("the archive extracts");
        let wall = at.elapsed().as_secs_f64();
        println!(
            "{path}: wall {wall:.3} s, claims {}, largest claimed packed {} bytes",
            rarkit::probe::ahead_claims(),
            census.largest_claimed
        );
        println!("| packed class | members | packed MiB | claimed | claimed MiB |");
        println!("|---|---|---|---|---|");
        for ((name, _), class) in CLASSES.iter().zip(census.classes.iter()) {
            println!(
                "| {name} | {} | {:.1} | {} | {:.1} |",
                class.members,
                class.packed as f64 / 1048576.0,
                class.claimed,
                class.claimed_packed as f64 / 1048576.0
            );
        }
    }
}
