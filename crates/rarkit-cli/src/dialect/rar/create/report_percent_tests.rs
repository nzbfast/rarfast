//! The report's percent column.

use super::*;

fn file(size: u64, is_dir: bool) -> Chosen {
    Chosen {
        shown: String::new(),
        disk: PathBuf::new(),
        stored: String::new(),
        is_dir,
        size,
        mtime: None,
        attributes: 0,
    }
}

/// The counter after each member is the running total's share, as the
/// sum from the first member gave it, directories and empty files
/// included, and the last member reads 100.
#[test]
fn the_counter_is_the_running_totals_share() {
    let files: Vec<Chosen> = (0..2_000u64)
        .map(|n| file((n * 7919) % 5_003, n % 13 == 0))
        .map(|mut f| {
            if f.is_dir {
                f.size = 0;
            }
            f
        })
        .collect();
    let opts = Options::default();
    let out = Out::new(&opts.shared);
    let report = Report::new(&out, &opts, &files, "arc.rar");
    let total: u64 = files.iter().map(|f| f.size).sum();
    for index in 0..files.len() {
        let through: u64 = files[..=index].iter().map(|f| f.size).sum();
        assert_eq!(
            report.percent_at_end_of(index),
            (through * 100 / total).min(100),
            "member {index}"
        );
    }
    assert_eq!(report.percent_at_end_of(files.len() - 1), 100);
}

#[test]
fn nothing_to_count_reads_zero() {
    let files = vec![file(0, true), file(0, false)];
    let opts = Options::default();
    let out = Out::new(&opts.shared);
    let report = Report::new(&out, &opts, &files, "arc.rar");
    assert_eq!(report.percent_at_end_of(0), 0);
    assert_eq!(report.percent_at_end_of(1), 0);
}
