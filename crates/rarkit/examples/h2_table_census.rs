//! The TABLE CENSUS of RAR 5 archives: per member, how many blocks carry
//! tables and how many of those repeat the previous group's code lengths
//! (SPEC-H2 3.2 and 3.3).
//!
//! **Why.** A reference writer puts a table set in every block of about
//! 16 KiB on media-like input, and rarkit builds each set afresh. Whether a
//! group could skip its build by keeping the previous set depends on how
//! often the lengths repeat, which only a count of real archives says.
//!
//!     cargo run --release --features bench-internals --example h2_table_census -- A.rar ...
//!
//! Prints one line per archive. Reads each whole archive into memory, so
//! give it single volume archives it can hold.

use rarkit::internals::rar5;

fn main() {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).expect("read the archive");
        let mut sum = rar5::TableCensus::default();
        let mut members = 0u64;
        for member in rar5::members(&data) {
            if member.method == 0 || member.directory {
                continue;
            }
            members += 1;
            let c = rar5::table_census(&member.packed, member.algorithm);
            sum.blocks += c.blocks;
            sum.groups += c.groups;
            sum.same_all += c.same_all;
            sum.main_long += c.main_long;
            sum.payload_bytes += c.payload_bytes;
            sum.table_bits += c.table_bits;
            for i in 0..4 {
                sum.same_part[i] += c.same_part[i];
                sum.coded[i] += c.coded[i];
            }
        }
        let g = sum.groups.max(1) as f64;
        println!(
            "{path}: members {members} blocks {} groups {} same_all {} ({:.2}%) same main/dist/align/len {:?} \
             coded per group main {:.1} dist {:.1} align {:.1} len {:.1} main codes over the lookup {:.1} payload per block {:.0} B payload {} B tables {} B ({:.2}%)",
            sum.blocks,
            sum.groups,
            sum.same_all,
            100.0 * sum.same_all as f64 / g,
            sum.same_part,
            sum.coded[0] as f64 / g,
            sum.coded[1] as f64 / g,
            sum.coded[2] as f64 / g,
            sum.coded[3] as f64 / g,
            sum.main_long as f64 / g,
            sum.payload_bytes as f64 / sum.blocks.max(1) as f64,
            sum.payload_bytes,
            sum.table_bits / 8,
            100.0 * (sum.table_bits / 8) as f64 / sum.payload_bytes.max(1) as f64,
        );
    }
}
