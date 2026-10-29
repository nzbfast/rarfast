//! COUNT what a fuzz corpus actually reaches in the RAR 2.0 multimedia
//! predictor, one input at a time.
//!
//! The question this answers is the one a target list cannot. Of the 43
//! registered fuzz targets only `fuzz:rar20_member` and
//! `fuzz:rar20_tables` have an input that can reach the predictor at all,
//! and both must get through a block header's multimedia bit and then a
//! code length table over 256 symbols per channel before a single sample
//! lands. Whether a corpus does that is a measurement, and a target that
//! never lands a sample is fuzzing the predictor in name alone.
//!
//! Usage, over a corpus directory a campaign left behind:
//!
//!     cargo run --release --example h3_audio_reach \
//!         --features audio-lane-ref,bench-internals -- <dir>...
//!
//! It prints one line per directory: inputs read, inputs that landed at
//! least one multimedia sample, and the total samples. An input that
//! faults is counted as read; a fault is the ordinary outcome here and
//! says nothing about reach.

use std::env;
use std::fs;

use rarkit::internals::rar20;

fn main() {
    let mut any = false;
    for dir in env::args().skip(1) {
        any = true;
        let mut inputs = 0u64;
        let mut reached = 0u64;
        let mut samples = 0u64;
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                println!("{dir}: unreadable, {error}");
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(data) = fs::read(&path) else { continue };
            if data.len() < 3 {
                continue;
            }
            inputs += 1;
            // The two targets' own input shapes, both of which begin at
            // offset 3 or at offset 0; run each input BOTH ways, so one
            // sweep covers `rar20_member` and `rar20_tables` corpora
            // without being told which is which.
            rar20::reset_audio_samples();
            let capacity = rar20::dictionary_size(data[0] & 7);
            let unpacked = u64::from(u16::from_le_bytes([data[1], data[2]]));
            let _ = rar20::decode_member(&data[3..], capacity, unpacked);
            let _ = rar20::decode_member(&data, 65_536, 64);
            let seen = rar20::audio_samples();
            if seen > 0 {
                reached += 1;
            }
            samples += seen;
        }
        println!(
            "{dir}: {inputs} input(s), {reached} reached the predictor, \
             {samples} sample(s)"
        );
    }
    if !any {
        println!("usage: h3_audio_reach <corpus dir>...");
    }
}
