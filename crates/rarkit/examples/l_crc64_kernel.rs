//! The recovery record's slice CRC-64 kernel, a core at a time: the slice-by-8
//! table against the carry-less fold `Crc64Register::update` now picks,
//! over a 256 MiB buffer hashed as 64 KiB slices (the record's group
//! length, the shape create and repair call it in) and as one 64 MiB run.
//! Prints GB/s and CPU seconds per arm; both arms answer the same
//! registers or it stops.
//!
//!     cargo run --release --example l_crc64_kernel [rounds]

use rarkit::internals::recovery as l;
use std::time::Instant;

/// This process's CPU seconds (`RUSAGE_SELF`).
#[cfg(unix)]
fn cpu() -> f64 {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given; RUSAGE_SELF is valid.
    #[allow(unsafe_code)]
    let ru = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr());
        ru.assume_init()
    };
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    t(ru.ru_utime) + t(ru.ru_stime)
}

#[cfg(not(unix))]
fn cpu() -> f64 {
    f64::NAN
}

fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(5);
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..256usize << 20)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    type Arm = fn(&[u8]) -> u64;
    let arms: [(&str, Arm); 2] = [
        ("table", l::crc64_register_table),
        ("fold", l::crc64_register),
    ];
    for (shape, piece) in [("64KiB-slices", 64usize << 10), ("64MiB-run", 64 << 20)] {
        let mut answers = Vec::new();
        for (name, arm) in arms {
            let mut best = f64::MAX;
            let cpu0 = cpu();
            let mut sink = 0u64;
            for _ in 0..rounds {
                let t = Instant::now();
                sink = 0;
                for chunk in data.chunks(piece) {
                    sink ^= std::hint::black_box(arm(chunk));
                }
                best = best.min(t.elapsed().as_secs_f64());
            }
            let cpu_s = cpu() - cpu0;
            answers.push(sink);
            println!(
                "{shape:>13} {name:>5}: best {:.4} s, {:.2} GB/s, CPU {:.2} s over {rounds} rounds, xor {sink:016x}",
                best,
                data.len() as f64 / best / 1e9,
                cpu_s
            );
        }
        assert_eq!(answers[0], answers[1], "the arms disagree");
    }
}
