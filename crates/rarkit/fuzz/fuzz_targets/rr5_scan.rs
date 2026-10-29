//! SPEC-L section 6: arbitrary volume bytes as a RAR 5 inline recovery
//! record, with and without a real record embedded. No panic, no unbounded
//! loop, no allocation sized by a declared field before the check that
//! bounds it; a scan that succeeds reports records inside the volume.
#![no_main]
use libfuzzer_sys::fuzz_target;

use rarkit::internals::recovery as l;

/// Enough to reach the two-group geometry is far more than a fuzz run
/// wants; this keeps each case linear and short.
const MAX: usize = 1 << 16;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let rest = &rest[..rest.len().min(MAX)];
    let volume = if mode & 1 != 0 && !rest.is_empty() {
        // A genuine record over a prefix of the input, then damage taken
        // from the rest of it: the interesting corpus is a real layout
        // with holes in it, not only noise.
        let cut = 1 + (mode as usize >> 1) % rest.len();
        let (protected, damage) = rest.split_at(cut);
        let percent = 1 + (mode as u32 >> 1) % 100;
        let Ok(area) = l::rr5_encode(protected, percent) else {
            return;
        };
        let mut volume = protected.to_vec();
        volume.extend_from_slice(&area);
        for pair in damage.chunks_exact(3) {
            let at = (u16::from_le_bytes([pair[0], pair[1]]) as usize) % volume.len();
            volume[at] ^= pair[2];
        }
        volume
    } else {
        rest.to_vec()
    };

    if let Ok(records) = l::rr5_scan(&volume, 64 << 20) {
        for &(_row, _group, offset) in &records {
            assert!(offset < volume.len() as u64, "a record inside the volume");
        }
    }
});
