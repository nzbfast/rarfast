//! SPEC-L section 6: arbitrary bytes as a RAR 4 family inline recovery
//! record, with and without a real one embedded. No panic, no unbounded
//! block walk, and a repair that runs writes a volume the same length as
//! the one it read.
#![no_main]
use libfuzzer_sys::fuzz_target;

use rarkit::internals::recovery as l;
use rarkit::memory::MemoryPolicy;

const MAX: usize = 1 << 16;

fn policy() -> MemoryPolicy {
    MemoryPolicy {
        working_limit: 64 << 20,
        max_window: 64 << 20,
        max_dictionary: 1 << 20,
        repair_limit: 64 << 20,
        read_ahead: 1 << 20,
        max_workers: 1,
        ..MemoryPolicy::default()
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let rest = &rest[..rest.len().min(MAX)];
    let mut volume = if mode & 1 != 0 && !rest.is_empty() {
        let cut = 1 + (mode as usize >> 1) % rest.len();
        let (protected, damage) = rest.split_at(cut);
        let percent = 1 + (mode as u32 >> 1) % 100;
        let Ok((area, sectors, parity)) = l::legacy_rr_build(protected, percent) else {
            return;
        };
        let mut head = [0u8; 26];
        head[2] = 0x78;
        head[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
        head[5..7].copy_from_slice(&26u16.to_le_bytes());
        head[7..11].copy_from_slice(&(area.len() as u32).to_le_bytes());
        head[11] = 20;
        head[12..14].copy_from_slice(&(parity as u16).to_le_bytes());
        head[14..18].copy_from_slice(&(sectors as u32).to_le_bytes());
        head[18..26].copy_from_slice(b"Protect!");
        let crc = rarkit::checksum::crc32(&head[2..]) as u16;
        head[..2].copy_from_slice(&crc.to_le_bytes());
        let mut volume = protected.to_vec();
        volume.extend_from_slice(&head);
        volume.extend_from_slice(&area);
        for pair in damage.chunks_exact(3) {
            let at = (u16::from_le_bytes([pair[0], pair[1]]) as usize) % volume.len();
            volume[at] ^= pair[2];
        }
        volume
    } else {
        rest.to_vec()
    };
    volume.shrink_to_fit();

    if let Ok((header_at, data_at, sectors, parity)) = l::legacy_rr_scan(&volume) {
        assert!(data_at >= header_at);
        assert!(parity >= 1 && sectors >= 1);
        assert!(data_at + 2 * sectors + 512 * parity <= volume.len() as u64);
        let mut out = Vec::new();
        if l::legacy_rr_repair(&volume, &policy(), &mut out).is_ok() {
            assert_eq!(out.len(), volume.len(), "the volume's length is kept");
        }
    }
});
