//! Just enough of the RAR 5 container to reach a member's packed bytes, for
//! this package's own tests.
//!
//! The container layer is spec F's and is not built yet; SPEC-H2 section
//! 5.2 asks that every archive of `specs/vectors-H/archives/` be a test, so
//! this walks the headers the archives need and nothing else: no
//! encryption, no volumes, no recovery record, no extra area but the ones
//! it steps over. It is TEST scaffolding and is not the read path.

#[cfg(test)]
use std::path::PathBuf;

/// One file member of one archive.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub packed: Vec<u8>,
    pub unpacked: u64,
    pub solid: bool,
    pub directory: bool,
    /// The compression method, 0 being stored.
    pub method: u8,
    /// The algorithm version the header declares (section 3.3).
    pub algorithm: u8,
    /// The declared dictionary size: `131,072 << n` (section 3.7).
    pub window: u64,
}

fn vint(data: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = data[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return value;
        }
    }
}

/// One file member, with its packed bytes BORROWED from the archive and no
/// name.
///
/// **Why this exists beside [`Member`], and it is a MEASUREMENT question.**
/// `Member` owns its packed bytes and its name, so [`members`] copies every
/// member's packed data into a fresh `Vec` and allocates a `String` for
/// every name. That is two allocations and a copy per member, and on the
/// `rar5_small_solid_20k` corpus it is 40,000 allocations and a copy of
/// 16 MB, INSIDE the region the bench leg times, where the arm it is
/// compared against carries no such term. Measured 22 Sep 2026 on
/// an Apple M3 Mac: the walk alone is 2.319 ms of that arm's 100.871 ms, 2.3
/// percent, and the arm allocates 2.00 calls a member against the shipped
/// read path's 1.00.
///
/// So the counting seam walks with THIS instead, which allocates nothing
/// per member and copies nothing. Nothing here is the read path either
/// way: spec F's walk is `read::walk` and `read::block::FileHdr`, and this
/// module is test scaffolding for the reason its own header gives.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MemberRef<'a> {
    pub(crate) packed: &'a [u8],
    pub(crate) unpacked: u64,
    pub(crate) solid: bool,
    pub(crate) directory: bool,
    pub(crate) method: u8,
    pub(crate) algorithm: u8,
    pub(crate) window: u64,
}

/// The file members of a RAR 5 archive, in order, owning their packed bytes
/// and their names.
///
/// [`member_refs`] is the same walk without either allocation, for a caller
/// that needs neither.
pub(crate) fn members(data: &[u8]) -> Vec<Member> {
    member_refs_with(data, |r, name| Member {
        name: String::from_utf8_lossy(name).into_owned(),
        packed: r.packed.to_vec(),
        unpacked: r.unpacked,
        solid: r.solid,
        directory: r.directory,
        method: r.method,
        algorithm: r.algorithm,
        window: r.window,
    })
}

/// The file members of a RAR 5 archive, in order, BORROWING their packed
/// bytes and dropping their names: no allocation per member.
pub(crate) fn member_refs(data: &[u8]) -> Vec<MemberRef<'_>> {
    member_refs_with(data, |r, _| r)
}

/// The one walk both forms above are built from, so there is never a second
/// header parser here to keep in step with the first.
fn member_refs_with<'a, T>(
    data: &'a [u8],
    mut make: impl FnMut(MemberRef<'a>, &'a [u8]) -> T,
) -> Vec<T> {
    assert_eq!(&data[..8], b"Rar!\x1a\x07\x01\x00", "not a RAR 5 archive");
    let mut at = 8usize;
    let mut out = Vec::new();
    while at + 4 < data.len() {
        let mut cursor = at + 4;
        let header_size = vint(data, &mut cursor) as usize;
        let body_end = cursor + header_size;
        let kind = vint(data, &mut cursor);
        let flags = vint(data, &mut cursor);
        if flags & 1 != 0 {
            vint(data, &mut cursor);
        }
        let data_size = if flags & 2 != 0 {
            vint(data, &mut cursor) as usize
        } else {
            0
        };
        if kind == 5 {
            break;
        }
        if kind == 2 {
            let file_flags = vint(data, &mut cursor);
            let unpacked = vint(data, &mut cursor);
            vint(data, &mut cursor);
            if file_flags & 2 != 0 {
                cursor += 4;
            }
            if file_flags & 4 != 0 {
                cursor += 4;
            }
            let compression = vint(data, &mut cursor);
            vint(data, &mut cursor);
            let name_len = vint(data, &mut cursor) as usize;
            let name = &data[cursor..cursor + name_len];
            out.push(make(
                MemberRef {
                    packed: &data[body_end..body_end + data_size],
                    unpacked,
                    solid: compression & 0x40 != 0,
                    directory: file_flags & 1 != 0,
                    method: ((compression >> 7) & 7) as u8,
                    algorithm: (compression & 0x3f) as u8,
                    window: 131_072u64 << ((compression >> 10) & 0xf),
                },
                name,
            ));
        }
        at = body_end + data_size;
    }
    out
}

/// One of `specs/vectors-H/archives/`.
#[cfg(test)]
pub(crate) fn archive(stem: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/vectors-H/archives")
        .join(format!("{stem}.rar"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every archive of section 5.2, by stem.
#[cfg(test)]
pub(crate) const ARCHIVES: [&str; 16] = [
    "h5_delta_m5",
    "h5_delta_off",
    "h5_empty",
    "h5_far_m5",
    "h5_far_small_md",
    "h5_lit_m1",
    "h5_md_max",
    "h5_rand_m5",
    "h5_runs_m5",
    "h5_solid",
    "h5_solid_mixed",
    "h5_text_m3",
    "h5_text_m5",
    "h5_tiny",
    "h5_x86_m5",
    "h5_x86_nofilter",
];

/// `specs/vectors-H/CHECK-rar5.tsv`: archive, member, bytes, SHA-256.
#[cfg(test)]
pub(crate) fn check_table() -> Vec<(String, String, u64, String)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-H/CHECK-rar5.tsv"
    );
    std::fs::read_to_string(path)
        .expect("CHECK-rar5.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            let stem = f[0]
                .rsplit('/')
                .next()
                .unwrap()
                .trim_end_matches(".rar")
                .to_owned();
            (
                stem,
                f[1].to_owned(),
                f[2].parse().unwrap(),
                f[3].to_owned(),
            )
        })
        .collect()
}
