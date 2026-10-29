//! Spec L entry points for this repository's fuzz targets, benches and
//! tests, behind the `bench-internals` feature. Not part of the API; no
//! shipped build enables it.

use std::io::Write;

use crate::memory::MemoryPolicy;
use crate::source::RangeSource;
use crate::Result;

/// BLAKE2sp of `data`, one shot (spec L 3.3).
pub fn blake2sp(data: &[u8]) -> [u8; 32] {
    crate::checksum::blake2sp::blake2sp(data)
}

/// An incremental BLAKE2sp allowed `workers` threads.
pub struct Blake2sp(crate::checksum::blake2sp::Blake2sp);

impl Blake2sp {
    /// A hasher allowed `workers` threads; one is the single-thread
    /// kernel.
    pub fn with_workers(workers: usize) -> Blake2sp {
        Blake2sp(crate::checksum::blake2sp::Blake2sp::with_workers(workers))
    }

    /// Feed `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    /// The digest.
    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

/// CRC-64/XZ (form A) of `data`.
pub fn crc64_xz(data: &[u8]) -> u64 {
    crate::checksum::crc64::crc64_xz(data)
}

/// The raw CRC-64 register (form B) over `data`.
pub fn crc64_register(data: &[u8]) -> u64 {
    let mut register = crate::checksum::crc64::Crc64Register::new();
    register.update(data);
    register.state()
}

/// The raw CRC-64 register (form B) over `data` through the slice-by-8
/// table alone, never the carry-less fold: the arm `crc64_register` is
/// measured against.
pub fn crc64_register_table(data: &[u8]) -> u64 {
    crate::checksum::crc64::register_by_table(data)
}

/// The CRC32 of `pieces` concatenated, on up to `workers` threads.
pub fn crc32_pieces(pieces: &[&[u8]], workers: usize) -> u32 {
    crate::checksum::crc32_pieces(pieces, workers)
}

/// `dst ^= c * src` over GF(2^16) symbols (spec L 3.4). The kernel both
/// encode and repair are built on.
pub fn fold(dst: &mut [u8], src: &[u8], c: u16) {
    crate::recovery::gf16::Coefficient::new(c).fold(dst, src)
}

/// The coefficient of data shard `col` in recovery row `row`.
pub fn cauchy_cell(k: u16, row: u16, col: u16) -> u16 {
    crate::recovery::gf16::cauchy_cell(k, row, col)
}

/// The geometry of a RAR 5 inline record: `(k, m, G, groups, H, span)`.
pub fn rr5_geometry(protected: u64, percent: u32) -> Result<(u16, u16, u64, u64, u32, u64)> {
    let plan = crate::recovery::rr5::Rr5Plan::new(protected, percent)?;
    Ok((
        plan.k,
        plan.m,
        plan.shard_len,
        plan.group_count,
        plan.header,
        plan.span,
    ))
}

/// The whole data area of the RAR 5 inline record for `protected` at
/// `percent` (spec L 3.5.4).
pub fn rr5_encode(protected: &[u8], percent: u32) -> Result<Vec<u8>> {
    crate::recovery::rr5::encode(protected, percent)
}

/// The same data area, with the encode team's width FORCED to
/// `max_workers` (spec L 3.5.4 and section 7's per-worker gate).
///
/// The whole point is that a caller can drive both of the encoder's paths
/// from outside the crate: `1` is the streaming encoder and anything wider
/// is the whole-slice team, on the same bytes, so a differential fuzz
/// target can say they are one record. The gate still applies, so a small
/// input answers on the streaming path whatever width is asked for, which
/// is a refusal to parallelise and not a refusal to encode.
pub fn rr5_encode_workers(protected: &[u8], percent: u32, max_workers: usize) -> Result<Vec<u8>> {
    crate::recovery::rr5::encode_with_workers(protected, percent, max_workers)
}

/// The `RR` service header rarkit's own writer puts in front of a record
/// area of `area_len` bytes written at `percent` (spec G 3.3.4, the
/// default layout, a Unix host): what a volume built by hand from
/// protected bytes and [`rr5_encode`]'s area needs between the two to be
/// laid out as an archive is (spec L 3.5.1, 3.5.5 O1 and O7).
pub fn rr5_service_header(area_len: u64, percent: u32) -> Vec<u8> {
    crate::write::rar5::service_header(
        crate::write::consts::SERVICE_RECOVERY,
        area_len,
        None,
        crate::write::rar5::HOST_OS_UNIX_BYTE,
        true,
        Some(u64::from(percent)),
        crate::write::rar5::Reserve::Natural,
    )
}

/// Scan a volume for RAR 5 records without repairing.
pub fn rr5_scan(volume: &dyn RangeSource, repair_limit: u64) -> Result<Vec<(u16, u64, u64)>> {
    let policy = crate::memory::repair_only(repair_limit);
    let found = crate::recovery::scan::scan(volume, &policy)?;
    Ok(found
        .records
        .iter()
        .map(|record| (record.row, record.group, record.offset))
        .collect())
}

/// The data area of a RAR 4 family record for `protected` at `percent`,
/// with `(n, r)` (spec L 3.7).
pub fn legacy_rr_build(protected: &[u8], percent: u32) -> Result<(Vec<u8>, u64, u64)> {
    let (area, record) = crate::recovery::legacy::build(protected, percent)?;
    Ok((area, record.sectors, record.parity))
}

/// Find a RAR 4 family record: `(header offset, data offset, n, r)`.
pub fn legacy_rr_scan(volume: &dyn RangeSource) -> Result<(u64, u64, u64, u64)> {
    let record = crate::recovery::legacy::scan(volume)?;
    Ok((
        record.header_at,
        record.data_at,
        record.sectors,
        record.parity,
    ))
}

/// Repair a RAR 4 family volume from its own record.
pub fn legacy_rr_repair(
    volume: &dyn RangeSource,
    policy: &MemoryPolicy,
    out: &mut dyn Write,
) -> Result<crate::rev5::RepairReport> {
    let record = crate::recovery::legacy::scan(volume)?;
    crate::recovery::legacy::repair(volume, &record, policy, out)
}

/// The sector length the RAR 4 family records work in.
pub const SECTOR: u64 = crate::recovery::legacy::SECTOR;
