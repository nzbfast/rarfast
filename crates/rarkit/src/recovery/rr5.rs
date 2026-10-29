//! The RAR 5 inline recovery record: geometry, layout and encode
//! (spec L 3.5.1 to 3.5.4).
//!
//! The record is the data area of a RAR 5 service header named `RR`. It
//! protects the file's bytes from byte 0 (so any bytes before the
//! signature too) up to that header's first byte, cut into `k` data shards of `G` bytes; `m` recovery rows of
//! the Cauchy code (3.4) are stored in `m * span` bytes, each row cut into
//! per-group records of at most 64 KiB so that no single record is larger
//! than the format's 32-bit length field comfortably holds.

use crate::checksum::crc64::{crc64_xz_pieces, crc64_xz_then, Crc64Register, ZeroShift};
use crate::recovery::gf16::{cauchy_cell, Coefficient};
use crate::{Error, ErrorKind, RecoveryFailure, Result};

/// Every record starts with this.
pub(crate) const MARKER: [u8; 4] = *b"{RB}";
/// A record's header length with no shard table: `0x48`.
pub(crate) const HEADER_BASE: u32 = 0x48;
/// The most bytes of a shard one record's parity covers.
pub(crate) const GROUP_MAX: u64 = 65_536;
/// The most data shards a record is cut into (3.5.1).
const DATA_SHARDS_MOST: u64 = 200;
/// Protected bytes to a data shard while there are fewer than the most.
const BYTES_PER_SHARD: u64 = 1_024;
/// The percentages a record is written at (3.5.1: the reference stores 1
/// to 1,000 as given).
pub(crate) const PERCENT_RANGE: std::ops::RangeInclusive<u32> = 1..=1_000;
/// Section 4's cap on a declared `k` or `m`.
pub(crate) const MAX_SHARDS: u32 = 4_096;

/// The geometry of one volume's record (spec L 3.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rr5Plan {
    /// Data shards.
    pub(crate) k: u16,
    /// Recovery rows.
    pub(crate) m: u16,
    /// Shard length in bytes, `G`: even, and `k * G >= protected`.
    pub(crate) shard_len: u64,
    /// Records one recovery row is cut into.
    pub(crate) group_count: u64,
    /// One record's header length, `H`.
    pub(crate) header: u32,
    /// Bytes one recovery row occupies, headers included.
    pub(crate) span: u64,
    /// Protected bytes, `P`.
    pub(crate) protected: u64,
}

impl Rr5Plan {
    /// The geometry for `protected` bytes at `percent` recovery (3.5.1):
    /// one shard to each 1,024 bytes up to 200 of them, `percent` rows to
    /// each hundred shards rounded down and never fewer than one, and a
    /// shard length that covers the prefix and is even. The rows are not
    /// held to the number of shards: 1,000 percent of 200 is 2,000.
    pub(crate) fn new(protected: u64, percent: u32) -> Result<Rr5Plan> {
        if protected == 0 || !PERCENT_RANGE.contains(&percent) {
            return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
        }
        let shards = protected
            .div_ceil(BYTES_PER_SHARD)
            .clamp(1, DATA_SHARDS_MOST);
        let rows = (u64::from(percent) * shards / 100).max(1);
        let shard_len = protected.div_ceil(shards).next_multiple_of(2);
        Rr5Plan::assemble(shards as u16, rows as u16, shard_len, protected)
    }

    /// The plan a record declares, checked against 3.5.3 and section 4.
    pub(crate) fn declared(k: u16, m: u16, shard_len: u64, protected: u64) -> Option<Rr5Plan> {
        if k == 0 || m == 0 || u32::from(k) > MAX_SHARDS || u32::from(m) > MAX_SHARDS {
            return None;
        }
        if u32::from(k) + u32::from(m) > 65_535 {
            return None;
        }
        if shard_len < 2 || !shard_len.is_multiple_of(2) || protected == 0 {
            return None;
        }
        // `k` shards of `G` must cover the prefix, and must not overshoot
        // it by a whole shard: that is what makes `G` the ceiling.
        let covered = shard_len.checked_mul(u64::from(k))?;
        if covered < protected || covered > protected + 2 * u64::from(k) {
            return None;
        }
        Rr5Plan::assemble(k, m, shard_len, protected).ok()
    }

    fn assemble(k: u16, m: u16, shard_len: u64, protected: u64) -> Result<Rr5Plan> {
        let too_big = || Error::new(ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged));
        let group_count = shard_len.div_ceil(GROUP_MAX).max(1);
        let header = HEADER_BASE
            .checked_add(8u32.checked_mul(u32::from(k)).ok_or_else(too_big)?)
            .ok_or_else(too_big)?;
        let span = group_count
            .checked_mul(u64::from(header))
            .and_then(|h| h.checked_add(shard_len))
            .ok_or_else(too_big)?;
        Ok(Rr5Plan {
            k,
            m,
            shard_len,
            group_count,
            header,
            span,
            protected,
        })
    }

    /// Bytes of a shard that group `g` covers.
    pub(crate) fn group_len(&self, g: u64) -> u64 {
        let start = g * GROUP_MAX;
        self.shard_len.min(start + GROUP_MAX).saturating_sub(start)
    }

    /// Bytes from the data area's start to record (row 0, group `g`).
    pub(crate) fn group_prefix(&self, g: u64) -> u64 {
        g * u64::from(self.header) + (g * GROUP_MAX).min(self.shard_len)
    }

    /// Bytes from the data area's start to record (`row`, `group`).
    pub(crate) fn position(&self, row: u16, group: u64) -> u64 {
        u64::from(row) * self.span + self.group_prefix(group)
    }

    /// The whole data area's length.
    pub(crate) fn data_len(&self) -> u64 {
        u64::from(self.m) * self.span
    }

    /// Real (below `P`) bytes the last data shard holds.
    pub(crate) fn last_shard_real(&self) -> u64 {
        self.protected - (u64::from(self.k) - 1) * self.shard_len
    }

    /// Real bytes of data shard `j`, which is `G` for every shard but the
    /// last and may be less - never more - for that one.
    pub(crate) fn shard_real(&self, j: u16) -> u64 {
        let start = u64::from(j) * self.shard_len;
        self.protected.saturating_sub(start).min(self.shard_len)
    }

    /// The extent field of a record of group `g` (3.5.2): with `r` the
    /// real bytes of the last data shard and `o` the group's offset, the
    /// lesser of `r - o` and 65,536 while the last shard reaches the
    /// group, and 65,536 for a group that begins past its end. Written
    /// as every genuine record holds it; nothing here reads it back.
    pub(crate) fn extent(&self, g: u64) -> u32 {
        let reach = self.last_shard_real();
        let offset = g * GROUP_MAX;
        if reach < offset {
            return GROUP_MAX as u32;
        }
        (reach - offset).min(GROUP_MAX) as u32
    }
}

/// One record's header, as stored (spec L 3.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) plan: Rr5Plan,
    /// The recovery row this record holds a slice of.
    pub(crate) row: u16,
    /// The group, computed from the record's position, not read.
    pub(crate) group: u64,
    /// Where the record starts in the volume.
    pub(crate) offset: u64,
    /// The record's whole length, header and parity.
    pub(crate) len: u64,
}

/// Fields whose offsets 3.5.2 fixes.
mod at {
    pub(super) const CRC64: usize = 0x04;
    pub(super) const RECORD_LEN: usize = 0x0C;
    pub(super) const HEADER_LEN: usize = 0x10;
    pub(super) const VERSION: usize = 0x14;
    pub(super) const KIND: usize = 0x15;
    pub(super) const GROUP_OFFSET: usize = 0x16;
    pub(super) const EXTENT: usize = 0x1E;
    pub(super) const PROTECTED: usize = 0x22;
    pub(super) const SHARD_LEN: usize = 0x2A;
    pub(super) const SPAN: usize = 0x32;
    pub(super) const K: usize = 0x3A;
    pub(super) const M: usize = 0x3C;
    pub(super) const ROW: usize = 0x3E;
    pub(super) const TABLE: usize = 0x40;
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

/// What a candidate's fixed fields say, before its body has been read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Candidate {
    pub(crate) plan: Rr5Plan,
    pub(crate) row: u16,
    pub(crate) declared_group: u64,
    pub(crate) len: u64,
}

impl Candidate {
    /// Parse and check everything 3.5.3 asks of the fixed fields. The
    /// group is only a HINT here: the reader computes the real one from
    /// the record's position.
    pub(crate) fn parse(head: &[u8]) -> Option<Candidate> {
        if head.len() < HEADER_BASE as usize || head[..4] != MARKER {
            return None;
        }
        if head[at::VERSION] != 1 || head[at::KIND] != 1 {
            return None;
        }
        let k = le16(head, at::K);
        let m = le16(head, at::M);
        let row = le16(head, at::ROW);
        let shard_len = le64(head, at::SHARD_LEN);
        let protected = le64(head, at::PROTECTED);
        let plan = Rr5Plan::declared(k, m, shard_len, protected)?;
        if row >= m
            || le32(head, at::HEADER_LEN) != plan.header
            || le64(head, at::SPAN) != plan.span
        {
            return None;
        }
        let len = u64::from(le32(head, at::RECORD_LEN));
        let parity = len.checked_sub(u64::from(plan.header))?;
        if parity == 0 || parity > GROUP_MAX || parity > plan.shard_len {
            return None;
        }
        let group_offset = le64(head, at::GROUP_OFFSET);
        if !group_offset.is_multiple_of(GROUP_MAX) || group_offset / GROUP_MAX >= plan.group_count {
            return None;
        }
        Some(Candidate {
            plan,
            row,
            declared_group: group_offset / GROUP_MAX,
            len,
        })
    }

    /// The parity this record holds, as a length.
    pub(crate) fn parity_len(&self) -> u64 {
        self.len - u64::from(self.plan.header)
    }
}

/// Finish a candidate once its whole body is in hand: check the record's
/// own CRC-64.
pub(crate) fn finish(
    candidate: &Candidate,
    body: &[u8],
    offset: u64,
    group: u64,
) -> Option<Record> {
    let plan = candidate.plan;
    if body.len() as u64 != candidate.len || candidate.parity_len() != plan.group_len(group) {
        return None;
    }
    if crc64_xz_pieces(&[&body[at::RECORD_LEN..]]) != le64(body, at::CRC64) {
        return None;
    }
    Some(Record {
        plan,
        row: candidate.row,
        group,
        offset,
        len: candidate.len,
    })
}

/// Where a record's shard table starts in the volume.
pub(crate) fn table_at(record: &Record) -> u64 {
    record.offset + at::TABLE as u64
}

/// Read one record's shard table: shard `j`'s CRC-64 (form B) over this
/// group's slice of it, real bytes only.
///
/// A scan may believe many records, and a table is `8k` bytes - up to
/// 32 KiB for a declared `k` - so a [`Record`] does not hold one: that
/// would be an allocation sized by a declared field, once per record. The
/// one table a repair needs is read back here.
pub(crate) fn read_table(
    src: &dyn crate::source::RangeSource,
    record: &Record,
) -> Result<Vec<u64>> {
    let mut bytes = vec![0u8; 8 * usize::from(record.plan.k)];
    crate::recovery::io::read_exact_at(src, table_at(record), &mut bytes)?;
    let (states, _) = bytes.as_chunks::<8>();
    Ok(states.iter().copied().map(u64::from_le_bytes).collect())
}

/// Write one record's header in place. `parity` is not written here.
fn write_header(out: &mut [u8], plan: &Rr5Plan, row: u16, group: u64, set_tag: u64, table: &[u64]) {
    let len = u64::from(plan.header) + plan.group_len(group);
    out[..4].copy_from_slice(&MARKER);
    out[at::RECORD_LEN..at::RECORD_LEN + 4].copy_from_slice(&(len as u32).to_le_bytes());
    out[at::HEADER_LEN..at::HEADER_LEN + 4].copy_from_slice(&plan.header.to_le_bytes());
    out[at::VERSION] = 1;
    out[at::KIND] = 1;
    out[at::GROUP_OFFSET..at::GROUP_OFFSET + 8].copy_from_slice(&(group * GROUP_MAX).to_le_bytes());
    out[at::EXTENT..at::EXTENT + 4].copy_from_slice(&plan.extent(group).to_le_bytes());
    out[at::PROTECTED..at::PROTECTED + 8].copy_from_slice(&plan.protected.to_le_bytes());
    out[at::SHARD_LEN..at::SHARD_LEN + 8].copy_from_slice(&plan.shard_len.to_le_bytes());
    out[at::SPAN..at::SPAN + 8].copy_from_slice(&plan.span.to_le_bytes());
    out[at::K..at::K + 2].copy_from_slice(&plan.k.to_le_bytes());
    out[at::M..at::M + 2].copy_from_slice(&plan.m.to_le_bytes());
    out[at::ROW..at::ROW + 2].copy_from_slice(&row.to_le_bytes());
    let table_end = at::TABLE + 8 * usize::from(plan.k);
    let (slots, _) = out[at::TABLE..table_end].as_chunks_mut::<8>();
    for (slot, state) in slots.iter_mut().zip(table) {
        *slot = state.to_le_bytes();
    }
    out[table_end..table_end + 8].copy_from_slice(&set_tag.to_le_bytes());
}

/// Seal a finished record: its CRC-64/XZ covers everything from the record
/// length field to its end, so it is written last.
fn seal(record: &mut [u8]) {
    let crc = crc64_xz_pieces(&[&record[at::RECORD_LEN..]]);
    record[at::CRC64..at::CRC64 + 8].copy_from_slice(&crc.to_le_bytes());
}

/// A streaming encoder for one volume's record (spec L 3.5.4).
///
/// Bytes are pushed in order and never held: each shard is folded into
/// every recovery row as it completes, and each slice's CRC-64 register
/// runs as the bytes pass. Working memory is `(m + 1) * G`.
pub(crate) struct Rr5Encoder {
    plan: Rr5Plan,
    /// One accumulator per recovery row, each a whole shard long.
    rows: Vec<Vec<u8>>,
    /// The shard being filled.
    shard: Vec<u8>,
    filled: usize,
    /// Data shards completed.
    index: u16,
    /// `table[group][shard]`: the CRC-64 form B of that slice.
    table: Vec<Vec<u64>>,
    pushed: u64,
}

impl Rr5Encoder {
    /// An encoder for `plan`.
    ///
    /// Every plan that reaches here is a `Rr5Plan::new` built from the
    /// length of a slice this process already holds (`rr5::encode`, and
    /// `internals_l::rr5_encode` behind it), never an `Rr5Plan::declared`
    /// parsed out of an archive. `shard_len` is `protected.div_ceil(k)`,
    /// so it is at most that slice's length and the narrowings below are
    /// exact on any pointer width. A declared plan's `shard_len` is an
    /// untrusted `u64` and must not be given to this constructor.
    pub(crate) fn new(plan: Rr5Plan) -> Rr5Encoder {
        debug_assert!(plan.shard_len <= usize::MAX as u64);
        let len = plan.shard_len as usize;
        Rr5Encoder {
            rows: vec![vec![0u8; len]; usize::from(plan.m)],
            shard: vec![0u8; len],
            filled: 0,
            index: 0,
            table: vec![vec![0u64; usize::from(plan.k)]; plan.group_count as usize],
            pushed: 0,
            plan,
        }
    }

    /// Feed the next protected bytes, in order.
    ///
    /// A caller that already holds a whole shard pays no staging copy: the
    /// shard is folded where it lies. Only a partial shard - a short feed,
    /// or the prefix's last few hundred bytes - is buffered, because the
    /// fold needs the shard's tail zeroed out to `G` and a caller's slice
    /// carries no such padding. The two paths fold the same bytes into the
    /// same rows, and `a_chunked_feed_matches_a_whole_one` pins that.
    pub(crate) fn push(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.index >= self.plan.k {
                // More bytes than the plan's prefix: the caller's error,
                // and silently ignoring them would write a record that
                // does not describe the volume.
                debug_assert!(false, "pushed past the protected length");
                return;
            }
            if self.filled == 0 && data.len() >= self.shard.len() {
                let (whole, rest) = data.split_at(self.shard.len());
                self.absorb(whole);
                self.pushed += whole.len() as u64;
                data = rest;
                continue;
            }
            let room = self.shard.len() - self.filled;
            let take = room.min(data.len());
            self.shard[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            self.pushed += take as u64;
            data = &data[take..];
            if self.filled == self.shard.len() {
                self.flush();
            }
        }
    }

    /// Fold the buffered shard into every row and record its slice CRCs.
    fn flush(&mut self) {
        self.shard[self.filled..].fill(0);
        // The buffer is lent to `absorb` and handed straight back: a
        // `Vec::default()` neither allocates nor frees, so this costs
        // nothing and keeps one body for both paths.
        let shard = std::mem::take(&mut self.shard);
        self.absorb(&shard);
        self.shard = shard;
        self.filled = 0;
    }

    /// Fold one whole shard - `G` bytes, padded with zeros if it is the
    /// prefix's last - into every row, and record its slice CRCs.
    fn absorb(&mut self, shard: &[u8]) {
        debug_assert_eq!(shard.len(), self.plan.shard_len as usize);
        let j = self.index;
        let real = self.plan.shard_real(j) as usize;
        for (g, table) in self.table.iter_mut().enumerate() {
            let start = (g as u64 * GROUP_MAX) as usize;
            let end = start + self.plan.group_len(g as u64) as usize;
            let slice = &shard[start..end.min(real).max(start)];
            let mut register = Crc64Register::new();
            register.update(slice);
            table[usize::from(j)] = register.state();
        }
        for (row, accumulator) in self.rows.iter_mut().enumerate() {
            let c = Coefficient::new(cauchy_cell(self.plan.k, row as u16, j));
            c.fold(accumulator, shard);
        }
        self.index += 1;
    }

    /// Emit the record's whole data area: `m * span` bytes.
    pub(crate) fn finish(mut self) -> Result<Vec<u8>> {
        if self.pushed != self.plan.protected {
            return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
        }
        while self.index < self.plan.k {
            self.flush();
        }
        // Question 3: the set tag is content-derived, so a deterministic
        // writer can reproduce it - the raw CRC-64 register over recovery
        // row 0's whole parity.
        let mut tag = Crc64Register::new();
        tag.update(&self.rows[0]);
        let set_tag = tag.state();

        Ok(emit(&self.plan, set_tag, &self.rows, &self.table))
    }
}

/// Lay out the `m * span` data area from the finished accumulators.
///
/// Shared by the streaming encoder's `finish` and by the whole-slice path
/// below, so that the two cannot drift: everything either of them does
/// differently is the FOLD, and this is what proves they are the same
/// record either way.
fn emit(plan: &Rr5Plan, set_tag: u64, rows: &[Vec<u8>], table: &[Vec<u64>]) -> Vec<u8> {
    let mut out = vec![0u8; plan.data_len() as usize];
    for (row, slot) in out.chunks_mut(plan.span as usize).enumerate() {
        emit_row(plan, set_tag, row as u16, &rows[row], table, slot);
    }
    out
}

/// One recovery row's `span` bytes of the data area: its per-group records,
/// header, parity and seal.
///
/// A row's records touch that row's accumulator and nothing else, which is
/// what lets the whole-slice path lay the rows out on a team. It is worth
/// doing: once the fold and the slice CRC-64 pass are wide, the emit is no
/// longer a rounding error beside them - it carries a CRC-64/XZ over every
/// byte it writes (3.5.2), and that register runs at the same rate as the
/// slice pass this record's table came from.
fn emit_row(
    plan: &Rr5Plan,
    set_tag: u64,
    row: u16,
    accumulator: &[u8],
    table: &[Vec<u64>],
    out: &mut [u8],
) {
    for group in 0..plan.group_count {
        let at = plan.group_prefix(group) as usize;
        let len = (u64::from(plan.header) + plan.group_len(group)) as usize;
        let record = &mut out[at..at + len];
        write_header(record, plan, row, group, set_tag, &table[group as usize]);
        let start = (group * GROUP_MAX) as usize;
        record[plan.header as usize..]
            .copy_from_slice(&accumulator[start..start + len - plan.header as usize]);
        seal(record);
    }
}

/// Protected bytes a worker must be given before the whole-slice path
/// takes it, per spec L section 7's requirement that the parallel fold be
/// gated on work PER THREAD and not on a byte count.
///
/// Section 7 names 1 MiB for the RAR 5 folds and that is what this is. It
/// is applied to the PROTECTED length rather than to the fold work `m * P`
/// because both of the stages this path widens are cut the same way: the
/// fold gives a worker `k * chunk` bytes of source, which is `m` times the
/// protected bytes it is charged with here and so is always the easier
/// gate, and the slice CRC-64 pass gives it exactly the protected bytes.
/// Gating on the harder of the two means neither stage can be started on a
/// worker's worth of nothing.
#[cfg(feature = "parallel")]
const ENCODE_TEAM_MIN_PER_WORKER: u64 = 1 << 20;

/// Encode the record for `protected` at `percent`, in one call.
///
/// The team's width is the caller's `max_workers` against the pool's, and
/// [`encode`] leaves it to the pool alone; see the module note on
/// [`encode_wide`] for what the team actually does.
pub(crate) fn encode_with_workers(
    protected: &[u8],
    percent: u32,
    max_workers: usize,
) -> Result<Vec<u8>> {
    let plan = Rr5Plan::new(protected.len() as u64, percent)?;
    #[cfg(feature = "parallel")]
    if let Some(area) = encode_wide(protected, &plan, max_workers) {
        return Ok(area);
    }
    #[cfg(not(feature = "parallel"))]
    let _ = max_workers;
    let mut encoder = Rr5Encoder::new(plan);
    // The whole prefix in one call: `push` then folds each shard where it
    // lies and stages only the last, partial one. Feeding it in 64 KiB
    // pieces instead staged all of it, which is a second pass over every
    // protected byte for no gain to a caller that holds them already.
    encoder.push(protected);
    encoder.finish()
}

/// Encode the record for `protected` at `percent`, the pool's width.
pub(crate) fn encode(protected: &[u8], percent: u32) -> Result<Vec<u8>> {
    encode_with_workers(protected, percent, usize::MAX)
}

/// The whole-slice encode, on a team. `None` means the gate refused and
/// the caller should take the streaming path.
///
/// **Why a second path at all.** [`Rr5Encoder`] is a STREAMING encoder and
/// its shape is forced by that: it sees one shard at a time, so the only
/// thing it can fold in parallel is one shard into `m` rows, which is `m`
/// tasks of `G` bytes and a team woken and parked `k` times. A caller that
/// already holds every protected byte - which is every caller in this
/// crate, the writer included - is under no such constraint, and the
/// decomposition available to it is much better.
///
/// **The decomposition.** Recovery row `i` at symbol `t` is
/// `XOR over j of C(i, j) * D_j[t]` (spec L 3.4), so byte `t` of a row
/// depends on byte `t` of every shard and on nothing else. Cut the shard
/// axis `0..G` into chunks and the pairs (row, chunk) are wholly
/// independent: each writes a disjoint sub-slice of a distinct row and
/// reads the same chunk of every shard. That is `m * chunks` tasks of
/// `k * chunk` bytes each, dispatched ONCE for the whole record instead of
/// once per shard, and it needs not one byte of working memory beyond the
/// accumulators the serial path already holds. The slice CRC-64 table is
/// cut the other way, one task per data shard, because a shard's slices
/// are what a column of the table is.
///
/// **The one staged shard.** `Coefficient::fold` folds
/// `min(dst, src) & !1` bytes, so a source that stops mid-symbol would
/// silently drop its last byte. Every shard but the last is `G` real bytes
/// and cannot; the last is `P - (k-1) * G` (`Rr5Plan::last_shard_real`,
/// which the geometry keeps at or below `G`), so it alone is staged into a
/// zero-padded buffer once, before the team starts. `a_wide_encode_matches_
/// the_streaming_one` pins the two paths together over exactly the sizes
/// where that boundary lands.
#[cfg(feature = "parallel")]
fn encode_wide(protected: &[u8], plan: &Rr5Plan, max_workers: usize) -> Option<Vec<u8>> {
    use rayon::prelude::*;

    // Read without building the pool, as spec L section 7 requires.
    let pool = rayon::current_num_threads();
    // Narrowed to what the gate allows rather than refused outright: the
    // rule is that every worker gets a worker's worth of work, and a team
    // of `P / 1 MiB` satisfies it exactly where a team of the pool's whole
    // width would not. Refusing instead would leave a 15 MiB volume - the
    // `g/create/rar5/m0/vol+rr` leg's shape - serial on a 32-core box for
    // no reason the rule gives.
    let width = max_workers
        .min(pool)
        .min((plan.protected / ENCODE_TEAM_MIN_PER_WORKER) as usize);
    if width <= 1 {
        return None;
    }

    let g = usize::try_from(plan.shard_len).ok()?;
    let k = usize::from(plan.k);
    let m = usize::from(plan.m);
    let groups = usize::try_from(plan.group_count).ok()?;

    // Shard `k - 1` is the only one the geometry lets fall short
    // (`Rr5Plan::last_shard_real`), so it alone is staged. The promise is
    // CHECKED rather than asserted: every plan reaching this function is an
    // `Rr5Plan::new` over a slice this process holds and the arithmetic
    // holds for all of them, but a geometry that broke it would index past
    // the caller's slice, and standing aside for the streaming path is a
    // better answer to that than a panic in a writer.
    let start = k.checked_sub(1)?.checked_mul(g)?;
    let tail_real = protected.len().checked_sub(start)?.min(g);
    let mut tail = vec![0u8; g];
    tail[..tail_real].copy_from_slice(&protected[start..start + tail_real]);
    let shard = |j: usize| -> &[u8] {
        if j + 1 == k {
            &tail
        } else {
            &protected[j * g..(j + 1) * g]
        }
    };

    // Stage one: the slice CRC-64 table, one task per data shard. Built
    // shard-major and transposed afterwards, the table being `k * groups`
    // words - a few thousand - and the transpose therefore free beside the
    // pass it follows.
    let mut columns = vec![vec![0u64; groups]; k];
    columns
        .par_iter_mut()
        .enumerate()
        .with_min_len(1)
        .for_each(|(j, column)| {
            let real = plan.shard_real(j as u16) as usize;
            let bytes = shard(j);
            for (group, slot) in column.iter_mut().enumerate() {
                let start = group * GROUP_MAX as usize;
                let end = start + plan.group_len(group as u64) as usize;
                let mut register = Crc64Register::new();
                register.update(&bytes[start..end.min(real).max(start)]);
                *slot = register.state();
            }
        });
    let mut table = vec![vec![0u64; k]; groups];
    for (j, column) in columns.iter().enumerate() {
        for (group, word) in column.iter().enumerate() {
            table[group][j] = *word;
        }
    }

    // Stage two: the fold. `chunks` pieces of the shard axis per row, so
    // that `m * chunks` covers the team, and each chunk EVEN so that no
    // task begins part way through a 2-byte symbol.
    let chunks = width.div_ceil(m).max(1);
    let chunk_len = g.div_ceil(chunks).next_multiple_of(2).max(2);
    // Section 7's structural rule - the per-coefficient fold tables are
    // built once per pass, never per symbol or per record - has to be read
    // here as once per ENCODE and not once per task WHEN a row is cut into
    // several chunks, because cutting it multiplies the tasks without
    // adding a single coefficient and a task-local table would then pay for
    // `chunks` copies of the same one. When a row is ONE task it is the
    // other way about: the builds are the same `m * k` either way, and a
    // task-local table is alive only while its task runs.
    //
    // Which matters because a table is about 1.2 KiB and `m` is not small
    // at every percentage: `-rr5` on 128 MiB is `m = 10`, 2,000 tables and
    // 2.3 MiB, but `-rr100` is `m = k = 200`, 40,000 tables and 46 MiB of
    // peak RSS that the serial path never paid. Splitting on `chunks` caps
    // the live tables at `width * k` in BOTH branches, because the shared
    // branch is taken only when `m < width`. A recovery record must not
    // cost the wall's weight in memory.
    let shared: Option<Vec<Coefficient>> = (chunks > 1).then(|| {
        (0..m)
            .flat_map(|row| (0..k).map(move |j| (row, j)))
            .map(|(row, j)| Coefficient::new(cauchy_cell(plan.k, row as u16, j as u16)))
            .collect()
    });
    let mut rows = vec![vec![0u8; g]; m];
    rows.par_iter_mut()
        .enumerate()
        .flat_map(|(row, accumulator)| {
            accumulator
                .par_chunks_mut(chunk_len)
                .enumerate()
                .map(move |(chunk, dst)| (row, chunk, dst))
        })
        .for_each(|(row, chunk, dst)| {
            let at = chunk * chunk_len;
            let owned;
            let coefficients: &[Coefficient] = match &shared {
                Some(all) => &all[row * k..(row + 1) * k],
                None => {
                    owned = (0..k)
                        .map(|j| Coefficient::new(cauchy_cell(plan.k, row as u16, j as u16)))
                        .collect::<Vec<_>>();
                    &owned
                }
            };
            for (j, c) in coefficients.iter().enumerate() {
                c.fold(dst, &shard(j)[at..at + dst.len()]);
            }
        });

    let mut tag = Crc64Register::new();
    tag.update(&rows[0]);
    let set_tag = tag.state();

    // Stage three: the emit, one task per recovery row.
    let mut out = vec![0u8; plan.data_len() as usize];
    out.par_chunks_mut(plan.span as usize)
        .enumerate()
        .for_each(|(row, slot)| {
            emit_row(plan, set_tag, row as u16, &rows[row], &table, slot);
        });
    Some(out)
}

/// Where an in-place encode reads the volume and writes its data area.
///
/// Offsets count from the volume's first byte. `read` is asked only for
/// bytes already written, the protected prefix or the data area laid down
/// before the encode starts, and `write` only ever goes back over bytes
/// already written, so an output that can seek and read back what it wrote
/// is all this needs.
pub(crate) trait InPlace {
    /// Fill `buf` with the volume's bytes at `at`.
    fn read(&mut self, at: u64, buf: &mut [u8]) -> Result<()>;
    /// Write `bytes` over the volume's bytes at `at`.
    fn write(&mut self, at: u64, bytes: &[u8]) -> Result<()>;
}

/// Protected coefficients a whole encode may keep built at once before
/// each group builds its own instead: about 1.2 KiB each, so 6,000 is
/// about 7 MiB, which `-rr5` at `k = 200` (`m = 10`, 2,000 of them) sits
/// well inside and `-rr100` (40,000) does not.
const SHARED_COEFFICIENTS_MAX: usize = 6_000;

/// Encode one volume's record WITHOUT HOLDING THE VOLUME (spec L 3.5.4),
/// for an output that can read back what it wrote.
///
/// **Why the bytes cannot simply be folded as they are written.** Data
/// shard `j` is protected bytes `[jG, (j+1)G)` with `G = ceil(P / k)`,
/// plus one if that is odd (3.5.1, `Rr5Plan::new`, which this takes its
/// plan from exactly as the whole-slice path does), and `P` is the
/// protected length, known only once the record's own header is reached. Until then no byte can be assigned to a shard.
/// And every record carries the set tag, the CRC-64 of recovery row 0 as
/// a whole (question 3), under its own seal, so no record is final until
/// the last group is folded.
///
/// So the volume is READ BACK once `P` is known, one group at a time: the
/// `k` slices of group `g` (at most 64 KiB each) are all that row `g`'s
/// parity depends on (3.4: byte `t` of a row depends on byte `t` of every
/// shard and on nothing else), and they give that group's slice CRC-64
/// table too. Each group's `m` records are written where they finally
/// lie, over a data area the caller has already laid down (zeros will
/// do), with the set tag left out, and each record's parity is
/// checksummed as it is folded: its raw CRC-64 register and its CRC32. A
/// second pass then reads each record's HEADER back in the data area's
/// order, puts the tag in, seals it from the header and its parity's raw
/// register (`crc64::ZeroShift`: the parity is not read again), writes the
/// header back, and runs the data area's CRC32 the same way
/// (`Crc32::append`), which is returned for the service header the caller
/// corrects last.
///
/// Working memory is `2k + m` slices of one group (the group being folded,
/// the next one being read, and the parity) and one record, which is at
/// most 39 MiB at `-rr100` and 158 MiB at `-rr1000` (`m = 2,000`), and
/// does not follow the volume's length, and
/// 12 bytes a record for the parity checksums, which does, at 12 bytes in
/// every 64 KiB of the record (under 1 MiB for a 50 GB volume at `-rr10`):
/// that is the whole point. The bytes written are exactly [`encode`]'s,
/// which `the_in_place_encode_is_the_whole_slice_one` pins.
pub(crate) fn encode_in_place(
    io: &mut dyn InPlace,
    plan: &Rr5Plan,
    area_at: u64,
    max_workers: usize,
) -> Result<u32> {
    debug_assert!(plan.shard_len <= usize::MAX as u64);
    let k = usize::from(plan.k);
    let m = usize::from(plan.m);
    let header = plan.header as usize;
    let width = plan.shard_len.min(GROUP_MAX) as usize;
    // Two sets of the group's slices: the team folds one while this
    // thread reads the next group into the other. Reading and folding
    // one after the other left the whole team spinning through every
    // read, measured on an Apple M3 Mac (28 Sep 2026: 4 GiB at -rr1, 7.3 s of
    // system time against 1.3 for the copy's path, the wall doubled).
    let mut slices = vec![0u8; k * width];
    let mut reals = vec![0usize; k];
    let mut ahead = vec![0u8; k * width];
    let mut ahead_reals = vec![0usize; k];
    let mut rows = vec![0u8; m * width];
    let mut table = vec![0u64; k];
    let mut record = vec![0u8; header + width];
    let mut tag = Crc64Register::new();
    // Each record's parity checksummed where it was folded: its raw CRC-64
    // register (form B) and its CRC32, 12 bytes a record against its 64
    // KiB, so the second pass seals the record and runs the data area's
    // CRC32 without reading any parity back.
    let groups = plan.group_count as usize;
    let mut group_sums = vec![(0u64, 0u32); m];
    let mut sums = vec![(0u64, 0u32); m * groups];

    let shared: Option<Vec<Coefficient>> = (m * k <= SHARED_COEFFICIENTS_MAX).then(|| {
        (0..m)
            .flat_map(|row| (0..k).map(move |j| (row, j)))
            .map(|(row, j)| Coefficient::new(cauchy_cell(plan.k, row as u16, j as u16)))
            .collect()
    });
    let team = in_place_team(plan, max_workers);
    let pool = TeamPool::new(team);
    let team = pool.width();

    read_group(io, plan, 0, width, &mut slices, &mut reals)?;
    for group in 0..plan.group_count {
        let len = plan.group_len(group) as usize;
        let mut read = Ok(());
        let fold = || {
            fold_group(
                plan,
                &slices,
                &reals,
                width,
                len,
                &mut rows,
                &mut table,
                &mut group_sums,
                shared.as_deref(),
                team,
            )
        };
        let read_next = || {
            if group + 1 < plan.group_count {
                read = read_group(io, plan, group + 1, width, &mut ahead, &mut ahead_reals);
            }
        };
        pool.beside(fold, read_next);
        read?;
        tag.update(&rows[..len]);
        for (row, sum) in group_sums.iter().enumerate() {
            sums[row * groups + group as usize] = *sum;
        }
        for row in 0..m {
            let slot = &mut record[..header + len];
            write_header(slot, plan, row as u16, group, 0, &table);
            slot[header..].copy_from_slice(&rows[row * width..row * width + len]);
            io.write(area_at + plan.position(row as u16, group), slot)?;
        }
        std::mem::swap(&mut slices, &mut ahead);
        std::mem::swap(&mut reals, &mut ahead_reals);
    }

    let set_tag = tag.state();
    let table_end = at::TABLE + 8 * k;
    let full = ZeroShift::new(width);
    let last_len = plan.group_len(plan.group_count - 1) as usize;
    let last = ZeroShift::new(last_len);
    let mut crc = crate::checksum::Crc32::new();
    for row in 0..plan.m {
        for group in 0..plan.group_count {
            let len = plan.group_len(group) as usize;
            let slot = &mut record[..header];
            let at = area_at + plan.position(row, group);
            io.read(at, slot)?;
            slot[table_end..table_end + 8].copy_from_slice(&set_tag.to_le_bytes());
            let (raw, parity_crc) = sums[usize::from(row) * groups + group as usize];
            let shift = if len == width { &full } else { &last };
            debug_assert!(len == width || len == last_len);
            let seal = crc64_xz_then(&slot[at::RECORD_LEN..], raw, shift);
            slot[at::CRC64..at::CRC64 + 8].copy_from_slice(&seal.to_le_bytes());
            io.write(at, slot)?;
            crc.update(slot);
            crc.append(parity_crc, len as u64);
        }
    }
    Ok(crc.finish())
}

/// Group `group`'s `k` slices into `slices` (each `width` apart), zero
/// padded past their real bytes, whose counts go in `reals`.
fn read_group(
    io: &mut dyn InPlace,
    plan: &Rr5Plan,
    group: u64,
    width: usize,
    slices: &mut [u8],
    reals: &mut [usize],
) -> Result<()> {
    let start = group * GROUP_MAX;
    let len = plan.group_len(group) as usize;
    for (j, (slice, real)) in slices.chunks_mut(width).zip(reals).enumerate() {
        let here = plan
            .shard_real(j as u16)
            .saturating_sub(start)
            .min(len as u64) as usize;
        io.read(j as u64 * plan.shard_len + start, &mut slice[..here])?;
        slice[here..len].fill(0);
        *real = here;
    }
    Ok(())
}

/// The in-place encode's OWN team: a pool of exactly the workers the fold
/// can use, rather than the process's.
///
/// The encode hands the team one group at a time, a few hundred times a
/// gigabyte, and every hand-off to the global pool woke every idle worker
/// there to spin and park again: on an Apple M3 Mac (28 Sep 2026) 4 GiB at -rr1
/// paid 8 s of system time with the team capped at four, against 1.7 when
/// the same binary was run under `-mt4`. A pool of the team's own width has
/// nobody else to wake. Building it costs a few threads once a record; if
/// it cannot be built the encode runs on this thread, which is correct and
/// merely narrower.
struct TeamPool {
    #[cfg(feature = "parallel")]
    pool: Option<rayon::ThreadPool>,
}

impl TeamPool {
    /// A pool of `width` workers, or none when `width` is one.
    fn new(width: usize) -> TeamPool {
        #[cfg(feature = "parallel")]
        {
            let pool = (width > 1)
                .then(|| {
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(width)
                        .build()
                        .ok()
                })
                .flatten();
            TeamPool { pool }
        }
        #[cfg(not(feature = "parallel"))]
        {
            let _ = width;
            TeamPool {}
        }
    }

    /// Workers the fold may cut its work for: one when there is no pool.
    fn width(&self) -> usize {
        #[cfg(feature = "parallel")]
        if let Some(pool) = &self.pool {
            return pool.current_num_threads();
        }
        1
    }

    /// Runs `team_work` on the team while this thread runs `here`, or one
    /// after the other with no team. `here` stays on this thread, which is
    /// what lets it hold the output, which need not be `Send`.
    fn beside(&self, team_work: impl FnOnce() + Send, here: impl FnOnce()) {
        #[cfg(feature = "parallel")]
        if let Some(pool) = &self.pool {
            pool.in_place_scope(|scope| {
                scope.spawn(|_| team_work());
                here();
            });
            return;
        }
        team_work();
        here();
    }
}

/// The working memory [`encode_in_place`] holds for `plan`, for the
/// writer's report: two groups' `k` slices, one group's `m` parity slices,
/// one record, the coefficients when they are shared, and 12 bytes a record
/// for the parity checksums.
pub(crate) fn in_place_bytes(plan: &Rr5Plan) -> u64 {
    let k = u64::from(plan.k);
    let m = u64::from(plan.m);
    let width = plan.shard_len.min(GROUP_MAX);
    let coefficients = if (m * k) as usize <= SHARED_COEFFICIENTS_MAX {
        m * k * std::mem::size_of::<Coefficient>() as u64
    } else {
        0
    };
    (2 * k + m + 1) * width
        + u64::from(plan.header)
        + 24 * k
        + 12 * m * (plan.group_count + 1)
        + coefficients
}

/// What an encode from a whole slice holds for `plan` beyond the slice
/// itself ([`encode_with_workers`], either path, and [`Rr5Encoder`]): the
/// `m` rows and one staged shard, each `G` long, and the data area handed
/// back. It follows the protected length, at about twice `percent` of it:
/// 2 MiB to each MiB protected at 100 percent and 20 MiB at 1,000.
pub(crate) fn whole_slice_bytes(plan: &Rr5Plan) -> u64 {
    (u64::from(plan.m) + 1)
        .saturating_mul(plan.shard_len)
        .saturating_add(plan.data_len())
}

/// How many workers fold one group: the caller's `max_workers` against the
/// pool, gated on protected bytes per worker exactly as [`encode_wide`] is
/// (spec L section 7). One means the fold runs on this thread.
fn in_place_team(plan: &Rr5Plan, max_workers: usize) -> usize {
    #[cfg(feature = "parallel")]
    {
        // At most two workers a recovery row and sixteen for the slice
        // CRC-64 table, which is as much work as the fold when `m` is small:
        // the team folds one group while this thread reads the next, and a
        // team wider than that only waits through the read. Screened on
        // an Apple M3 Mac, 28 Sep 2026, untimed at load 21 to 28, 4 GiB at -rr1,
        // -rr5 and -rr10, two runs each: `m + 2` ran 1.45 to 2.11 s at
        // -rr1 (too narrow for the table), the pool's whole width 1.55 to
        // 1.73, `2m + 8` 1.49 to 1.57, and this 1.39 to 1.51, level with
        // or under the others at -rr5 and -rr10.
        max_workers
            .min(rayon::current_num_threads())
            .min((plan.protected / ENCODE_TEAM_MIN_PER_WORKER) as usize)
            .min(2 * usize::from(plan.m) + 16)
            .max(1)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (plan, max_workers);
        1
    }
}

/// One group's slice CRC-64 table and its `m` parity slices, from the `k`
/// slices already read (each `width` apart, `len` long, zero padded past
/// its real bytes).
#[allow(clippy::too_many_arguments)]
fn fold_group(
    plan: &Rr5Plan,
    slices: &[u8],
    reals: &[usize],
    width: usize,
    len: usize,
    rows: &mut [u8],
    table: &mut [u64],
    sums: &mut [(u64, u32)],
    shared: Option<&[Coefficient]>,
    team: usize,
) {
    let k = usize::from(plan.k);
    let slice = |j: usize| &slices[j * width..j * width + len];
    let crc_of = |j: usize| {
        let mut register = Crc64Register::new();
        register.update(&slice(j)[..reals[j]]);
        register.state()
    };
    // One row's coefficients: shared across the encode when they are few,
    // built for the task otherwise (the rule `encode_wide` states).
    let fold_into = |row: usize, at: usize, dst: &mut [u8]| {
        dst.fill(0);
        let owned;
        let coefficients: &[Coefficient] = match shared {
            Some(all) => &all[row * k..(row + 1) * k],
            None => {
                owned = (0..k)
                    .map(|j| Coefficient::new(cauchy_cell(plan.k, row as u16, j as u16)))
                    .collect::<Vec<_>>();
                &owned
            }
        };
        for (j, c) in coefficients.iter().enumerate() {
            c.fold(dst, &slice(j)[at..at + dst.len()]);
        }
    };

    #[cfg(feature = "parallel")]
    if team > 1 {
        use rayon::prelude::*;
        let m = usize::from(plan.m);
        let chunks = team.div_ceil(m).max(1);
        let chunk_len = len.div_ceil(chunks).next_multiple_of(2).max(2);
        rayon::join(
            || {
                table
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(j, slot)| *slot = crc_of(j));
            },
            || {
                rows.par_chunks_mut(width)
                    .enumerate()
                    .flat_map(|(row, dst)| {
                        dst[..len]
                            .par_chunks_mut(chunk_len)
                            .enumerate()
                            .map(move |(chunk, dst)| (row, chunk, dst))
                    })
                    .for_each(|(row, chunk, dst)| fold_into(row, chunk * chunk_len, dst));
            },
        );
        rows.par_chunks(width)
            .zip(sums.par_iter_mut())
            .for_each(|(row, sum)| *sum = parity_sums(&row[..len]));
        return;
    }
    #[cfg(not(feature = "parallel"))]
    let _ = team;
    for (j, slot) in table.iter_mut().enumerate() {
        *slot = crc_of(j);
    }
    for (row, dst) in rows.chunks_mut(width).enumerate() {
        fold_into(row, 0, &mut dst[..len]);
    }
    for (row, sum) in rows.chunks(width).zip(sums) {
        *sum = parity_sums(&row[..len]);
    }
}

/// One record's parity, checksummed for the second pass: its raw CRC-64
/// register from zero (form B) and its CRC32.
fn parity_sums(parity: &[u8]) -> (u64, u32) {
    let mut raw = Crc64Register::new();
    raw.update(parity);
    (raw.state(), crate::checksum::crc32(parity))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A volume in memory: the protected bytes, then the data area laid
    /// down as zeros, which is what the writer hands the in-place encode.
    struct Laid(Vec<u8>);

    impl InPlace for Laid {
        fn read(&mut self, at: u64, buf: &mut [u8]) -> Result<()> {
            let at = at as usize;
            buf.copy_from_slice(&self.0[at..at + buf.len()]);
            Ok(())
        }
        fn write(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
            let at = at as usize;
            self.0[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
    }

    /// The in-place encode writes exactly the bytes the whole-slice one
    /// returns, and its CRC32 is that area's, over sizes that cross every
    /// boundary the geometry has: `k` still growing, one group, several
    /// groups with a short last one, the last shard short by an odd byte,
    /// and every width from serial to the pool's.
    #[test]
    fn the_in_place_encode_is_the_whole_slice_one() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for protected in [
            97usize, 40_218, 204_799, 204_800, 1_000_001, 13_107_201, 16_000_162,
        ] {
            let data: Vec<u8> = (0..protected)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            for percent in [1, 5, 37, 100, 250, 1_000] {
                // The large sizes at the percentages that say something
                // of them; more rows than shards on the rest.
                if (protected > 2_000_000 && percent == 37)
                    || (protected > 300_000 && percent > 100)
                {
                    continue;
                }
                let want = encode(&data, percent).unwrap();
                let plan = Rr5Plan::new(protected as u64, percent).unwrap();
                for workers in [1, 3, usize::MAX] {
                    let mut laid = data.clone();
                    laid.resize(protected + 5 + want.len(), 0);
                    let mut volume = Laid(laid);
                    let area_at = protected as u64 + 5;
                    let crc = encode_in_place(&mut volume, &plan, area_at, workers).unwrap();
                    assert!(
                        volume.0[protected + 5..] == want[..],
                        "P {protected}, {percent}%, {workers} workers"
                    );
                    assert_eq!(volume.0[..protected], data[..]);
                    assert_eq!(crc, crate::checksum::crc32(&want));
                }
            }
        }
    }

    #[test]
    fn geometry_matches_the_reference_archives() {
        // Spec L 3.5.1 and 5.4.
        let p = Rr5Plan::new(40_218, 5).unwrap();
        assert_eq!((p.k, p.m, p.shard_len, p.group_count), (40, 2, 1_006, 1));
        assert_eq!((p.header, p.span), (392, 1_398));
        assert_eq!(p.extent(0), 984);

        let p = Rr5Plan::new(97, 100).unwrap();
        assert_eq!((p.k, p.m, p.shard_len, p.header), (1, 1, 98, 80));
        assert_eq!(p.extent(0), 97);

        let p = Rr5Plan::new(16_000_162, 3).unwrap();
        assert_eq!((p.k, p.m, p.shard_len, p.group_count), (200, 6, 80_002, 2));
        assert_eq!((p.header, p.span), (1_672, 83_346));
        assert_eq!((p.group_len(0), p.group_len(1)), (65_536, 14_466));
        // The two-group case of 5.4's last row.
        assert_eq!(
            u64::from(p.header) + p.group_len(1),
            16_138,
            "record (row 0, group 1) length"
        );
        assert_eq!(p.extent(1), 14_228);
    }

    /// `push` folds a whole shard where it lies and stages only a partial
    /// one, so a caller's chunking must not reach the bytes written. Two
    /// of these sizes straddle a shard boundary and one is a single byte
    /// at a time, which stages every shard; the lengths are chosen so that
    /// the last shard is short and therefore zero-padded on both paths.
    /// The two paths are the same record, over the sizes where the last
    /// shard's boundary and the team's chunking actually differ.
    ///
    /// The widths are forced rather than taken from the box, so this says
    /// the same thing on a laptop and on a 32-core fleet box; the sizes
    /// straddle the `k = 200` ceiling, the second group's 64 KiB boundary
    /// and an odd protected length, which is the case `Coefficient::fold`
    /// would drop a byte on were the last shard not staged.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_wide_encode_matches_the_streaming_one() {
        for &len in &[
            3_usize << 20,
            (3 << 20) + 1,
            (3 << 20) + 1023,
            8 << 20,
            (13 << 20) + 7,
            200 * 1024 + 3,
        ] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes()[3])
                .collect();
            for percent in [1, 5, 37, 100] {
                let plan = Rr5Plan::new(len as u64, percent).unwrap();
                let mut serial = Rr5Encoder::new(plan);
                serial.push(&data);
                let serial = serial.finish().unwrap();
                for workers in [2usize, 3, 7, 32] {
                    let Some(wide) = encode_wide(&data, &plan, workers) else {
                        continue;
                    };
                    assert_eq!(
                        wide, serial,
                        "len {len}, {percent}%, {workers} workers: the team wrote a \
                         different record from the streaming encoder"
                    );
                }
            }
        }
    }

    /// The gate of spec L section 7, as behaviour: a worker is never given
    /// less than a worker's worth, and the team is NARROWED to make that
    /// true rather than the path being refused outright.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_team_is_gated_on_work_per_worker() {
        let small = vec![0u8; 900 << 10];
        let plan = Rr5Plan::new(small.len() as u64, 5).unwrap();
        assert!(
            encode_wide(&small, &plan, 32).is_none(),
            "under one worker's 1 MiB the whole-slice path must stand aside"
        );

        // 15 MiB is the `g/create/rar5/m0/vol+rr` leg's volume: a 32-core
        // box may not put 32 workers on it, but 15 is exactly the rule.
        let volume = vec![7u8; 15 << 20];
        let plan = Rr5Plan::new(volume.len() as u64, 5).unwrap();
        assert!(
            encode_wide(&volume, &plan, 32).is_some(),
            "a 15 MiB volume has room for a narrowed team"
        );
    }

    #[test]
    fn a_chunked_feed_matches_a_whole_one() {
        for &(len, percent) in &[(5_000u32, 10u32), (3_001, 20), (300_000, 5), (97, 100)] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let whole = encode(&data, percent).expect("the whole prefix encodes");
            let plan = Rr5Plan::new(data.len() as u64, percent).unwrap();
            let g = plan.shard_len as usize;
            for chunk in [1, 64, g - 1, g, g + 1, 64 << 10] {
                let mut encoder = Rr5Encoder::new(plan);
                for piece in data.chunks(chunk) {
                    encoder.push(piece);
                }
                let streamed = encoder.finish().expect("the chunked feed encodes");
                assert_eq!(streamed, whole, "len {len} at {percent}%, chunk {chunk}");
            }
        }
    }

    #[test]
    fn positions_tile_the_data_area() {
        let plan = Rr5Plan::new(16_000_162, 3).unwrap();
        let mut at = 0u64;
        for row in 0..plan.m {
            for group in 0..plan.group_count {
                assert_eq!(plan.position(row, group), at, "row {row} group {group}");
                at += u64::from(plan.header) + plan.group_len(group);
            }
        }
        assert_eq!(at, plan.data_len());
    }

    #[test]
    fn round_trips_through_the_parser() {
        let data: Vec<u8> = (0..5_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let area = encode(&data, 10).unwrap();
        let plan = Rr5Plan::new(data.len() as u64, 10).unwrap();
        assert_eq!(area.len() as u64, plan.data_len());
        for row in 0..plan.m {
            for group in 0..plan.group_count {
                let at = plan.position(row, group) as usize;
                let candidate = Candidate::parse(&area[at..]).expect("a record parses");
                assert_eq!(candidate.plan, plan);
                assert_eq!(candidate.row, row);
                assert_eq!(candidate.declared_group, group);
                let body = &area[at..at + candidate.len as usize];
                let record = finish(&candidate, body, at as u64, group).expect("crc holds");
                assert_eq!(record.row, row);
                assert_eq!(record.len, candidate.len);
            }
        }
    }

    #[test]
    fn parity_is_the_cauchy_row() {
        let data: Vec<u8> = (0..3_000u32).map(|i| (i * 13 + 1) as u8).collect();
        let plan = Rr5Plan::new(data.len() as u64, 20).unwrap();
        let area = encode(&data, 20).unwrap();
        let gf = crate::recovery::gf16::field();
        for row in 0..plan.m {
            let at = plan.position(row, 0) as usize;
            let parity = &area
                [at + plan.header as usize..at + plan.header as usize + plan.group_len(0) as usize];
            for t in 0..(plan.shard_len / 2) as usize {
                let mut want = 0u16;
                for j in 0..plan.k {
                    let start = u64::from(j) * plan.shard_len + 2 * t as u64;
                    let byte = |at: u64| data.get(at as usize).copied().unwrap_or(0);
                    let symbol = u16::from_le_bytes([byte(start), byte(start + 1)]);
                    want ^= gf.mul(cauchy_cell(plan.k, row, j), symbol);
                }
                assert_eq!(
                    u16::from_le_bytes([parity[2 * t], parity[2 * t + 1]]),
                    want,
                    "row {row} symbol {t}"
                );
            }
        }
    }

    #[test]
    fn slice_tables_are_the_zero_seeded_registers() {
        let data: Vec<u8> = (0..4_000u32).map(|i| (i * 5 + 9) as u8).collect();
        let plan = Rr5Plan::new(data.len() as u64, 10).unwrap();
        let area = encode(&data, 10).unwrap();
        let at = plan.position(0, 0) as usize;
        let candidate = Candidate::parse(&area[at..]).unwrap();
        let record = finish(
            &candidate,
            &area[at..at + candidate.len as usize],
            at as u64,
            0,
        )
        .unwrap();
        let table = read_table(&area, &record).unwrap();
        for j in 0..plan.k {
            let start = (u64::from(j) * plan.shard_len) as usize;
            let real = plan.shard_real(j) as usize;
            let mut register = Crc64Register::new();
            register.update(&data[start..start + real]);
            assert_eq!(table[usize::from(j)], register.state(), "shard {j}");
        }
    }

    fn vector(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../specs/vectors-L/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("spec L vector")
    }

    /// Replace every record's set tag and re-seal, so an area this crate
    /// wrote can be compared byte for byte with one reference `rar` wrote:
    /// the tag is the only clock-derived field (question 3).
    fn retag(area: &mut [u8], plan: &Rr5Plan, tag: u64) {
        for row in 0..plan.m {
            for group in 0..plan.group_count {
                let at = plan.position(row, group) as usize;
                let len = (u64::from(plan.header) + plan.group_len(group)) as usize;
                let record = &mut area[at..at + len];
                let table_end = at::TABLE + 8 * usize::from(plan.k);
                record[table_end..table_end + 8].copy_from_slice(&tag.to_le_bytes());
                seal(record);
            }
        }
    }

    /// Every byte of the reference archives' records, from this file's
    /// rules alone, against reference `rar` 7.23 output (spec L 5.4).
    #[cfg(feature = "repo-tests")]
    #[test]
    fn reference_archives_are_reproduced_byte_for_byte() {
        for (name, protected, percent, area_at, tag) in [
            (
                "rr5_small.rar",
                40_218usize,
                5u32,
                40_241usize,
                0x4d21_87dc_0e6f_a9c6u64,
            ),
            ("rr100_small.rar", 97, 100, 120, 0x4d21_87dc_0e6f_aa86),
        ] {
            let file = vector(name);
            let plan = Rr5Plan::new(protected as u64, percent).unwrap();
            let mut ours = encode(&file[..protected], percent).unwrap();
            assert_eq!(ours.len() as u64, plan.data_len(), "{name} area length");
            let table_end = at::TABLE + 8 * usize::from(plan.k);
            assert_eq!(
                le64(&file[area_at..], table_end),
                tag,
                "{name}: the set tag spec L 5.4 pins"
            );
            retag(&mut ours, &plan, tag);
            assert_eq!(
                ours,
                file[area_at..area_at + ours.len()],
                "{name}: record bytes"
            );
        }
    }

    /// The tag this crate writes instead (question 3): content-derived, so
    /// the same bytes give the same record twice over.
    #[test]
    fn the_set_tag_is_deterministic_and_shared() {
        let data: Vec<u8> = (0..9_000u32).map(|i| (i * 11 + 2) as u8).collect();
        let first = encode(&data, 30).unwrap();
        assert_eq!(first, encode(&data, 30).unwrap(), "deterministic");
        let plan = Rr5Plan::new(data.len() as u64, 30).unwrap();
        let table_end = at::TABLE + 8 * usize::from(plan.k);
        let tag = le64(&first[plan.position(0, 0) as usize..], table_end);
        for row in 0..plan.m {
            for group in 0..plan.group_count {
                let at = plan.position(row, group) as usize;
                assert_eq!(
                    le64(&first[at..], table_end),
                    tag,
                    "row {row} group {group}"
                );
            }
        }
        let mut other = data.clone();
        other[0] ^= 1;
        assert_ne!(
            le64(&encode(&other, 30).unwrap(), table_end),
            tag,
            "content-derived"
        );
    }

    #[test]
    fn refuses_a_geometry_past_the_caps() {
        assert!(Rr5Plan::declared(0, 1, 2, 2).is_none());
        assert!(Rr5Plan::declared(1, 0, 2, 2).is_none());
        assert!(Rr5Plan::declared(5_000, 1, 2, 2).is_none());
        assert!(Rr5Plan::declared(1, 1, 3, 2).is_none(), "odd G");
        assert!(Rr5Plan::declared(1, 1, 2, 5).is_none(), "k G < P");
        assert!(
            Rr5Plan::declared(1, 1, 1 << 40, 2).is_none(),
            "k G far past P"
        );
        assert!(Rr5Plan::new(0, 5).is_err());
        assert!(Rr5Plan::new(100, 0).is_err());
        assert!(Rr5Plan::new(100, 1_000).is_ok());
        assert!(Rr5Plan::new(100, 1_001).is_err());
    }
}
