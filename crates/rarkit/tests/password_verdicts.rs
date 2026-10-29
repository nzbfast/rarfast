//! What a caller is told about an encrypted member that did not come out
//! right: `MemberInfo::password_checked` (did the member carry a password
//! check record, spec K 3.7.3) and `MemberOutcome::password_refused` (was
//! it closed undecoded because the record said the password was wrong).
//!
//! The two are what let a caller report a wrong password and damage apart,
//! which `checksum_ok` alone cannot: a RAR 5 member whose record passed
//! and whose bytes then fail is DAMAGED, and one whose record fails is
//! refused before a byte. A member with no record (the RAR 1.3 to 4.x
//! family, or a RAR 5 record with flag 0x0001 clear) cannot tell the two
//! apart at all, and says so by `password_checked == false`. Measured
//! against reference `unrar` 7.23 on 29 Sep 2026: the CLI rows
//! are in `crates/rarkit-cli/tests/encrypted_damage.rs`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, ErrorKind, MemberInfo, MemberOutcome, ParallelSink,
    RangeSource, ReadOptions, Sink,
};

fn spec(dir: &str, name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs"))
        .join(dir)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The RAR 5 vectors of spec K (`rar a -ma5 -pSecret`).
fn k(name: &str) -> Vec<u8> {
    spec("vectors-K", name)
}

/// The RAR 4 vectors of spec G (`rar` 4.20, `-pSecret`).
fn g(name: &str) -> Vec<u8> {
    spec("vectors-G/archives", name)
}

/// One byte of `data` changed, `at` a fraction of the way in.
fn flipped(mut data: Vec<u8>, at: f64) -> Vec<u8> {
    let i = (data.len() as f64 * at) as usize;
    data[i] ^= 0x40;
    data
}

/// One closed file member: what `open` saw and what `close` was told.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    name: Vec<u8>,
    encrypted: bool,
    password_checked: bool,
    outcome: MemberOutcome,
}

#[derive(Default)]
struct Collect(Vec<Seen>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(if member.is_directory {
            Disposition::Skip
        } else {
            Disposition::Verify
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.0.push(Seen {
            name: member.name.to_vec(),
            encrypted: member.encrypted,
            password_checked: member.password_checked,
            outcome: *outcome,
        });
        Ok(())
    }
}

#[derive(Default)]
struct CollectParallel(Mutex<Vec<Seen>>);

impl ParallelSink for CollectParallel {
    type Out = std::io::Sink;

    fn open(&self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Self::Out>> {
        Ok(if member.is_directory {
            Disposition::Skip
        } else {
            Disposition::Verify
        })
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        _out: Option<Self::Out>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.0.lock().unwrap().push(Seen {
            name: member.name.to_vec(),
            encrypted: member.encrypted,
            password_checked: member.password_checked,
            outcome: *outcome,
        });
        Ok(())
    }
}

fn sources(volumes: Vec<Vec<u8>>) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .into_iter()
        .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
        .collect()
}

/// Every member closed, through BOTH drivers, which must agree; and the
/// operation's own verdict.
fn closes(volumes: Vec<Vec<u8>>, password: &str) -> (Vec<Seen>, Option<String>) {
    let opts = ReadOptions::default().with_password(Some(rarkit::Password::from(password)));
    let mut sink = Collect::default();
    let sequential = extract(sources(volumes.clone()), &opts, &mut sink, &mut ());
    let parallel = CollectParallel::default();
    let pooled = extract_parallel(sources(volumes), &opts, &parallel, 4);
    let mut pooled_seen = parallel.0.into_inner().unwrap();
    pooled_seen.sort_by(|a, b| a.name.cmp(&b.name));
    let mut seen = sink.0;
    seen.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        seen, pooled_seen,
        "the two drivers told the sink different things"
    );
    // `ErrorKind` has no `PartialEq`: its `Debug` text is compared.
    let kind = |r: &rarkit::Result<rarkit::ExtractReport>| {
        r.as_ref().err().map(|e| format!("{:?}", e.kind()))
    };
    assert_eq!(
        kind(&sequential),
        kind(&pooled),
        "the two drivers ended differently"
    );
    (seen, kind(&sequential))
}

fn wrong_password() -> String {
    format!("{:?}", ErrorKind::WrongPassword)
}

/// The one file member of a one-member archive.
fn only(seen: &[Seen]) -> &Seen {
    assert_eq!(seen.len(), 1, "{seen:?}");
    &seen[0]
}

#[test]
fn a_rar5_member_with_a_record_reads_password_checked() {
    let (seen, err) = closes(vec![k("r5_p_m3.rar")], "Secret");
    assert_eq!(err, None);
    let member = only(&seen);
    assert!(member.encrypted && member.password_checked);
    assert_eq!(member.outcome.checksum_ok, Some(true));
    assert!(!member.outcome.password_refused);
}

#[test]
fn a_rar4_member_and_an_unencrypted_one_are_not_password_checked() {
    let (seen, _) = closes(vec![g("r4_pw.rar")], "Secret");
    let member = only(&seen);
    assert!(member.encrypted && !member.password_checked);
    let (seen, _) = closes(vec![spec("vectors-F/archives", "f01_stored.rar")], "Secret");
    assert!(seen.iter().all(|m| !m.encrypted && !m.password_checked));
}

/// The record fails: the member is closed undecoded and refused for its
/// password, and the operation ends `WrongPassword`.
#[test]
fn a_wrong_password_closes_the_member_refused() {
    for volumes in [
        vec![k("r5_p_m3.rar")],
        vec![
            k("r5_p_vol.part1.rar"),
            k("r5_p_vol.part2.rar"),
            k("r5_p_vol.part3.rar"),
        ],
    ] {
        let (seen, err) = closes(volumes, "Wrong");
        assert_eq!(err, Some(wrong_password()));
        let member = only(&seen);
        assert!(member.password_checked);
        // Read field by field: `MemberOutcome` is non_exhaustive (API
        // 4.4), so a caller never builds one to compare against.
        assert_eq!(member.outcome.checksum_ok, Some(false));
        assert_eq!(member.outcome.bytes, 0);
        assert!(member.outcome.password_refused);
        assert_eq!(member.outcome.fragment_mismatches, 0);
    }
}

/// The record passes and a byte of the data is wrong: DAMAGE, a checksum
/// failure that is not a refusal, and the operation carries on.
#[test]
fn damage_after_a_passing_record_is_not_a_refusal() {
    let set = || {
        vec![
            k("r5_p_vol.part1.rar"),
            k("r5_p_vol.part2.rar"),
            k("r5_p_vol.part3.rar"),
        ]
    };
    let first = {
        let mut v = set();
        v[0] = flipped(k("r5_p_vol.part1.rar"), 0.5);
        v
    };
    let mut last = set();
    last[2] = flipped(k("r5_p_vol.part3.rar"), 0.5);
    for volumes in [vec![flipped(k("r5_p_m3.rar"), 0.5)], first, last] {
        let (seen, err) = closes(volumes, "Secret");
        assert_eq!(err, None, "damage ended the operation");
        let member = only(&seen);
        assert!(member.password_checked);
        assert_eq!(member.outcome.checksum_ok, Some(false));
        assert!(!member.outcome.password_refused);
    }
}

/// With no record a wrong password is never REFUSED: it shows as the
/// member's own failure, a checksum or a decoder's verdict, exactly as
/// damage does (spec K 3.6.4; the API's section 4.5).
#[test]
fn without_a_record_a_wrong_password_is_never_refused() {
    let (seen, _) = closes(vec![g("r4_pw.rar")], "Wrong");
    let member = only(&seen);
    assert!(!member.password_checked);
    assert_eq!(member.outcome.checksum_ok, Some(false));
    assert!(!member.outcome.password_refused);

    let stripped = strip_check_records(&k("r5_p_m3.rar"));
    let (seen, err) = closes(vec![stripped.clone()], "Secret");
    assert_eq!(err, None, "the stripped archive no longer reads");
    let member = only(&seen);
    assert!(member.encrypted && !member.password_checked);
    assert_eq!(member.outcome.checksum_ok, Some(true));

    let (seen, err) = closes(vec![stripped], "Wrong");
    assert_ne!(err, Some(wrong_password()));
    let member = only(&seen);
    assert_eq!(member.outcome.checksum_ok, Some(false));
    assert!(!member.outcome.password_refused);
}

// ---------------------------------------------------------------------
// A RAR 5 archive without check records, made from one with them
// ---------------------------------------------------------------------

fn read_vint(b: &[u8], mut i: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = b[i];
        i += 1;
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, i);
        }
    }
}

fn write_vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `value` as a vint of exactly `len` bytes: the writer pads some.
fn write_vint_len(mut value: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for k in 0..len {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        out.push(if k + 1 < len { byte | 0x80 } else { byte });
    }
    assert_eq!(value, 0, "the new size does not fit the old field");
    out
}

/// Every file and service header's encryption record with its check
/// record removed: flag 0x0001 cleared and the 12 bytes dropped, the
/// record's, the extra area's and the header's sizes and the header CRC32
/// re-stamped (spec F 3.2.2, spec K 3.7.1). A legal RAR 5 form the
/// reference writer never makes. The archive must carry no quick-open
/// record, whose copies of the headers would no longer match.
fn strip_check_records(archive: &[u8]) -> Vec<u8> {
    const SIGNATURE: usize = 8;
    let mut out = archive[..SIGNATURE].to_vec();
    let mut i = SIGNATURE;
    let mut stripped = 0;
    while i < archive.len() {
        let (size, body_at) = read_vint(archive, i + 4);
        let mut body = archive[body_at..body_at + size as usize].to_vec();
        let (kind, at) = read_vint(&body, 0);
        let (flags, at) = read_vint(&body, at);
        let (mut extra, mut data) = (0u64, 0u64);
        let mut extra_field = at..at;
        let mut at = at;
        if flags & 1 != 0 {
            let (value, next) = read_vint(&body, at);
            extra_field = at..next;
            extra = value;
            at = next;
        }
        if flags & 2 != 0 {
            data = read_vint(&body, at).0;
        }
        if (kind == 2 || kind == 3) && extra > 0 {
            let start = body.len() - extra as usize;
            let mut records = Vec::new();
            let mut r = start;
            while r < body.len() {
                let (len, rec_at) = read_vint(&body, r);
                let end = rec_at + len as usize;
                let (rec_kind, fields) = read_vint(&body, rec_at);
                if rec_kind == 1 {
                    let (version, a) = read_vint(&body, fields);
                    let (rec_flags, b) = read_vint(&body, a);
                    if rec_flags & 1 != 0 {
                        // Exponent, salt and IV stay; the 12 check bytes go.
                        let kept = &body[b..end - 12];
                        let mut rec = write_vint(1);
                        rec.extend(write_vint(version));
                        rec.extend(write_vint(rec_flags & !1));
                        rec.extend_from_slice(kept);
                        records.extend(write_vint(rec.len() as u64));
                        records.extend(rec);
                        stripped += 1;
                        r = end;
                        continue;
                    }
                }
                records.extend_from_slice(&body[r..end]);
                r = end;
            }
            let mut rebuilt = body[..extra_field.start].to_vec();
            rebuilt.extend(write_vint_len(records.len() as u64, extra_field.len()));
            rebuilt.extend_from_slice(&body[extra_field.end..start]);
            rebuilt.extend(records);
            body = rebuilt;
        }
        let size_field = write_vint(body.len() as u64);
        let mut header = size_field.clone();
        header.extend_from_slice(&body);
        out.extend_from_slice(&rarkit::checksum::crc32(&header).to_le_bytes());
        out.extend(header);
        let end = body_at + size as usize;
        out.extend_from_slice(&archive[end..end + data as usize]);
        i = end + data as usize;
        if kind == 5 {
            out.extend_from_slice(&archive[i..]);
            break;
        }
    }
    assert!(stripped > 0, "no check record to strip");
    out
}

// ---------------------------------------------------------------------
// Spec K 3.7.3 step 1: a check record whose own checksum fails
// ---------------------------------------------------------------------

/// Every check record of `archive` with one byte changed, the byte at
/// `byte` of its twelve, and each header's CRC32 stamped again: below 8
/// the check value changes and its checksum no longer fits; from 8 the
/// record's own checksum changes. Records are found in file and service
/// headers (extra record type 1) and in the archive encryption header.
fn damage_check_records(archive: &[u8], byte: usize) -> Vec<u8> {
    const SIGNATURE: usize = 8;
    let mut out = archive.to_vec();
    let mut i = SIGNATURE;
    let mut damaged = 0;
    while i < archive.len() {
        let (size, body_at) = read_vint(archive, i + 4);
        let end = body_at + size as usize;
        let (kind, at) = read_vint(archive, body_at);
        let (flags, mut at) = read_vint(archive, at);
        let (mut extra, mut data) = (0u64, 0u64);
        if flags & 1 != 0 {
            (extra, at) = read_vint(archive, at);
        }
        if flags & 2 != 0 {
            (data, at) = read_vint(archive, at);
        }
        if kind == 4 {
            // Version, flags, exponent, salt, and the record when flagged.
            let (_, a) = read_vint(archive, at);
            let (crypt_flags, _) = read_vint(archive, a);
            if crypt_flags & 1 != 0 {
                out[end - 12 + byte] ^= 0x40;
                damaged += 1;
            }
        }
        if kind == 2 || kind == 3 {
            let mut r = end - extra as usize;
            while r < end {
                let (len, rec_at) = read_vint(archive, r);
                let rec_end = rec_at + len as usize;
                let (rec_kind, fields) = read_vint(archive, rec_at);
                let (_, a) = read_vint(archive, fields);
                let (rec_flags, _) = read_vint(archive, a);
                if rec_kind == 1 && rec_flags & 1 != 0 {
                    out[rec_end - 12 + byte] ^= 0x40;
                    damaged += 1;
                }
                r = rec_end;
            }
        }
        let crc = rarkit::checksum::crc32(&out[i + 4..end]);
        out[i..i + 4].copy_from_slice(&crc.to_le_bytes());
        if kind == 4 {
            // Everything after the encryption header is ciphertext.
            break;
        }
        i = end + data as usize;
        if kind == 5 {
            break;
        }
    }
    assert!(damaged > 0, "no check record to damage");
    out
}

/// A check record that fails its OWN checksum is damaged and says nothing
/// about the password: it is treated as absent, as the reference does
/// ("All OK" under the right password). The member is decoded and its own
/// checksum and MAC judge it, and `password_checked` is false because the
/// password was never proven.
///
/// Every byte of the record is damaged in turn, in three archives and
/// under two passwords: no case is an error of the open, and none holds
/// more than the archive (the record is twelve bytes read in place, and
/// the member is then decoded exactly as one that carries no record).
///
/// Four threads in the pooled driver; a few hundred KiB.
#[test]
fn a_check_record_failing_its_own_checksum_is_treated_as_absent() {
    let set = || {
        vec![
            k("r5_p_vol.part1.rar"),
            k("r5_p_vol.part2.rar"),
            k("r5_p_vol.part3.rar"),
        ]
    };
    for byte in 0..12 {
        for volumes in [vec![k("r5_p_m3.rar")], vec![k("r5_p_m0_blake.rar")], set()] {
            let volumes: Vec<Vec<u8>> = volumes
                .iter()
                .map(|v| damage_check_records(v, byte))
                .collect();
            let (seen, err) = closes(volumes.clone(), "Secret");
            assert_eq!(err, None, "byte {byte}: the right password was refused");
            assert!(!seen.is_empty());
            for member in &seen {
                assert!(member.encrypted && !member.password_checked, "byte {byte}");
                assert_eq!(member.outcome.checksum_ok, Some(true), "byte {byte}");
                assert!(!member.outcome.password_refused, "byte {byte}");
            }

            // Under a wrong password nothing can say "wrong password":
            // the member fails its checksum, as one with no record does.
            let (seen, err) = closes(volumes, "Wrong");
            assert_ne!(err, Some(wrong_password()), "byte {byte}");
            for member in &seen {
                assert_eq!(member.outcome.checksum_ok, Some(false), "byte {byte}");
                assert!(!member.outcome.password_refused, "byte {byte}");
            }
        }
    }
}

/// The same for the archive encryption header's record: the archive opens
/// under the right password, and under a wrong one the first encrypted
/// header fails as the noise it is rather than the archive being called a
/// wrong password.
///
/// Four threads in the pooled driver; under 1 KiB.
#[test]
fn an_archive_check_record_failing_its_own_checksum_is_treated_as_absent() {
    for byte in [0, 11] {
        let archive = damage_check_records(&k("r5_hp_m0.rar"), byte);
        let (seen, err) = closes(vec![archive.clone()], "Secret");
        assert_eq!(err, None, "byte {byte}: the right password was refused");
        assert_eq!(only(&seen).outcome.checksum_ok, Some(true), "byte {byte}");

        let (seen, err) = closes(vec![archive], "Wrong");
        assert!(seen.is_empty(), "byte {byte}: {seen:?}");
        // The first header deciphered under the wrong key is noise: a
        // failed header check, or a size that runs past the source.
        let noise = [
            format!("{:?}", ErrorKind::HeaderChecksum),
            format!("{:?}", ErrorKind::Truncated),
        ];
        assert!(
            err.as_ref().is_some_and(|e| noise.contains(e)),
            "byte {byte}: {err:?}"
        );
    }
}
