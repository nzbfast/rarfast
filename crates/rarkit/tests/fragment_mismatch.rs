//! A leading fragment whose CRC32 field disagrees with its packed bytes is
//! a per-volume DIAGNOSTIC, never the member's failure (spec F 3.5.6 and
//! API 4.4, answered 29 Sep 2026).
//!
//! The member is judged by its WHOLE checksum alone. The sink hears of each
//! disagreeing leading fragment through `fragment_mismatch(member, volume)`,
//! once per fragment, before that member's `close`, and the close counts
//! them in `MemberOutcome::fragment_mismatches`. A member the sink skipped
//! has its fragments judged by nobody.
//!
//! Every arrangement a split member is read in is asked the same questions:
//! both entry points, at one worker and at several, verified and written,
//! stored and compressed, solid and not. The sets are written by this
//! crate's own writer and damaged here: "field" is a leading fragment's
//! data CRC32 overwritten with 0xDEADBEEF and its header CRC re-stamped,
//! "data" one byte of that fragment's data area inverted.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rarkit::checksum::crc32;
use rarkit::{
    Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, ParallelSink, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const VOLUME_CAP: u64 = 64 << 10;

/// Bytes no compressor shrinks.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// A volume set of `members`, written with `method` and `solid`.
///
/// **Written with `level3_optimal` since 30 Sep 2026**: level
/// 3's default parse became the lazy parse 64 links deep, and
/// `damaged_bytes_fail_the_member_and_name_their_volume` inverts ONE byte
/// in the middle of a compressed member, where the stream's layout decides
/// what that byte breaks. Under the optimal parse it breaks the member's
/// checksum (the member fails, the extract goes on, which is what these
/// tests pin about fragments); under the lazy parse the same flip breaks
/// the block structure and the whole extract returns
/// `Corrupt(Rar5(IncompleteMember))`. These tests are about fragment
/// verdicts, not the parse, so the set keeps level 3's earlier bytes.
/// Whether a structurally damaged member should abort the whole extract
/// or fail that member and continue is an open question.
fn volume_set(members: &[(&str, Vec<u8>)], method: WriteMethod, solid: bool) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        method,
        solid,
        level3_optimal: true,
        volume_file_size: Some(VOLUME_CAP),
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, payload) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(payload),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish_volumes");
    out
}

// ---- a minimal RAR 5 block walker, for patching the set's headers ----

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// One file header of a volume: its name, where its header CRC and its data
/// CRC field sit, whether the member continues past it, and its data area.
struct FileHead {
    name: Vec<u8>,
    start: usize,
    body: std::ops::Range<usize>,
    data_crc: Option<usize>,
    split_after: bool,
    data: std::ops::Range<usize>,
}

fn file_heads(volume: &[u8]) -> Vec<FileHead> {
    let mut heads = Vec::new();
    let mut at = 8;
    while at + 4 < volume.len() {
        let start = at;
        let mut p = at + 4;
        let size = vint(volume, &mut p) as usize;
        let body = start + 4..p + size;
        let kind = vint(volume, &mut p);
        let flags = vint(volume, &mut p);
        if flags & 1 != 0 {
            vint(volume, &mut p);
        }
        let data_size = if flags & 2 != 0 {
            vint(volume, &mut p) as usize
        } else {
            0
        };
        let data = body.end..body.end + data_size;
        if kind == 2 {
            let file_flags = vint(volume, &mut p);
            vint(volume, &mut p); // unpacked size
            vint(volume, &mut p); // attributes
            if file_flags & 2 != 0 {
                p += 4; // mtime
            }
            let data_crc = (file_flags & 4 != 0).then_some(p);
            if file_flags & 4 != 0 {
                p += 4;
            }
            vint(volume, &mut p); // compression
            vint(volume, &mut p); // host OS
            let name_len = vint(volume, &mut p) as usize;
            heads.push(FileHead {
                name: volume[p..p + name_len].to_vec(),
                start,
                body: body.clone(),
                data_crc,
                split_after: flags & 0x10 != 0,
                data: data.clone(),
            });
        }
        if kind == 5 {
            break;
        }
        at = data.end;
    }
    heads
}

/// The volumes holding a LEADING fragment of `name`: every fragment but the
/// last, which is the ones whose field is a packed CRC32.
fn leading_volumes(set: &[Vec<u8>], name: &str) -> Vec<usize> {
    (0..set.len())
        .filter(|&v| {
            file_heads(&set[v])
                .iter()
                .any(|h| h.name == name.as_bytes() && h.split_after)
        })
        .collect()
}

fn head_of<'a>(heads: &'a [FileHead], name: &str) -> &'a FileHead {
    heads
        .iter()
        .find(|h| h.name == name.as_bytes())
        .expect("the member has a header in this volume")
}

/// Overwrite the member's leading field in volume `v` and re-stamp the
/// header's own CRC, so only the field disagrees.
fn damage_field(set: &mut [Vec<u8>], v: usize, name: &str) {
    let heads = file_heads(&set[v]);
    let head = head_of(&heads, name);
    let at = head
        .data_crc
        .expect("a leading fragment carries a data CRC");
    set[v][at..at + 4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
    let crc = crc32(&set[v][head.body.clone()]);
    set[v][head.start..head.start + 4].copy_from_slice(&crc.to_le_bytes());
}

/// Invert one byte in the middle of the member's data area in volume `v`.
fn damage_data(set: &mut [Vec<u8>], v: usize, name: &str) {
    let heads = file_heads(&set[v]);
    let head = head_of(&heads, name);
    let at = head.data.start + head.data.len() / 2;
    set[v][at] ^= 0xFF;
}

// ---- a sink that records what it is told, for both entry points ----

/// What one member was told, in order.
#[derive(Clone, Debug, Default, PartialEq)]
struct Heard {
    /// `fragment_mismatch` volumes, in the order they came.
    mismatches: Vec<u32>,
    /// The close: checksum verdict and the counted mismatches.
    closed: Option<(Option<bool>, u32)>,
    /// A mismatch that arrived AFTER the member's close.
    late: bool,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Record {
    members: BTreeMap<Vec<u8>, Heard>,
}

struct Recorder {
    record: Arc<Mutex<Record>>,
    verify: bool,
    skip: Option<&'static str>,
}

struct Out {
    record: Arc<Mutex<Record>>,
    name: Vec<u8>,
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        lock(&self.record)
            .members
            .entry(self.name.clone())
            .or_default()
            .bytes
            .extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn lock<T>(held: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

impl Recorder {
    fn opened(&self, member: &MemberInfo<'_>) -> Disposition<Out> {
        if self.skip.is_some_and(|s| s.as_bytes() == member.name) {
            return Disposition::Skip;
        }
        lock(&self.record)
            .members
            .insert(member.name.to_vec(), Heard::default());
        if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Out {
                record: Arc::clone(&self.record),
                name: member.name.to_vec(),
            })
        }
    }
    fn mismatched(&self, member: &MemberInfo<'_>, volume: u32) {
        let mut record = lock(&self.record);
        let heard = record.members.entry(member.name.to_vec()).or_default();
        heard.late |= heard.closed.is_some();
        heard.mismatches.push(volume);
    }
    fn closed(&self, member: &MemberInfo<'_>, outcome: &MemberOutcome) {
        let mut record = lock(&self.record);
        let heard = record.members.entry(member.name.to_vec()).or_default();
        heard.closed = Some((outcome.checksum_ok, outcome.fragment_mismatches));
    }
}

impl Sink for Recorder {
    type Out = Out;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        Ok(self.opened(member))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed(member, outcome);
        Ok(())
    }
    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.mismatched(member, volume);
        Ok(())
    }
}

impl ParallelSink for Recorder {
    type Out = Out;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        Ok(self.opened(member))
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        _out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed(member, outcome);
        Ok(())
    }
    fn fragment_mismatch(&self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.mismatched(member, volume);
        Ok(())
    }
}

/// Every arrangement: (label, what each member heard).
fn every_arm(
    set: &[Vec<u8>],
    skip: Option<&'static str>,
) -> Vec<(String, BTreeMap<Vec<u8>, Heard>)> {
    let sources = || -> Vec<Arc<dyn RangeSource>> {
        set.iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect()
    };
    let mut arms = Vec::new();
    for workers in [1usize, 4] {
        for verify in [true, false] {
            let options = ReadOptions::default().with_workers(Some(workers));
            let record = Arc::new(Mutex::new(Record::default()));
            let mut sink = Recorder {
                record: Arc::clone(&record),
                verify,
                skip,
            };
            let what = if verify { "verify" } else { "write" };
            rarkit::extract(sources(), &options, &mut sink, &mut ())
                .unwrap_or_else(|e| panic!("extract {what} -mt{workers}: {e:?}"));
            drop(sink);
            let members = std::mem::take(&mut lock(&record).members);
            arms.push((format!("extract {what} at width {workers}"), members));

            let record = Arc::new(Mutex::new(Record::default()));
            let sink = Recorder {
                record: Arc::clone(&record),
                verify,
                skip,
            };
            rarkit::extract_parallel(sources(), &options, &sink, workers)
                .unwrap_or_else(|e| panic!("extract_parallel {what} x{workers}: {e:?}"));
            drop(sink);
            let members = std::mem::take(&mut lock(&record).members);
            arms.push((
                format!("extract_parallel {what} at breadth {workers}"),
                members,
            ));
        }
    }
    arms
}

/// What `name` must have heard on every arm: `mismatches` in that order,
/// the verdict `ok`, and (written) the original bytes when `ok`.
fn expect(set: &[Vec<u8>], name: &str, original: &[u8], mismatches: &[usize], ok: bool) {
    let want: Vec<u32> = mismatches.iter().map(|&v| v as u32).collect();
    for (arm, members) in every_arm(set, None) {
        let heard = members
            .get(name.as_bytes())
            .unwrap_or_else(|| panic!("{arm}: {name} was never opened"));
        assert_eq!(heard.mismatches, want, "{arm}: {name}'s mismatches");
        assert!(!heard.late, "{arm}: a mismatch came after {name}'s close");
        assert_eq!(
            heard.closed,
            Some((Some(ok), want.len() as u32)),
            "{arm}: {name}'s close"
        );
        if ok && arm.contains("write") {
            assert!(heard.bytes == original, "{arm}: {name}'s bytes");
        }
    }
}

/// The three sets a split member is read from: stored, compressed and a
/// compressed solid set whose split member follows another in the chain.
/// Each is (label, set, the split member's name and bytes, every member).
#[allow(clippy::type_complexity)]
fn sets() -> Vec<(&'static str, Vec<Vec<u8>>, &'static str, Vec<u8>)> {
    let stored = noise(300_000, 4);
    let text = rarkit_testdata::chatter(9, 1 << 20);
    let head = rarkit_testdata::chatter(3, 20_000);
    vec![
        (
            "stored",
            volume_set(&[("split.bin", stored.clone())], WriteMethod::Stored, false),
            "split.bin",
            stored,
        ),
        (
            "compressed",
            volume_set(
                &[("split.txt", text.clone())],
                WriteMethod::Compressed {
                    level: 3,
                    dictionary: None,
                },
                false,
            ),
            "split.txt",
            text.clone(),
        ),
        (
            "solid",
            volume_set(
                &[("head.txt", head), ("split.txt", text.clone())],
                WriteMethod::Compressed {
                    level: 3,
                    dictionary: None,
                },
                true,
            ),
            "split.txt",
            text,
        ),
    ]
}

#[test]
fn every_set_has_leading_fragments_with_a_field() {
    for (label, set, name, _) in sets() {
        let leading = leading_volumes(&set, name);
        assert!(
            leading.len() >= 2,
            "{label}: {} leading fragments",
            leading.len()
        );
        for v in leading {
            let heads = file_heads(&set[v]);
            assert!(
                head_of(&heads, name).data_crc.is_some(),
                "{label}: volume {v} carries no field"
            );
        }
    }
}

#[test]
fn a_clean_split_member_hears_no_mismatch() {
    for (label, set, name, original) in sets() {
        let _ = label;
        expect(&set, name, &original, &[], true);
    }
}

/// The field alone disagrees: the member is GOOD, whole and kept, and the
/// sink is told which volume, once.
#[test]
fn a_field_that_disagrees_is_a_diagnostic_and_the_member_passes() {
    for (label, clean, name, original) in sets() {
        for v in leading_volumes(&clean, name) {
            let mut set = clean.clone();
            damage_field(&mut set, v, name);
            let _ = label;
            expect(&set, name, &original, &[v], true);
        }
    }
}

/// Two fields: both volumes, in the order the fragments ended.
#[test]
fn two_fields_that_disagree_are_told_in_fragment_order() {
    for (_, clean, name, original) in sets() {
        let leading = leading_volumes(&clean, name);
        let (a, b) = (leading[0], leading[1]);
        let mut set = clean.clone();
        damage_field(&mut set, a, name);
        damage_field(&mut set, b, name);
        expect(&set, name, &original, &[a, b], true);
    }
}

/// Real damage fails the WHOLE checksum, and the damaged fragment's own
/// field disagrees too, so its volume is named beside the bad field's.
#[test]
fn damaged_bytes_fail_the_member_and_name_their_volume() {
    for (_, clean, name, original) in sets() {
        let leading = leading_volumes(&clean, name);
        let (a, b) = (leading[0], leading[1]);
        let mut set = clean.clone();
        damage_field(&mut set, a, name);
        damage_data(&mut set, b, name);
        expect(&set, name, &original, &[a, b], false);
    }
}

/// A member the sink SKIPPED hears nothing more: no `fragment_mismatch`
/// and no `close` (SPEC-API 4.4, `close` is "called once per member opened
/// with Write or Verify"; spec F 3.5.6, fragments are judged for such a
/// member only). Until 30 Sep 2026 every arm closed a skipped member with
/// no verdict, split or not, and a skipped split member of a solid set,
/// which is decoded because the chain needs it, was told of every
/// disagreeing fragment besides.
///
/// Asked of each set's split member with every leading field damaged, of
/// the member in front of it, which is not split, and of the genuine rar
/// 4.20 three-volume set (`r4_vol`, one stored member over all three).
#[test]
fn a_skipped_member_hears_nothing() {
    let mut heard = Vec::new();
    for (label, clean, name, _) in sets() {
        let mut set = clean.clone();
        for v in leading_volumes(&clean, name) {
            damage_field(&mut set, v, name);
        }
        for (arm, members) in every_arm(&set, Some(name)) {
            if let Some(h) = members.get(name.as_bytes()) {
                heard.push(format!(
                    "{label} {arm}: {name} {:?} {:?}",
                    h.mismatches, h.closed
                ));
            }
        }
    }
    for solid in [false, true] {
        let set = volume_set(
            &[
                ("head.txt", rarkit_testdata::chatter(3, 20_000)),
                ("split.txt", rarkit_testdata::chatter(9, 1 << 20)),
            ],
            WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            solid,
        );
        for (arm, members) in every_arm(&set, Some("head.txt")) {
            if let Some(h) = members.get(b"head.txt".as_slice()) {
                heard.push(format!("solid {solid} {arm}: head.txt {:?}", h.closed));
            }
            assert!(
                members
                    .get(b"split.txt".as_slice())
                    .is_some_and(|h| h.closed.is_some()),
                "solid {solid} {arm}: the member after a skipped one was not closed"
            );
        }
    }
    let rar4: Vec<Vec<u8>> = (1..=3)
        .map(|n| {
            let path = format!(
                "{}/../../specs/vectors-G/archives/r4_vol.part{n}.rar",
                env!("CARGO_MANIFEST_DIR")
            );
            std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
        })
        .collect();
    for (arm, members) in every_arm(&rar4, Some("split.bin")) {
        if let Some(h) = members.get(b"split.bin".as_slice()) {
            heard.push(format!("rar4 {arm}: split.bin {:?}", h.closed));
        }
    }
    assert!(heard.is_empty(), "a skipped member heard of: {heard:#?}");
}
