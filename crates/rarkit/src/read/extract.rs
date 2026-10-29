//! Layer 4 of spec F section 2.3: extraction.
//!
//! One pass, in archive order, with the headers of volume `k + 1` parsed
//! when volume `k + 1` is first needed and not before. `extract` therefore
//! parses headers AS it goes and never calls `Archive::open` on the volumes
//! it extracts: a reader that walks every header of a volume before
//! extracting anything has already read to the end of the volume, which on
//! a downloading source means waiting for the whole volume.
//!
//! The crossing of volumes and the packed stream of one member are layer 3
//! ([`crate::read::walk`]). Every decoder PULLS, so a member is decoded
//! inside one call that owns the walk for as long as the member lasts, and
//! the walk comes back positioned after the member's last fragment.
//!
//! **An extraction error is never a silent success** (spec F section 8).
//! Every member that fails for any reason is reported through its own
//! `Sink::close` with its own outcome, before extraction moves on, and the
//! report counts it. A feature this package cannot decode is an error
//! naming the feature, raised once the good members ahead of and behind it
//! have been delivered.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::checksum::blake2sp::{Armed, Blake2sp};
use crate::checksum::Crc32;
use crate::crypto::{rar4_family_cipher_on, MemberCipher, MemberDecryptor, Rar13Stream, Rar5Keys};
use crate::error::{Corruption, Error, ErrorKind, Rar5Fault, Result, Unsupported};
use crate::lz20::bits::{BitSource, SliceBits};
use crate::lz20::window::Window as Rar20Window;
use crate::lz20::{Lz20Step, Rar20Lz};
use crate::rar1x::Rar1x;
use crate::rar3_lz::bits::Bits as Rar3Bits;
use crate::rar3_lz::{MemberSpan, Rar3Stream, StreamOut};
use crate::rar5_lz::output::LzSink;
use crate::rar5_lz::{PackedSource, Rar5Lz};
use crate::read::block::{Fields, FileHdr, Redirect};
use crate::read::rar13::Sum16;
use crate::read::rar4;
use crate::read::reader::ReadCtx;
#[cfg(feature = "parallel")]
use crate::read::seam;
#[cfg(feature = "parallel")]
use crate::read::walk::Span;
use crate::read::walk::{Gate, MemberStream, Notify, Walk, TICK};
use crate::read::{
    Disposition, ExtractReport, Format, MemberInfo, MemberOutcome, Progress, Redirection, Sink,
};
use crate::source::Volumes;
use crate::types::{Checksum, Method};

// The parts, one module a seam.
mod links;
use links::*;
mod reading;
use reading::Probe;
mod packed;
use packed::*;
pub(crate) use packed::{PackedRead, Scratch, Tally};
mod decoders;
use decoders::*;
#[cfg(feature = "parallel")]
pub(crate) use decoders::{charge_after, window_of};
pub(crate) use decoders::{codec_of, decode, member_need, member_reach, Codec, Decoders, Shrink};
mod stored;
pub(crate) use stored::COPY;
use stored::*;
#[cfg(feature = "parallel")]
mod wide;
#[cfg(feature = "parallel")]
use wide::*;
#[cfg(feature = "parallel")]
pub(crate) use wide::{CutWhen, Slice};
mod walk;
#[cfg(all(feature = "parallel", feature = "offload-knob"))]
pub(crate) use walk::offload_floor_compressed;
#[cfg(all(feature = "parallel", not(feature = "offload-knob")))]
pub(crate) use walk::offload_floor_compressed;
pub(crate) use walk::Walking;
use walk::*;
#[cfg(feature = "parallel")]
pub(crate) use walk::{batchable, offloadable, split_job_kind, worth_a_worker};
mod driver;
pub(crate) use driver::{Closed, Direct, Driver};
#[cfg(feature = "parallel")]
pub(crate) use driver::{Job, Next, Split};

// The most packed bytes held at once for a decoder that needs a block
// contiguous: a RAR 5 block header plus the largest payload its 24 bit
// length field can name (spec H2 4.1). The decoder's own constant, so the
// source's cap and the tape walk's largest request are one number.
use crate::rar5_lz::MAX_PACKED;

/// What one member is being decoded into.
pub(crate) enum Out<W> {
    /// Decode and write.
    Write(W),
    /// Run the member through the decoder and the checksums but put the
    /// plaintext nowhere: what section 4.4 gives the `t` command.
    Verify,
}

/// The member being decoded: its output, its running checksums and what it
/// has produced.
pub(crate) struct Member<W> {
    pub(crate) out: Option<Out<W>>,
    /// The declared unpacked size, which is a LIMIT on output and never the
    /// size of a buffer (spec F 4.2).
    unpacked_size: Option<u64>,
    pub(crate) written: u64,
    /// Whether the decoder failed this member by a filter span of its own
    /// (spec J 3.8): the one failure that is a member's verdict even when
    /// it declares no bytes (spec F 3.6.3 item 4). Set by the RAR 3
    /// decode; RAR 5 names the same verdict in its error.
    pub(crate) span_left_member: bool,
    crc: Crc32,
    /// Whether anything will ever READ [`Self::crc`].
    ///
    /// Only a member whose header carries a CRC32 is compared against one
    /// (`finish` below), and a RAR 1.3 member carries none at all: its
    /// integrity is [`Self::sum16`]. The CRC32 was run over every output
    /// byte of every member regardless, so a RAR 1.3 extract paid for a
    /// whole second pass over its output whose result no branch of
    /// `finish` can reach.
    crc_wanted: bool,
    /// Whether the member's HEADER carries a checksum of its data, as it
    /// was read when the member was built: [`Self::carries_a_checksum`].
    /// Not the same question as [`Self::crc_wanted`], which is switched
    /// off while another unit runs the CRC32 ([`Self::detach_crc`]): a
    /// member decoded behind the seam still carries its checksum.
    checked: bool,
    /// Whether the FIRST header NAMED a checksum, a CRC32 field or a
    /// BLAKE2sp record. Narrower than [`Self::checked`], which also
    /// counts a bare split header (it arms CRC32 for what the last header
    /// may bring). `verdict` reads it for a last header that names none.
    named: bool,
    /// Whether the member's archive is a VOLUME of a set, by its main
    /// header's volume flag, which whoever builds the member for a read
    /// says after building it. A member that ends short there is never
    /// good (spec F 4.2, rule 6); `verdict` reads it and nothing else
    /// does.
    pub(crate) in_set: bool,
    /// The RAR 1.3 member checksum, run ONLY on that container. It is a
    /// serial byte loop by definition (spec F 3.4.3), so running it on
    /// every format would put a one-byte-at-a-time dependency chain in
    /// front of every archive this crate reads.
    sum16: Option<Sum16>,
    /// Whether this member carries a BLAKE2sp hash, which is run in the
    /// operation's ONE hasher rather than in a state of the member's own:
    /// the state is 4 KiB of inline arrays and a box of it per member is an
    /// allocation per member, which API promise 2.4 forbids.
    blake: bool,
    /// The member's RAR 5 keys, when it is encrypted. Whether the stored
    /// checksums are MAC-converted (spec K 3.7.4) is the LAST fragment
    /// header's to say, so the keys are kept and the conversion is decided
    /// at `close`. Held INLINE: a box of 72 bytes of arrays, per member, is
    /// the same per-member allocation.
    keys: Option<Rar5Keys>,
    /// Whether a WRITTEN member may take the wide read (`read::wide`):
    /// only where the caller has said its writer is not a file on disk
    /// (`ReadOptions::sink_is_file` of `Some(false)`, which `p` says). A
    /// file's write is the wall and the seam already hides the read
    /// behind it; measured, the wide read bought `x` nothing on a timed
    /// Zen 4 (0.65 s against 0.67 to 0.68 s), so it is not
    /// risked there. A member that is only checked goes wide regardless.
    #[cfg(feature = "parallel")]
    pub(crate) wide_write: bool,
    /// Whether the caller has said every volume is already present
    /// (`ReadOptions::volumes_present`), so a read abreast may cross to
    /// the next volume ahead of its join (`read::across`). The walk's own
    /// member only; `false` everywhere else.
    #[cfg(feature = "parallel")]
    pub(crate) volumes_present: bool,
    /// How this member's writer takes a stored RANGE instead of its bytes
    /// (`read::handed`), where the driver's writer can
    /// ([`Driver::hand_over`]): the solid path's, whose caller writes on
    /// another thread than the walk's. `None` everywhere else, and the
    /// member is then read as it always was.
    #[cfg(feature = "parallel")]
    pub(crate) hand_over: Option<crate::read::handed::HandOver<W>>,
    /// [`Member::hand_over`] for a range of whole AES-CBC blocks, where
    /// the member's writer is not said to be a stream and is on the thread
    /// that holds the member's key (`read::handed::cut_cipher_here`): a pool worker's
    /// member and the walk's own. `None` everywhere else, and the range
    /// is then deciphered wide and written from the joined pieces.
    #[cfg(feature = "parallel")]
    pub(crate) hand_cipher: Option<crate::read::handed::HandCipher<W>>,
    /// [`Member::hand_over`] for a range of a CLEAR member whose one check
    /// is a BLAKE2sp record, where the member's writer is on the thread
    /// that reads it (`read::handed::cut_hashed_here`): a pool worker's
    /// member. `None` everywhere else, and such a member is then read,
    /// hashed and written a buffer at a time on its own thread.
    #[cfg(feature = "parallel")]
    pub(crate) hand_hashed: Option<crate::read::handed::HandHashed<W>>,
}

/// Where extraction has got to on the OUTPUT side. The packed side is the
/// walk's (layer 3), and the two are alive together while a member decodes.
struct Run<'p, D: Driver> {
    driver: &'p mut D,
    /// Decoded bytes the WALKING thread produced. A worker's are its own
    /// and reach the report through [`Closed::bytes`].
    bytes: u64,
    /// Decoded bytes the driver has delivered that `bytes` does not count
    /// ([`Driver::delivered`]), so the caller's `Progress::output` counts
    /// every byte the caller has been given.
    base: u64,
    output_since_tick: u64,
    /// The memory policy of this operation, which sizes every decoder.
    policy: crate::MemoryPolicy,
    /// `ReadOptions::sink_is_file`: the caller's cost class for the seam
    /// of spec F 3.7.7, read here because the walk borrows the context
    /// that holds the options and the gate is asked per member. It
    /// reaches exactly one decision, `seam::engages`, and nothing else in
    /// an extraction reads it (SPEC-API 8.5).
    ///
    /// Gated on `parallel` because the decision it feeds is: without the
    /// feature there is no seam for any value of the field (8.5), the
    /// branch below compiles away, and a field nothing reads is dead.
    #[cfg(feature = "parallel")]
    sink_is_file: Option<bool>,
    /// `ReadOptions::volumes_present`, read where `sink_is_file` is.
    #[cfg(feature = "parallel")]
    volumes_present: bool,
    /// The window a decoder that needs one block contiguous reads through
    /// and the buffer a stored member is carried through: one set for the
    /// whole operation, never one per member (spec F 7.3.5, 7.3.6, and the
    /// per-member buffer the profile found in the engine this replaces,
    /// 7.3.9).
    scratch: Scratch,
    /// The operation's ONE BLAKE2sp state, started again for each member
    /// that carries one. Boxed once because it is 4 KiB of inline arrays
    /// and `Run` lives on the stack; never boxed per member.
    blake: Option<Box<Blake2sp>>,
}

/// `RARKIT_B2SP_TEAM`: which figure the BLAKE2sp leaf team's worker
/// allowance is taken from ([`TeamRule`]): `policy`, `larger` or `width`;
/// anything else, or nothing, is [`TEAM_RULE`]. A RUNTIME knob, so one
/// binary carries every arm. It moves which threads hash, never a digest.
pub(crate) const B2SP_TEAM_ENV: &str = "RARKIT_B2SP_TEAM";

/// Where a member's BLAKE2sp hasher takes its worker allowance from.
///
/// **Why there is a choice.** The hasher was always given
/// `MemoryPolicy::max_workers`, which is the MEMORY budget's figure
/// (`working_limit / 64 MiB`) and which the read's `-mt` has not moved
/// since the width dial separated the two (SPEC-API 8.4.6). A process
/// budget leaves 480 of the default 512 MiB to the engine, so that figure
/// is 7 under `rarfast`, and the carried team rounds an allowance of 4 to
/// 7 down to FOUR leaf threads: counted on an M1 Ultra (1 Oct 2026),
/// a lone stored big member checked by
/// BLAKE2sp hashed on four threads at every `-mt`, a stated `-mt1`
/// included, and tested behind unrar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TeamRule {
    /// `MemoryPolicy::max_workers`, as before 1 Oct 2026.
    Policy,
    /// Under the DEFAULT WHOLE-PROCESS policy
    /// (`MemoryPolicy::process_default`, which is `rarfast` with no `-mm`),
    /// the larger of that and the read's resolved width, stated or not: a
    /// read eight wide or wider hashes a lone stream on a leaf a thread,
    /// and a narrower one keeps the policy's figure, so no row falls
    /// under what it was (a stated `-mt1`, `-mt2` or `-mt4` hashes as it
    /// did before this rule). Under every other policy it is `Policy`: a
    /// library caller's `max_workers` bounds the team as SPEC-API 8.4.1
    /// says (a caller that sets one keeps its CPU), and a NAMED budget
    /// (`-mm`), on which no row was sat, keeps what it had.
    Larger,
    /// The read's resolved width alone, stated or not: a stated `-mt1` is
    /// one thread for the hash too.
    Width,
}

/// The rule where [`B2SP_TEAM_ENV`] says nothing: `larger`, on its rows
/// (M1 Ultra, a quiet box, the control's own binary beside it,
/// 1 Oct 2026): the lone stored big member's `t`
/// 6.31 s to 4.19 s, its `x` 6.61 s to 4.27 s, and every compressed,
/// mixed, solid and encrypted row under BLAKE2sp level or ahead, none
/// under 0.97 of main. Off aarch64 the hash is one thread and no rule
/// reaches it. What a stated `-mt1` should mean for the hash (`width`
/// makes it one thread at 1.6 times the wall) is the owner's question and
/// is not decided here.
const TEAM_RULE: TeamRule = TeamRule::Larger;

/// [`B2SP_TEAM_ENV`]'s value as a rule.
fn team_rule_of(text: Option<&str>) -> TeamRule {
    match text.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("policy") => TeamRule::Policy,
        Some("larger") => TeamRule::Larger,
        Some("width") => TeamRule::Width,
        _ => TEAM_RULE,
    }
}

/// The rule in force: a test's, then the environment's, read once.
fn team_rule() -> TeamRule {
    #[cfg(feature = "test-support")]
    if let Some(forced) = crate::probe::b2sp_team() {
        return forced;
    }
    static RULE: std::sync::OnceLock<TeamRule> = std::sync::OnceLock::new();
    *RULE.get_or_init(|| team_rule_of(crate::knob::reader_var(B2SP_TEAM_ENV).ok().as_deref()))
}

/// The allowance `rule` gives a hasher: `policy` is the memory policy's
/// worker figure, `width` the width the read resolved for this member
/// (`Decoders::decode_width`: the operation's, or a pool worker's share of
/// it), `process_default` whether the policy is the default whole-process
/// one (a process overhead and no named limit).
fn team_allowance(rule: TeamRule, policy: usize, width: usize, process_default: bool) -> usize {
    match rule {
        TeamRule::Policy => policy,
        TeamRule::Larger if process_default => policy.max(width),
        TeamRule::Larger => policy,
        TeamRule::Width => width.max(1),
    }
}

/// The worker allowance a member's BLAKE2sp hasher is built with
/// ([`Member::of`]'s `workers`), under the rule in force, and beside it
/// the width the read resolved for the member, which the allowance does
/// not tell the hasher: under the default rule it is the larger of the
/// two figures.
pub(crate) fn blake_workers(policy: &crate::MemoryPolicy, decoders: &Decoders) -> Armed {
    Armed {
        workers: team_allowance(
            team_rule(),
            policy.max_workers,
            decoders.decode_width,
            policy.process_overhead > 0 && !policy.limit_named,
        ),
        width: decoders.decode_width.max(1),
    }
}

impl<W> Member<W> {
    /// Set one member up to be decoded, from its header.
    ///
    /// ONE constructor for both drivers: a field the sequential path sets
    /// and the concurrent one forgets is a member whose verdict differs
    /// between the two, which SPEC-API 4.4 forbids and which no output byte
    /// would show.
    ///
    /// `workers` is the operation's worker ceiling, which is what API 8.2's
    /// table promises for the BLAKE2sp leaf team: `max_workers` bounds
    /// whether the team may engage and how many leaves it may spread over.
    /// It is a ceiling and not a demand - the team engages only on a batch
    /// large enough to be worth it, and a member whose decoded output never
    /// reaches that size is hashed on the thread that decodes it - so a
    /// narrow decode does not wake workers for a trickle of bytes.
    pub(crate) fn of(
        out: Option<Out<W>>,
        file: &FileHdr,
        format: Format,
        keys: Option<Rar5Keys>,
        blake_state: &mut Option<Box<Blake2sp>>,
        workers: impl Into<Armed>,
    ) -> Member<W> {
        // Which hasher to run is the LAST fragment's to say (spec F 3.5.6),
        // and this is the FIRST fragment's header. On a member that is not
        // split, or whose first header carries a checksum, the two agree:
        // a leading fragment's field is of the member's own kind. A RAR 5
        // leading fragment may carry NO checksum at all, which the old
        // engine's writer does (26 Sep 2026: every leading header of its
        // volume sets, with the whole member's CRC32 on the last, and
        // `unrar t` 7.23 calls the set OK). Arming from that header ran no
        // hash and failed every such member whose bytes were right. So a
        // split member whose first header names no kind arms CRC32, the
        // kind that writer closes with.
        //
        // NOT BLAKE2sp (decided 26 Sep 2026): no
        // known writer puts a BLAKE2sp last header behind bare leading
        // ones (reference `rar -htb` writes a digest in every header), and
        // the unused pass cost 47 percent of the instructions on the sets
        // that do occur. Such a member, if one appears, FAILS in
        // `verdict` below: its last header names a kind nothing here ran.
        let unknown = file.split_after && file.checksum.is_none();
        let carries_blake = matches!(file.checksum, Some(Checksum::Blake2sp(_)));
        if carries_blake {
            let armed: Armed = workers.into();
            #[cfg(feature = "test-support")]
            crate::probe::note_b2sp_allowance(armed.workers);
            // RESET rather than rebuilt: a hasher owns a heap stage, so
            // building one per member is an allocation per member
            // (API promise 2.4).
            blake_state
                .get_or_insert_with(|| Box::new(Blake2sp::with_workers(armed.workers)))
                .arm_member(armed, matches!(file.method, Method::Stored));
        }
        let crc_wanted = matches!(file.checksum, Some(Checksum::Crc32(_)))
            || (unknown && !matches!(format, Format::Rar13));
        Member {
            out,
            unpacked_size: file.unpacked_size,
            written: 0,
            span_left_member: false,
            crc: Crc32::new(),
            crc_wanted,
            checked: crc_wanted || carries_blake,
            named: file.checksum.is_some(),
            in_set: false,
            sum16: matches!(format, Format::Rar13).then(Sum16::new),
            blake: carries_blake,
            keys,
            #[cfg(feature = "parallel")]
            wide_write: false,
            #[cfg(feature = "parallel")]
            volumes_present: false,
            #[cfg(feature = "parallel")]
            hand_over: None,
            #[cfg(feature = "parallel")]
            hand_cipher: None,
            #[cfg(feature = "parallel")]
            hand_hashed: None,
        }
    }
}

impl<W> Member<W> {
    /// Whether this member carries a checksum of its data, a CRC32 field
    /// or a BLAKE2sp record. A split member whose first header names no
    /// kind counts as carrying one: its last header may. Whichever unit
    /// runs the checksum, the answer is the header's.
    pub(crate) fn carries_a_checksum(&self) -> bool {
        self.checked
    }

    /// The same member, its output swapped for another.
    ///
    /// The seam of spec F 3.7.7 decodes into a ring rather than into the
    /// caller's writer, and the member that comes back off the source unit
    /// carries the RING's end of it. Everything that decides the verdict -
    /// the running checksums, the bytes produced, the keys the MAC
    /// conversion needs - is unchanged by the swap, which is the point:
    /// `verdict` and `close` then see exactly the member the sequential
    /// path would have handed them.
    #[cfg(feature = "parallel")]
    pub(crate) fn retarget<X>(self, out: Option<Out<X>>) -> Member<X> {
        Member {
            out,
            unpacked_size: self.unpacked_size,
            written: self.written,
            span_left_member: self.span_left_member,
            crc: self.crc,
            crc_wanted: self.crc_wanted,
            checked: self.checked,
            named: self.named,
            in_set: self.in_set,
            sum16: self.sum16,
            blake: self.blake,
            keys: self.keys,
            wide_write: self.wide_write,
            #[cfg(feature = "parallel")]
            volumes_present: self.volumes_present,
            // A hand-over belongs to the writer it was made for.
            hand_over: None,
            #[cfg(feature = "parallel")]
            hand_cipher: None,
            #[cfg(feature = "parallel")]
            hand_hashed: None,
        }
    }

    /// Hand the member's CRC32 to another unit, or `None` when nothing
    /// will ever read it. After this `emit` folds nothing into the member
    /// until [`Self::attach_crc`] gives the state back.
    ///
    /// For the seam of spec F 3.7.7, whose deliver unit runs the checksum
    /// for a member whose source unit is the wall (`seam::checksum_on_deliver`).
    #[cfg(feature = "parallel")]
    pub(crate) fn detach_crc(&mut self) -> Option<Crc32> {
        if !self.crc_wanted {
            return None;
        }
        self.crc_wanted = false;
        Some(std::mem::replace(&mut self.crc, Crc32::new()))
    }

    /// The state [`Self::detach_crc`] handed out, back in the member for
    /// `verdict` to read. The bytes that reached it are the member's own,
    /// in order, so the verdict is the sequential path's.
    #[cfg(feature = "parallel")]
    pub(crate) fn attach_crc(&mut self, crc: Crc32) {
        self.crc = crc;
        self.crc_wanted = true;
    }
}

/// What one member's packed stream leaves behind once its decode has
/// stopped, whichever unit ran it.
pub(crate) struct Landed {
    pub(crate) outcome: Result<()>,
    pub(crate) broken: bool,
    /// The volumes of the leading fragments whose field disagreed (spec F
    /// 3.5.6): reported before the close, never a failure.
    pub(crate) fragment_mismatches: Vec<u32>,
    /// The LAST fragment's header, and `None` when the member had exactly
    /// one fragment and that header is still the caller's own.
    ///
    /// The close reads the last fragment's header (spec F 3.5.6 puts the
    /// member's checksum there), which for an unsplit member is the first
    /// one. Carrying it by value cost a clone a member and bought nothing
    /// that the caller's own reference does not already give.
    pub(crate) later: Option<Box<FileHdr>>,
    pub(crate) data: std::ops::Range<u64>,
    pub(crate) name_span: std::ops::Range<u32>,
    /// The member FAILED by a decoder's verdict with fragments still
    /// ahead, and the walk passed over them: it stands after the member's
    /// last fragment, in another volume than `data` names, and has
    /// released what it passed. `false` for every member that did not
    /// fail so.
    pub(crate) passed: bool,
}

/// Land the walk after the member's last fragment and read off what the
/// close needs.
///
/// Whatever happened, the walk must land after the member's last fragment:
/// the block after it is the next thing extraction reads. A member that
/// FAILED is not drained - its error is the outcome - which is also what
/// keeps the cancellation bound of 3.7.7 a bound: a refused writer must
/// not be answered by reading the rest of the member to be tidy.
///
/// ONE failure leaves the walk short of that and is mended here: a
/// DECODER'S VERDICT on a member that still has fragments ahead. That
/// error is the member's alone and extraction goes on (spec F 8), so the
/// fragments ahead are passed over UNREAD: left where it stood, the walk
/// read the member's own continuation header next and took it for a
/// member, and the sink was asked to open the same member twice. An error
/// that breaks the walk or ends the operation passes nothing.
pub(crate) fn land<V: Volumes, N: Notify>(
    mut stream: MemberStream<'_, '_, V, N>,
    outcome: Result<()>,
    scratch: &mut Scratch,
) -> Landed {
    let outcome = match outcome {
        Ok(()) => {
            let mut buf = std::mem::take(&mut scratch.copy);
            if buf.len() < COPY {
                buf.resize(COPY, 0);
            }
            let drained = stream.drain(&mut buf);
            scratch.copy = buf;
            drained
        }
        Err(e) => Err(e),
    };
    let passed =
        matches!(&outcome, Err(e) if !stream.broken && !ends_operation(e)) && stream.continues();
    if passed {
        stream.pass_the_rest();
    }
    Landed {
        outcome,
        broken: stream.broken,
        fragment_mismatches: stream.fragment_mismatches,
        later: stream.later,
        data: stream.data.clone(),
        name_span: stream.name_span.clone(),
        passed,
    }
}

/// The end of a member whose remaining fragments were passed over
/// ([`Landed::passed`]): its `close` has been made, and what that walk
/// met, if it failed, now ends the operation.
#[cold]
fn after_passing<V: Volumes>(walk: &mut Walk<'_, V>, closed: Result<()>) -> Result<()> {
    closed?;
    walk.passing_failed.take().map_or(Ok(()), Err)
}

/// Extract a single archive, a set, or a set whose volumes are still
/// arriving.
pub(crate) fn extract_with<V: Volumes, K: Sink, P: Progress>(
    volumes: V,
    ctx: &mut ReadCtx,
    sink: &mut K,
    progress: &mut P,
) -> Result<ExtractReport> {
    // DECODE AHEAD behind the sequential contract (`read::sequential`),
    // where it is on and there is a second thread to decode on: a caller
    // who asked for a width of one gets one.
    let sink = &mut Guarded(sink);
    let (volumes, room) = budget_floor(volumes, ctx)?;
    ctx.room = room;
    #[cfg(feature = "parallel")]
    if crate::read::sequential::engaged() && ctx.options.read_width() > 1 {
        return crate::read::sequential::extract_ahead(volumes, ctx, sink, progress);
    }
    extract_driven(volumes, ctx, &mut Direct::new(sink), progress)
}

/// The up-front check and the ROOM a NAMED budget leaves for the
/// windows of the members in flight (SPEC-API 8.4.1). Without a named
/// budget nothing is read and nothing changes. With one, volume 0's headers
/// are read once, before any member: a budget below
/// [`crate::read::Archive::minimum_working_memory`] is refused as
/// `LimitExceeded { resource: WorkingMemory }` in the terms of the policy's
/// constructor, and otherwise the engine limit less what the walk holds
/// whatever the member ([`crate::read::Archive::fixed_working_memory`]) is
/// handed to the pools as the limit their admission prices each member's
/// window against: so small members read as wide as the width allows and a
/// large one waits for the room its own need takes, instead of every
/// member paying the largest member's need. The room is never below the
/// largest member's need, which the floor guarantees, so a member with
/// nothing else in flight is always admitted. Volume 0 is handed back to
/// the walk as it was fetched, so a provider is asked for it once. Later
/// volumes of a set are not waited for: their members keep promise 2.3's
/// own refusal. A header this pass cannot read is left for the walk to
/// report as it always has.
pub(crate) fn budget_floor<V: Volumes>(
    mut volumes: V,
    ctx: &ReadCtx,
) -> Result<(First<V>, Option<Room>)> {
    let policy = ctx.options.memory;
    if !policy.limit_named {
        return Ok((
            First {
                first: None,
                rest: volumes,
            },
            None,
        ));
    }
    let Some(src) = volumes.volume(0)? else {
        return Ok((
            First {
                first: None,
                rest: volumes,
            },
            None,
        ));
    };
    let floor = crate::read::Archive::open(std::sync::Arc::clone(&src), &ctx.options)
        .ok()
        .map(|archive| {
            (
                archive.minimum_working_memory(&policy),
                archive.fixed_working_memory(&policy),
                archive.largest_member_need(&policy),
            )
        });
    let volumes = First {
        first: Some(src),
        rest: volumes,
    };
    let Some((minimum, fixed, largest)) = floor else {
        return Ok((volumes, None));
    };
    let stated = policy.working_limit.saturating_add(policy.process_overhead);
    if stated < minimum {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: crate::error::Resource::WorkingMemory,
            needed: minimum,
            limit: stated,
        }));
    }
    let windows = policy.working_limit.saturating_sub(fixed);
    // The workers the room above the largest member's need pays for at
    // their idle price, and always the one the floor guarantees.
    #[cfg(feature = "parallel")]
    let workers = 1 + usize::try_from(windows.saturating_sub(largest) / WORKER_IDLE_BYTES)
        .unwrap_or(usize::MAX);
    #[cfg(not(feature = "parallel"))]
    let workers = 1;
    Ok((
        volumes,
        Some(Room {
            windows,
            largest,
            workers,
        }),
    ))
}

/// What a NAMED budget leaves a read, from the pre-scan.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) struct Room {
    /// Engine working memory for the windows of the members in flight,
    /// beside what the walk holds whatever the member: the limit the
    /// pools price each member's declared window against.
    pub(crate) windows: u64,
    /// The largest member's need (`Archive::largest_member_need`), which
    /// the look-ahead reserves for the walk's own member.
    pub(crate) largest: u64,
    /// The most workers the room above the largest member's need pays
    /// for at [`WORKER_IDLE_BYTES`] each, at least one.
    pub(crate) workers: usize,
}

/// Volume 0 as the pre-scan fetched it, then the caller's provider.
pub(crate) struct First<V> {
    first: Option<std::sync::Arc<dyn crate::RangeSource>>,
    rest: V,
}

impl<V: Volumes> Volumes for First<V> {
    fn volume(&mut self, index: u32) -> Result<Option<std::sync::Arc<dyn crate::RangeSource>>> {
        match (index, &self.first) {
            (0, Some(src)) => Ok(Some(std::sync::Arc::clone(src))),
            _ => self.rest.volume(index),
        }
    }
}

/// The caller's sink, with the one answer no sink may give refused
/// (SPEC-API 4.4, spec F 3.8.1): `Write` for a redirection member. The
/// writer is dropped unwritten and the operation fails naming the member,
/// so a sink that was never taught about links cannot turn one into an
/// empty file. Every driver reaches the caller through this, whenever it
/// asks: the decode-ahead drivers ask at the member's turn.
pub(crate) struct Guarded<'a, K>(pub(crate) &'a mut K);

/// The refusal both guards raise.
pub(crate) fn refuse_write(member: &MemberInfo<'_>) -> Result<()> {
    match member.redirection {
        Some(redirection) => Err(Error::new(ErrorKind::Unsupported(Unsupported::Redirection(
            redirection.kind,
        )))
        .with_member(member.name)),
        None => Ok(()),
    }
}

impl<K: Sink> Sink for Guarded<'_, K> {
    type Out = K::Out;

    #[inline(always)]
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<K::Out>> {
        let disposition = self.0.open(member)?;
        if matches!(disposition, Disposition::Write(_)) {
            refuse_write(member)?;
        }
        Ok(disposition)
    }

    #[inline(always)]
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<K::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.close(member, out, outcome)
    }

    /// Passed through: a defaulted method a wrapper does not name would
    /// otherwise reach the caller as the default, silently.
    #[inline(always)]
    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.0.fragment_mismatch(member, volume)
    }
}

/// [`Guarded`] for the parallel entry point.
#[cfg(feature = "parallel")]
pub(crate) struct GuardedParallel<'a, S>(pub(crate) &'a S);

#[cfg(feature = "parallel")]
impl<S: crate::read::ParallelSink> crate::read::ParallelSink for GuardedParallel<'_, S> {
    type Out = S::Out;

    #[inline(always)]
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<S::Out>> {
        let disposition = self.0.open(member)?;
        if matches!(disposition, Disposition::Write(_)) {
            refuse_write(member)?;
        }
        Ok(disposition)
    }

    #[inline(always)]
    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<S::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.close(member, out, outcome)
    }

    /// Passed through, as [`Guarded`]'s is.
    #[inline(always)]
    fn fragment_mismatch(&self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.0.fragment_mismatch(member, volume)
    }
}

/// The one walk, whichever driver runs the decodes.
pub(crate) fn extract_driven<V: Volumes, D: Driver, P: Progress>(
    volumes: V,
    ctx: &mut ReadCtx,
    driver: &mut D,
    progress: &mut P,
) -> Result<ExtractReport> {
    let mut walking = Walking::begin(volumes, ctx)?;
    let outcome = walking.phase(driver, progress).map(|_| ());
    walking.finish(driver, progress, outcome)
}

/// A pool worker's own read window over the volume it decodes from, which
/// every worker holds beside its decoder (`read::concurrent`).
#[cfg(feature = "parallel")]
pub(crate) const WORKER_READ_BUF: usize = 64 * 1024;

/// What a scratch buffer is kept at between members under a NAMED budget
/// ([`Scratch::give_back`]): the stored copy's request size, so a stored
/// member of any size still copies through it without growing it.
pub(crate) const SCRATCH_KEEP: usize = STORED_REQUEST;

/// Whether a member continuing a solid chain keeps its [`Scratch`] for the
/// next ([`decode`]'s tail): yes, unless `RARKIT_CHAIN_SCRATCH_KEEP` is
/// `0`, which restores the give-back after every member for a measuring
/// arm. Read once.
fn keeps_chain_scratch() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        crate::knob::reader_var_os("RARKIT_CHAIN_SCRATCH_KEEP").is_none_or(|v| v != "0")
    })
}

/// What a pool worker holds IDLE between members under a NAMED budget,
/// whatever its last member was: the floor ring
/// (`rar5_lz::output::RING_FLOOR`, which a member's reach never sizes
/// below), its scratch at [`SCRATCH_KEEP`] (packed and copy), its read
/// window, and the decoder tables. The room a named budget leaves above
/// the largest member's need is spent on workers at this price
/// ([`budget_floor`]): a per-member admission cannot see a per-worker
/// cost, and twenty idle workers at their high-water held more than the
/// limit before any member was priced.
#[cfg(feature = "parallel")]
pub(crate) const WORKER_IDLE_BYTES: u64 = (crate::rar5_lz::output::RING_FLOOR
    + crate::rar5_lz::output::SPILL
    + 2 * SCRATCH_KEEP
    + WORKER_READ_BUF
    + 256 * 1024) as u64;

/// One member, from its first fragment's header to its `close`.
#[allow(clippy::too_many_arguments)]
fn member<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &mut Vec<u8>,
    chain_started: &mut bool,
    decoders: &mut Decoders,
    cancel: Option<&AtomicBool>,
) -> Result<()> {
    let format = walk.format;
    let solid_archive = walk.solid_archive;
    name.clear();
    name.extend_from_slice(
        walk.arena()
            .get(file.name.start as usize..file.name.end as usize)
            .unwrap_or(&[]),
    );

    // A REDIRECTION member is never delivered as bytes (spec F 3.8.1), so
    // it takes its own path before anything below can build a decoder, a
    // job or a seam for it.
    if let Some(redirect) = file.redirect {
        return redirected(
            run,
            walk,
            gate,
            block,
            file,
            name,
            redirect,
            chain_started,
            decoders,
        );
    }

    // BUILT ONCE. `MemberInfo` is 168 bytes of seventeen fields read out
    // of the header, and it was built twice for every member: here for
    // the sink's `open`, and again at the close. For a member with ONE
    // fragment the two are field for field the same, because the close
    // reads the same header, the same data range and the same name - so
    // the one-fragment path below hands this very value back rather than
    // building a second (5.1 to 5.8 ns a member, measured).
    let info = info_of(name, file, &block.data);
    if file.encrypted {
        reading::quiesce(run, walk, file, format)?;
    }
    let disposition = run.driver.open(&info)?;
    let wanted = !matches!(disposition, Disposition::Skip);
    // The oldest writers have no per-member solid bit at all, so in a
    // solid archive of those generations every member but the first
    // continues the chain. Spec F 3.4.4 lists the RAR 1.3 container's four
    // flags and none of them is one; the RAR 1.5 container HAS the flag
    // (0x0010) and its writer never sets it. OBSERVED on the genuine
    // corpus: `fixtures/legacy/archives/d155_sol.rar` (DOS RAR 1.55, main
    // flags 0x0008) carries the bit on 0 of its 12 members, against 8 of 12
    // on `d250_sol.rar` (RAR 2.50) and 11 of 12 on the RAR 3.93, 4.20 and
    // 5.50 ones. Reading the member bit alone decodes every member of a
    // solid RAR 1.5 archive from a cleared model, which fails on the second
    // one (`TABLE.BIN`: `Corrupt(Stream)`, a match past the member's size).
    //
    // RAR 5 FIRST, because its `unpack_version` is the compression
    // version (0 or 1), which the RAR 1.5 test below also matches: every
    // RAR 5 member after the first then continued the chain whatever its
    // own bit said, so a member with the bit CLEAR decoded against the
    // window of the chain before it (fuzz, 27 Sep 2026,
    // `fuzz/findings-27sep/solid-chain-break-continues.rar`). Spec F 3.6:
    // the chain starts at the most recent member with the bit clear.
    let solid_member = match format {
        Format::Rar5 => file.solid,
        Format::Rar13 => solid_archive && *chain_started,
        _ if file.unpack_version < 20 => solid_archive && *chain_started,
        _ => file.solid,
    };
    // An ORPHAN CHAIN START: the first member of a single archive or of
    // the first volume, its solid bit set, has no member before it to
    // continue and so begins a fresh stream, as a member with the bit
    // clear would (spec F 3.6, decided
    // 28 Sep 2026; the fuzz finds `orphan-chain-start-*.rar`, which
    // `unrar` 7.23 tests OK with their checksums verified).
    let solid_member = solid_member && !(walk.at_set_start && !*chain_started);
    let solid_chain = solid_archive && solid_member;
    // A solid chain whose first member is missing is not repairable: the
    // caller opened a LATER volume of a set and asked to extract, and
    // nothing here can rebuild the dictionary the chain needs (spec F 3.6).
    if solid_chain && !*chain_started {
        let err = Error::new(ErrorKind::Corrupt(Corruption::Stream));
        return refuse(run, walk, gate, block, file, name, err, !wanted);
    }
    if !solid_member {
        *chain_started = true;
    }

    let (codec, refused) = match codec_of(file, format, solid_archive) {
        Codec::Missing(kind) => (None, Some(kind)),
        other => (Some(other), None),
    };
    // A member the sink skips in an archive that is not solid is neither
    // taken nor needed: nothing would have decoded it, so that nothing
    // could is not the operation's error (unrar 7.23 exits 0), as a
    // skipped member's unusable encryption record never was. In a solid
    // archive the members behind it need it, and its refusal stands.
    let refused = refused.filter(|_| wanted || solid_archive);
    // A member refused here is never decoded, so the window lacks its
    // bytes and a member that continues the chain after it cannot be
    // decoded: the chain is broken as if its head were missing, and its
    // members fail `Corrupt(Stream)` until one with its bit clear starts
    // the next (spec F 3.2.6, decided 28 Sep 2026).
    if refused.is_some() && solid_archive {
        *chain_started = false;
    }
    // A non-solid member the sink skips is never read at all; a member of
    // a SOLID archive still costs its decode, because the member after it
    // may continue from its window and this walk cannot look ahead to find
    // out (spec F 3.6, 3.7.1). A refused member is not read either:
    // nothing here can decode it.
    //
    // The test `must_read` used to make was `solid_chain`, the member's OWN
    // solid bit, and that is the one member of a chain it is wrong for: the
    // member that STARTS the chain carries the bit clear, so a selection
    // that wanted only a later member skipped the start and decoded the
    // rest against a cleared model. On the genuine `r420_solid.rar` that
    // panicked in the text model rather than producing wrong bytes, which
    // is the only reason it was not a silent corruption
    // (`tests/selection.rs`).
    let must_read = refused.is_none() && (wanted || solid_archive);
    // ONE test for "its packed bytes are read" and "its key is fetched".
    // They were two, and the key's asked the member's own solid bit: the
    // skipped head of an encrypted chain was then read with no cipher, its
    // ciphertext decoded as a packed stream, and the operation ended there
    // (`tests/encrypted_solid_skip.rs`).
    let crypto = if must_read {
        let probe = Probe {
            block,
            solid_archive,
            continues: solid_chain || (solid_archive && file.unpacked_size == Some(0)),
            decoders: &mut *decoders,
        };
        match member_crypto(run, walk, file, format, Some(probe)) {
            Ok((cipher, mac)) => Some((cipher.map(MemberDecryptor::new), mac)),
            // A RAR 5 member of a SOLID archive that its password check
            // value refuses is withheld like any refused member, and is
            // still decoded for the members after it (spec K 3.7.3).
            Err(e) if solid_archive && check_refused(&e, format) => {
                let continues = solid_chain || (solid_archive && file.unpacked_size == Some(0));
                return refused_in_chain(
                    run, walk, gate, block, file, name, format, codec, continues, decoders, cancel,
                    e, !wanted,
                );
            }
            Err(e) => return refuse(run, walk, gate, block, file, name, e, !wanted),
        }
    } else {
        None
    };

    // The one place a member's decode may leave the walking thread, and it
    // is BEFORE the packed stream is opened: a member handed to a worker is
    // one the walk only SKIPS, because the worker reads that member's own
    // byte range from the volume it sits in. Nothing is read twice, and the
    // walk is free to reach the next header while the decode runs
    // (spec F 3.7.6, SPEC-API 4.4).
    let mut disposition = disposition;
    let mut codec = codec;
    let mut crypto = crypto;
    if offer(
        run,
        walk,
        gate,
        block,
        file,
        name,
        format,
        solid_archive,
        solid_chain,
        &mut disposition,
        &mut codec,
        &mut crypto,
    )? {
        return Ok(());
    }

    let out = match disposition {
        Disposition::Write(w) => Some(Out::Write(w)),
        Disposition::Verify => Some(Out::Verify),
        Disposition::Skip => None,
    };
    // A member that declares NO bytes neither starts a stream nor breaks
    // one: it produces nothing, so whether its writer meant a reset is
    // unobservable, and the members after it want the chain. The genuine
    // solid archives put empty members and directory entries in the middle
    // of a chain with their solid bit clear (`d250_sol.rar`'s
    // `EMPTY.DAT`), so reading that as a chain start clears the window
    // under the members that follow.
    //
    // ONLY in a solid archive. A non-solid archive has no chain to keep,
    // and every member there is independent (spec F 3.6): a zero byte
    // member that continued would decode its packed bytes in whatever
    // state the member before it left, and after a DAMAGED member that
    // state is a faulted stream, so an intact empty member failed with it.
    // Spec F section 0 item 12 says it is reported OK.
    let continues = solid_chain || (solid_archive && file.unpacked_size == Some(0));

    // THE SEAM of spec F 3.7.7: this member's read, decrypt, decode and
    // checksum on a scoped thread while this thread writes. It is a
    // choice and never a promise (SPEC-API 8.5), so everything below runs
    // the same member the same way when it is not taken.
    //
    // Except for a WRITTEN stored member the wide read takes, which is one
    // whose writer the caller says is NOT a file (`sink_is_file` of
    // `Some(false)`, `p` to a stream): there the read and the CRC32 go
    // wide and this thread writes in piece order (`copy`, `read::wide`),
    // which overlaps the read with the write as the seam does and spreads
    // the read besides, where the seam's source unit is one thread.
    //
    // And except for an ENCRYPTED stored member, whose serial
    // read is its cipher: it goes wide to a file as well where
    // `cipher_to_file` says so, deciphered piece by piece.
    #[cfg(feature = "parallel")]
    let cipher = crypto
        .as_ref()
        .and_then(|(cipher, _)| cipher.as_ref())
        .map(|cipher| cipher.is_cbc());
    #[cfg(feature = "parallel")]
    let wide_written = matches!(out, Some(Out::Write(_)))
        && (run.sink_is_file == Some(false) || (cipher == Some(true) && cipher_to_file()))
        && wide_takes(
            codec.as_ref(),
            file,
            format,
            cipher == Some(false),
            cipher.is_none(),
            decoders.decode_width.max(1),
            run.policy.read_ahead,
        );
    // And except for a CLEAR stored member checked by BLAKE2sp that this
    // thread writes to a file, where `read::handed::b2sp_cut_walk` says so:
    // it is cut here as a pool worker cuts its own (one reader in order,
    // the hasher on a lane behind it, this thread writing), where the
    // seam's source unit reads AND hashes on one thread. Not where the
    // caller says its writer is a stream, and not on the solid path, whose
    // writer takes ranges itself. And only a member WHOLE IN ONE VOLUME:
    // the cut takes each fragment as a range of its own and starts its
    // reader and hasher again at every one, where the seam's source reads
    // on across the boundary (counted on 2 Oct 2026, a big member across 100 MiB
    // volumes, warm on a Zen 4: 0.940x of the seam; 1 GiB volumes 0.980x).
    #[cfg(feature = "parallel")]
    let hashed_cut = matches!(out, Some(Out::Write(_)))
        && must_read
        && cipher.is_none()
        && run.sink_is_file != Some(false)
        && !file.split_before
        && !file.split_after
        && matches!(codec, Some(Codec::Stored))
        && matches!(file.checksum, Some(Checksum::Blake2sp(_)))
        && !matches!(format, Format::Rar13)
        && file
            .unpacked_size
            .is_some_and(|n| n >= crate::read::wide::FLOOR)
        && crate::read::wide::plan(decoders.decode_width.max(1), run.policy.read_ahead).is_some()
        && crate::read::handed::b2sp_cut_walk()
        && crate::read::handed::b2sp_cut().is_some()
        && crate::read::handed::walk_hashed_cut().is_some()
        && run.driver.hand_over().is_none();
    #[cfg(feature = "parallel")]
    let overlap = !wide_written
        && !hashed_cut
        && must_read
        && run.driver.overlaps()
        && codec.as_ref().is_some_and(|codec| {
            seam::engages(
                out.as_ref(),
                file,
                block,
                &run.policy,
                decoders.decode_width.max(1),
                run.sink_is_file,
                codec,
                seam::lends(codec, file, cipher.is_none()),
            )
        });
    #[cfg(not(feature = "parallel"))]
    let overlap = false;

    // `mut` only where the seam can take it: without `parallel` the
    // branch below is compiled away and nothing ever moves out of it.
    #[cfg_attr(not(feature = "parallel"), allow(unused_mut))]
    let mut out = out;
    if overlap {
        #[cfg(feature = "parallel")]
        {
            let Some(unit) = out.take() else {
                unreachable!("`engages` answers true only for a written or verified member")
            };
            let keys = crypto.as_ref().and_then(|(_, keys)| keys.clone());
            let decryptor = crypto.map(|(cipher, _)| cipher).unwrap_or(None);
            let policy = run.policy;
            let overlapped = seam::overlapped(
                walk,
                gate,
                block,
                file,
                name,
                format,
                unit,
                run.sink_is_file,
                seam::Work {
                    codec: codec.take().expect("checked by `overlap`"),
                    decryptor,
                    keys,
                    continues,
                },
                &mut run.blake,
                decoders,
                &mut run.scratch,
                &policy,
                &mut run.bytes,
                &mut run.output_since_tick,
                cancel,
            )?;
            match overlapped {
                seam::Seamed::Ran(overlapped) => {
                    let mut member = overlapped.member;
                    member.in_set = walk.in_set;
                    return settle(
                        run,
                        walk,
                        gate,
                        overlapped.landed,
                        member,
                        file,
                        name,
                        refused,
                    );
                }
                // No thread for the source unit: the member takes the
                // path below, which is the one it takes with no seam.
                seam::Seamed::NoThread { out: unit, work } => {
                    out = Some(unit);
                    codec = Some(work.codec);
                    crypto = Some((work.decryptor, work.keys));
                }
            }
        }
    }

    // THE SOLID CHAIN'S LOOKAHEAD (SPEC-H2 3.8, `read::ahead`): the
    // volume by handle, and the first byte past this member, which is
    // where the header of the next one begins. Built before the walk is
    // borrowed for the member's own stream.
    #[cfg(feature = "parallel")]
    let feed =
        if crate::read::ahead::wanted(format, solid_archive, file.split_before || file.split_after)
        {
            walk.shared_source().map(|source| crate::read::ahead::Feed {
                source,
                volume: walk.volume,
                from: block.end(),
                declared: file.unpacked_size,
            })
        } else {
            None
        };
    #[cfg(not(feature = "parallel"))]
    let feed: Option<()> = None;

    let in_set = walk.in_set;
    let mut stream = MemberStream::new(walk, gate, block, file, name);
    stream.check_leading_fragment()?;
    let mut member = Member::of(
        out,
        file,
        format,
        crypto.as_ref().and_then(|(_, keys)| keys.clone()),
        &mut run.blake,
        blake_workers(&run.policy, decoders),
    );
    member.in_set = in_set;
    #[cfg(feature = "parallel")]
    {
        member.wide_write = run.sink_is_file == Some(false);
        member.volumes_present = run.volumes_present;
        member.hand_over = run.driver.hand_over();
        // The walk's own encrypted stored member, written from this
        // thread: cut here (`read::handed`), unless the caller says its
        // writer is NOT a file (`p` to a stream, whose wide read is the
        // whole width's). A caller that says nothing is `rarfast x` of a
        // set that is not solid, and a writer that is no file loses
        // nothing to pieces that start on a page. A driver whose writer
        // takes ranges itself leads to another thread, where the member's
        // key does not go.
        if run.sink_is_file != Some(false)
            && member.hand_over.is_none()
            && crate::read::handed::stored_cut().is_some()
            && crate::read::handed::stored_cut_cipher()
        {
            member.hand_cipher = Some(crate::read::handed::cut_cipher_here::<D::Out>);
        }
        // The walk's own clear BLAKE2sp member, cut here (`hashed_cut`).
        if hashed_cut {
            member.hand_hashed = Some(crate::read::handed::cut_hashed_here::<D::Out>);
        }
    }

    let outcome = match (must_read, codec) {
        (true, Some(codec)) => {
            let decryptor = crypto.map(|(cipher, _)| cipher).unwrap_or(None);
            let policy = run.policy;
            let mut tally = Ticker {
                bytes: &mut run.bytes,
                base: run.base,
                since: &mut run.output_since_tick,
                gate,
                cancel,
            };
            decode(
                &mut stream,
                &mut member,
                &mut run.blake,
                &mut tally,
                decryptor,
                codec,
                decoders,
                &mut run.scratch,
                &policy,
                continues,
                feed.as_ref(),
            )
        }
        _ => stream.skip(),
    };
    let landed = land(stream, outcome, &mut run.scratch);
    // THE ONE-FRAGMENT PATH. `later` is `None` exactly when no
    // continuation header replaced the first, which is when the caller's
    // own header, data range and name are still the close's (spec F
    // 3.5.6, and the same reading the borrowed `first` rests on).
    if landed.later.is_none() {
        let Landed {
            outcome,
            broken,
            fragment_mismatches,
            data,
            name_span,
            later: _,
            passed,
        } = landed;
        // The three things `info` would have been rebuilt from, checked
        // in every debug build rather than argued for: a later change that
        // makes any of them move for an unsplit member fails here
        // instead of reporting the wrong member through `close`.
        debug_assert_eq!(
            data, block.data,
            "a member with one fragment ends in the block it started in"
        );
        debug_assert_eq!(
            name_span, file.name,
            "a member with one fragment closes on the header it opened with"
        );
        // A member whose remaining fragments were passed over stands in
        // another volume than `data` names, which the walk has released.
        if passed {
            let closed = close_member(
                run,
                member,
                file,
                &info,
                refused,
                &fragment_mismatches,
                outcome,
                broken,
            );
            return after_passing(walk, closed);
        }
        walk.release(gate, data.end)?;
        return close_member(
            run,
            member,
            file,
            &info,
            refused,
            &fragment_mismatches,
            outcome,
            broken,
        );
    }
    settle(run, walk, gate, landed, member, file, name, refused)
}

/// Report one member, whichever unit decoded it.
///
/// The walk is positioned after the member's last fragment and the member
/// carries the caller's own writer: from here the sequential path and the
/// seam of 3.7.7 are the same code, which is what keeps their `close`
/// identical.
#[allow(clippy::too_many_arguments)]
fn settle<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    landed: Landed,
    member: Member<D::Out>,
    first: &FileHdr,
    name: &mut Vec<u8>,
    refused: Option<ErrorKind>,
) -> Result<()> {
    let Landed {
        outcome,
        broken,
        fragment_mismatches,
        later,
        data,
        name_span: span,
        passed,
    } = landed;
    // The LAST fragment's header, which for a member with one fragment is
    // the one the caller already holds (spec F 3.5.6).
    let last = later.as_deref().unwrap_or(first);
    // And its name is the name already read: only a member that CONTINUED
    // has a different header, and so a different name span, from the one
    // `member` read out of the arena on the way in. Re-reading it for every
    // member of a 20,000 member archive cost a measured 4.3 ns each
    // (the stored TEST legs).
    // A member whose remaining fragments were passed over closes on the
    // name it opened with, which every fragment of it carries: the arena
    // in hand is another volume's by now.
    if !passed && later.is_some() {
        name.clear();
        name.extend_from_slice(
            walk.arena()
                .get(span.start as usize..span.end as usize)
                .unwrap_or(&[]),
        );
    } else if !passed {
        // THE INVARIANT THE SKIP RESTS ON, checked in every debug build:
        // the name in the buffer is this member's name, because `member`
        // read it out of the arena from the same span on the way in and
        // nothing between the two writes that buffer. A later change that
        // gives the walking thread another use for it fails here rather
        // than reporting the wrong member's name through `close`.
        //
        // The arena is asked only where it still HAS those bytes. A walk
        // that broke has closed the volume the name lived in, and the old
        // code, which re-read the arena unconditionally, reported an EMPTY
        // name for such a member; this one reports the name it read. That
        // is a difference and it is an improvement, so it is stated rather
        // than hidden: `containers::a_set_handed_over_out_of_order_is_corrupt`
        // is the case, and its error now names `rand.bin` instead of
        // nothing.
        debug_assert!(
            walk.arena()
                .get(span.start as usize..span.end as usize)
                .is_none_or(|held| held.is_empty() || held == name.as_slice()),
            "the name buffer must still hold this member's name at close"
        );
    }
    // The bytes of the last fragment are released whatever the outcome;
    // the walk that passed over a member's remaining fragments has done so.
    if !passed {
        walk.release(gate, data.end)?;
    }
    let info = info_of(name, last, &data);
    let closed = close_member(
        run,
        member,
        last,
        &info,
        refused,
        &fragment_mismatches,
        outcome,
        broken,
    );
    if passed {
        return after_passing(walk, closed);
    }
    closed
}

/// Report one member through the driver, from a `MemberInfo` the caller
/// has already built.
///
/// **Both closes go through here**, which is what keeps them identical:
/// the general path of [`settle`], which builds a fresh `MemberInfo` for
/// the LAST fragment's header, and the one-fragment path in [`member`],
/// which hands back the very `MemberInfo` the sink's `open` was given.
/// That reuse is the point: `MemberInfo` is 168 bytes of seventeen
/// fields read out of a header, `info_of` was measured at 5.1 to 5.8
/// nanoseconds a member on an Apple M3 Mac, and it ran TWICE for every member
/// of a 20,000 member archive although the two were field for field the
/// same.
#[allow(clippy::too_many_arguments)]
fn close_member<D: Driver>(
    run: &mut Run<'_, D>,
    member: Member<D::Out>,
    last: &FileHdr,
    info: &MemberInfo<'_>,
    refused: Option<ErrorKind>,
    fragment_mismatches: &[u32],
    outcome: Result<()>,
    broken: bool,
) -> Result<()> {
    // A walk that broke inside the member ends the operation with no
    // `close`, so nothing is said of its fragments either; nor of a member
    // the caller skipped, whose output is the one thing a member reaching
    // here can lack (every writer and `Verify` travels with its member,
    // the seam's included), and which hears nothing more at all
    // ([`Driver::skipped`]).
    let skipped = member.out.is_none();
    let mismatches = match &outcome {
        Err(e) if broken || ends_operation(e) => 0,
        _ if skipped => 0,
        _ => report_mismatches(run, info, fragment_mismatches)?,
    };
    match outcome {
        Ok(()) => finish(run, member, last, info, refused, mismatches),
        // A MEMBER THAT DECLARES NO BYTES IS NOT FAILED BY ITS PACKED
        // BYTES (spec F 3.6.3 item 4). They are read,
        // because the member after it depends on them, but its own outcome
        // is its checksum's against the zero bytes it produced: reference
        // unrar 7.23 passes `r420_solid.rar`'s `EMPTY.DAT` with its two
        // bytes replaced, where RAR 3's decoder may refuse a symbol among
        // them by its own strict rules (spec H1 3.8). What the decoder is
        // left holding for the next member is unchanged by this.
        //
        // ONE verdict is the member's own all the same (spec F 3.6.3 item
        // 4, spec H2 3.1): `FilterRange`, which the RAR 5 decoder raises
        // for a member of zero bytes only where the member carries a
        // checksum and its stream completes a kept filter span, as for
        // any other member. With no checksum the decoder passes it, and
        // so does the reference. It is asked last, so it costs a member
        // that passed nothing and one that failed a single compare.
        // The RAR 3 decoder says the same of a span its stream
        // completed past the declared size (spec J 3.8), by the member's
        // own mark: its error is `Corrupt`, record, as a damaged record's
        // is, and that one is not this member's.
        Err(e)
            if member.unpacked_size == Some(0)
                && member.written == 0
                && !broken
                && decoder_verdict(&e)
                && !span_past_the_member(&e)
                && !member.span_left_member =>
        {
            finish(run, member, last, info, refused, mismatches)
        }
        Err(e) => {
            // A member that failed mid-decode is still reported through its
            // own `close`, with its own outcome, before extraction moves on
            // (spec F 8). Only an error that belongs to the CALLER or that
            // ends the whole operation is raised straight away.
            if broken || ends_operation(&e) {
                return Err(e);
            }
            let value = match member.out {
                Some(Out::Write(w)) => Some(w),
                _ => None,
            };
            let named = e.with_member(info.name);
            close_or_skip(
                run,
                skipped,
                info,
                value,
                &MemberOutcome {
                    checksum_ok: Some(false),
                    bytes: member.written,
                    password_refused: crate::read::password_refused(Some(&named)),
                    fragment_mismatches: mismatches,
                },
                Some(named),
            )
        }
    }
}

/// The member's `close`, or, for one the caller skipped, its count alone
/// ([`Driver::skipped`]).
fn close_or_skip<D: Driver>(
    run: &mut Run<'_, D>,
    skipped: bool,
    info: &MemberInfo<'_>,
    value: Option<D::Out>,
    outcome: &MemberOutcome,
    err: Option<Error>,
) -> Result<()> {
    if skipped {
        run.driver.skipped(info, outcome, err)
    } else {
        run.driver.close(info, value, outcome, err)
    }
}

/// Whether an error is a decoder's verdict on a member's packed bytes, and
/// nothing else: not a header's, a source's, a cipher's or the caller's.
/// The member's packed bytes running out under the decoder is one too
/// (spec F 3.6.3 item 4: whatever the decoder met in them).
fn decoder_verdict(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Truncated
            | ErrorKind::Corrupt(
                Corruption::Stream
                    | Corruption::FilterRecord
                    | Corruption::FilterParameters
                    | Corruption::Ppmd(_)
                    | Corruption::Rar3(_)
                    | Corruption::Rar5(_)
                    | Corruption::Rar20(_)
            )
    )
}

/// The one decoder verdict a member of zero bytes is failed for: a kept
/// RAR 5 filter span that the decoder refuses (spec H2 3.1 says which).
fn span_past_the_member(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Corrupt(Corruption::Rar5(Rar5Fault::FilterRange))
    )
}

/// Whether an error ends the whole operation rather than one member. A
/// source that failed, a caller that failed, the cancel flag, a limit and a
/// broken volume set are all the operation's; a decoder's verdict on one
/// member's bytes is that member's.
///
/// ONE limit is a member's and not the operation's: a packed block the
/// budget does not hold beside the member's window
/// (`Resource::BlockBuffer`; SPEC-API 8.4.1, the account's item 7). It is
/// met inside the member, at that block, so the member is closed failed
/// with it, the bytes delivered before the block counted, and the read
/// goes on to the next member where the format lets it.
pub(crate) fn ends_operation(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Source(_)
            | ErrorKind::Caller
            | ErrorKind::Cancelled
            | ErrorKind::Corrupt(Corruption::VolumeSet)
            | ErrorKind::PasswordRequired
            | ErrorKind::WrongPassword
    ) || matches!(
        err.kind(),
        ErrorKind::LimitExceeded { resource, .. }
            if !matches!(resource, crate::error::Resource::BlockBuffer)
    )
}

/// The cipher a member's own encryption record selects, or `None` when the
/// member is not encrypted. Spec K owns every cipher; this package finds
/// the salts, initialisation vectors and check records and calls it.
///
/// `probe` is what a RAR 3 member whose data alone is encrypted needs to
/// find the session's reading of the password before its key is fetched
/// ([`reading::settle`]); `None` where the member is not decoded.
#[allow(clippy::type_complexity)]
fn member_crypto<V: Volumes, D: Driver>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    file: &FileHdr,
    format: Format,
    probe: Option<Probe<'_>>,
) -> Result<(Option<MemberCipher>, Option<Rar5Keys>)> {
    if !file.encrypted {
        return Ok((None, None));
    }
    if matches!(format, Format::Rar5) {
        let record = file
            .crypt
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Corrupt(Corruption::Header)))?;
        // A record the header parse kept although it cannot key the
        // member: this member's refusal, and no other's.
        if let Some(refusal) = record.refusal() {
            return Err(refusal);
        }
        let iv = record
            .iv
            .ok_or_else(|| Error::new(ErrorKind::Corrupt(Corruption::Header)))?;
        // The context is split rather than the password cloned: the key
        // cache wants `&mut` and the password `&`, and taking a copy of the
        // password to satisfy that is an allocation per encrypted member
        // (API promise 2.4).
        let crate::read::reader::ReadCtx {
            options,
            keys: cache,
            ..
        } = walk.ctx();
        let password = options
            .password
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::PasswordRequired))?;
        // Judged against the member's check record before a byte is
        // deciphered, under the second cut of a long password where the
        // first does not fit (spec K 3.7.1, 3.7.3).
        let keys = cache.rar5_judged(password, &record.salt, record.log2, record.check.as_ref())?;
        // The keys travel with the member whether or not THIS fragment's
        // record sets the MAC flag: on a split member only the last
        // fragment's does (see `finish`). They are 72 bytes of arrays and
        // are carried inline: a box per member is an allocation per member
        // (API promise 2.4).
        // The schedule does NOT travel: the cipher borrows the cache's
        // (`MemberCipher::aes256_on`), and the carried keys stay the 72
        // bytes they were.
        let carried = keys.keys().clone();
        return Ok((Some(MemberCipher::aes256_on(keys, &iv)), Some(carried)));
    }
    // Spec B 3.2: a password with a character outside the basic plane has
    // two genuine readings, and data that is encrypted under headers that
    // are not says which only by its checksum. Asked here, where only an
    // encrypted member of this family comes, and answered no at once for
    // every other password.
    reading::settle(run, walk, file, format, probe)?;
    let version = u8::try_from(file.unpack_version).unwrap_or(u8::MAX);
    let crate::read::reader::ReadCtx {
        options,
        keys: cache,
        ..
    } = walk.ctx();
    let password = options
        .password
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::PasswordRequired))?;
    if matches!(format, Format::Rar13) {
        // Spec K 3.2: in the RAR 1.3 and 1.4 container the encrypted flag
        // selects the RAR 1.3 stream cipher by the ARCHIVE's generation.
        // The unpack version selects it in every LATER container, and that
        // container's version is 2, which names no cipher of its own.
        return Ok((
            Some(MemberCipher::V13(Rar13Stream::new(password.as_bytes()))),
            None,
        ));
    }
    // The cipher is built on the cache's own schedule, borrowed for the
    // call: nothing of the key is copied out but the chain's own copy.
    let key = if version >= 29 {
        Some(cache.rar4_cipher(password, file.rar4_salt)?)
    } else {
        None
    };
    Ok((
        Some(rar4_family_cipher_on(version, password.as_bytes(), key)?),
        None,
    ))
}

/// Report a member that cannot even be opened through its OWN close, count
/// it, and remember the error for the end of the operation. Its packed
/// bytes are skipped, across volumes where it is split.
#[allow(clippy::too_many_arguments)]
fn refuse<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    err: Error,
    skipped: bool,
) -> Result<()> {
    {
        let mut stream = MemberStream::new(walk, gate, block, file, name);
        stream.skip()?;
    }
    let info = info_of(name, file, &block.data);
    let named = err.with_member(info.name);
    close_or_skip(
        run,
        skipped,
        &info,
        None,
        &MemberOutcome {
            checksum_ok: Some(false),
            bytes: 0,
            password_refused: crate::read::password_refused(Some(&named)),
            fragment_mismatches: 0,
        },
        Some(named),
    )
}

/// Whether `err` is a RAR 5 password check record refusing the password
/// (spec K 3.7.3): the one way a RAR 5 member's keys answer
/// `WrongPassword`, a missing password being `PasswordRequired`.
fn check_refused(err: &Error, format: Format) -> bool {
    matches!(format, Format::Rar5) && matches!(err.kind(), ErrorKind::WrongPassword)
}

/// A member of a SOLID RAR 5 archive whose password check value refused
/// the password: withheld, and still decoded for the chain (spec K 3.7.3,
/// "A refused member inside a solid chain", 8 Oct 2026).
///
/// The refusal is reported first and exactly as [`refuse`] reports it:
/// no byte delivered, `WrongPassword`, the member's own `close` or, for
/// one the caller skipped, its count. Then its packed data is deciphered
/// under the key the password and the member's own record derive, which
/// the check value does not enter, and decoded with its output discarded,
/// as a skipped member of a chain is, so that the members after it find
/// the window their writer left. The reference does the same: the
/// refused member alone is named and every later member whose own check
/// passes comes out right. Closed undecoded, as it was, every later
/// member of the chain failed its checksum.
///
/// What that decode meets is nobody's verdict: the member is already
/// reported. If the password really is wrong the bytes are noise, the
/// decode ends at once on whatever it meets, and the members that lean
/// on it fail their own checksums, as members after a damaged one do.
/// Only what ends the OPERATION leaves here as an error: the source, the
/// caller's cancel, a limit, a broken volume set.
///
/// Out of line and cold: reached only from a member already refused.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn refused_in_chain<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    format: Format,
    codec: Option<Codec>,
    continues: bool,
    decoders: &mut Decoders,
    cancel: Option<&AtomicBool>,
    err: Error,
    skipped: bool,
) -> Result<()> {
    // The key, not judged: the cache derived it when the check was made,
    // so this is a lookup. Without the record's fields, or a codec, there
    // is nothing to decode with and the member is refused as it was.
    let cipher = {
        let crate::read::reader::ReadCtx {
            options,
            keys: cache,
            ..
        } = walk.ctx();
        match (&file.crypt, options.password.as_ref()) {
            (Some(record), Some(password)) => record.iv.and_then(|iv| {
                cache
                    .rar5_cipher(password, &record.salt, record.log2)
                    .ok()
                    .map(|keys| MemberCipher::aes256_on(keys, &iv))
            }),
            _ => None,
        }
    };
    let (Some(cipher), Some(codec)) = (cipher, codec) else {
        return refuse(run, walk, gate, block, file, name, err, skipped);
    };
    let info = info_of(name, file, &block.data);
    let named = err.with_member(info.name);
    close_or_skip(
        run,
        skipped,
        &info,
        None,
        &MemberOutcome {
            checksum_ok: Some(false),
            bytes: 0,
            password_refused: crate::read::password_refused(Some(&named)),
            fragment_mismatches: 0,
        },
        Some(named),
    )?;
    let mut stream = MemberStream::new(walk, gate, block, file, name);
    stream.check_leading_fragment()?;
    // No output and no checksum: a member the sink skipped, to the decode.
    let mut member: Member<D::Out> = Member::of(
        None,
        file,
        format,
        None,
        &mut run.blake,
        blake_workers(&run.policy, decoders),
    );
    let policy = run.policy;
    let outcome = {
        let mut tally = Ticker {
            bytes: &mut run.bytes,
            base: run.base,
            since: &mut run.output_since_tick,
            gate,
            cancel,
        };
        decode(
            &mut stream,
            &mut member,
            &mut run.blake,
            &mut tally,
            Some(MemberDecryptor::new(cipher)),
            codec,
            decoders,
            &mut run.scratch,
            &policy,
            continues,
            None,
        )
    };
    let landed = land(stream, outcome, &mut run.scratch);
    if landed.passed {
        return after_passing(walk, Ok(()));
    }
    walk.release(gate, landed.data.end)?;
    match landed.outcome {
        Err(e) if landed.broken || ends_operation(&e) => Err(e),
        _ => Ok(()),
    }
}

pub(crate) fn info_of<'a>(
    name: &'a [u8],
    file: &FileHdr,
    data: &std::ops::Range<u64>,
) -> MemberInfo<'a> {
    MemberInfo {
        name,
        is_directory: file.is_directory,
        unpacked_size: file.unpacked_size,
        packed_size: data.end - data.start,
        split_before: file.split_before,
        split_after: file.split_after,
        encrypted: file.encrypted,
        password_checked: file.encrypted && file.crypt.as_ref().is_some_and(|c| c.check.is_some()),
        mtime: file.mtime,
        attributes: file.attributes,
        host_os: file.host_os,
        checksum: file.checksum,
        method: file.method,
        dictionary: file.dictionary,
        solid: file.solid,
        algorithm_version: file.unpack_version,
        data: data.clone(),
        // The target is the caller's to add where it has it: the
        // redirection path hands it to `open` (spec F 3.8.1).
        redirection: file.redirect.map(|r| Redirection {
            kind: r.kind(),
            target: None,
            target_is_directory: r.dir,
        }),
        file_version: file.file_version(),
    }
}

/// A redirection member the sink skipped: its data area is passed over.
/// It has no `close`; its count is `links::skip_unread`'s.
fn pass_unread<V: Volumes, P: Progress>(
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
) -> Result<()> {
    let mut stream = MemberStream::new(walk, gate, block, file, name);
    let skipped = stream.skip();
    let broken = stream.broken;
    let data = stream.data.clone();
    drop(stream);
    skipped?;
    if !broken {
        walk.release(gate, data.end)?;
    }
    Ok(())
}

/// A redirection member refused after its `open`: its data area passed
/// over unread, and the member closed failed with `err`, which is how
/// every member-level refusal is reported (spec F section 8).
#[allow(clippy::too_many_arguments)]
fn close_unread<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    info: &MemberInfo<'_>,
    out: Option<Out<D::Out>>,
    err: Error,
) -> Result<()> {
    {
        let mut stream = MemberStream::new(walk, gate, block, file, info.name);
        stream.skip()?;
    }
    let value = match out {
        Some(Out::Write(w)) => Some(w),
        _ => None,
    };
    let err = err.with_member(info.name);
    run.driver.close(
        info,
        value,
        &MemberOutcome {
            checksum_ok: Some(false),
            bytes: 0,
            password_refused: crate::read::password_refused(Some(&err)),
            fragment_mismatches: 0,
        },
        Some(err),
    )
}

/// The integrity verdict of one member, from the checksums it ran and the
/// LAST fragment header's recorded value.
///
/// Free of the walk and of the sink, so the concurrent driver's workers
/// reach exactly this arithmetic: a verdict computed twice in two places is
/// a verdict that can differ between the two paths, which SPEC-API 4.4
/// forbids.
pub(crate) fn verdict<W>(
    member: &Member<W>,
    blake_state: &mut Option<Box<Blake2sp>>,
    file: &FileHdr,
    refused: bool,
) -> Option<bool> {
    // Spec K 3.7.4's MAC conversion applies when the member's encryption
    // record says so, and on a SPLIT member that is the LAST fragment's
    // record: OBSERVED on the corpus's `rar50/encrypted_multivol.part*`,
    // whose leading fragments carry crypt flags 0x0001 (password check
    // only) and whose last carries 0x0003 (check and MAC), over one salt
    // and one cipher chain. Reading the flag from the first fragment makes
    // every split encrypted member fail a checksum whose bytes are right.
    // The checksum itself is the last fragment's (spec F 3.5.6), and so is
    // the flag that says how to compare it.
    let mac = member
        .keys
        .as_ref()
        .filter(|_| file.crypt.as_ref().is_some_and(|record| record.mac()));
    if refused {
        return Some(false);
    }
    // A member the sink skipped ran no checksum, so it has no verdict.
    // A leading fragment whose own field disagreed is NOT a verdict: the
    // member is judged by its whole checksum alone (spec F 3.5.6, 29 Sep
    // 2026), and the disagreement reaches the sink as a diagnostic.
    member.out.as_ref()?;
    // A MEMBER THAT ENDS SHORT (spec F 4.2, restated 8 Oct 2026). Its
    // data came to a valid end before its declared size, which no genuine
    // writer was seen to make. When it carries a checksum it is judged by
    // it against the bytes produced, as the reference judges it: a match
    // is the writer's own statement about exactly those bytes, and the
    // member is good with fewer bytes than it declared. When it carries
    // none it is never good, where the reference does not judge it:
    // nothing vouches for the short file. And in an archive that is a
    // VOLUME of a set it is never good whatever its checksum says (rule
    // 6, 9 Oct 2026): there a header's checksum can be a fragment's, of
    // a member whose "continues" flag was lost, and nothing at the
    // member tells the two apart; the reference writes the short file
    // and calls it good. The checksum is run to its end below either
    // way, since the BLAKE2sp state is one per operation and
    // must be left ready for the next member.
    //
    // A REDIRECTION member is not one: a hard link or a file copy declares
    // its target's size and carries no data of its own (spec F 3.8.1), so
    // it produces nothing and is whole.
    //
    // DECLARED is the LAST header's size where it has one (spec F 3.5.4:
    // "the size and the checksum of a split member are its last
    // fragment's header's"), and the size the member was built with
    // otherwise. The two are one number wherever the join check compared
    // them, which is every split member but one whose leading header
    // declares 4,294,967,295 in the older container (`walk.rs`).
    let short = file.redirect.is_none()
        && file
            .unpacked_size
            .or(member.unpacked_size)
            .is_some_and(|declared| member.written < declared);
    // WHAT WAS RUN is the first header's choice (`Member::of`), and the
    // value to meet is the last header's (spec F 3.5.6). On a split member
    // the two can name different kinds, which no genuine writer was seen
    // to make. Then nothing computed here can be compared with the stored
    // value and the member FAILS, whatever its bytes (10 Oct 2026): a
    // BLAKE2sp last header behind a first that armed CRC32 had no verdict,
    // which a caller reads as good, and a CRC32 last header behind a first
    // that armed BLAKE2sp was compared with a register nothing had fed,
    // which finishes as 0. rar and unrar 7.23 fail both pairs too; behind
    // a BARE first header they judge nothing and call a BLAKE2sp member
    // good with a byte changed, which is not followed
    // (`tests/split_checksum_kind.rs`). `checked` and not `crc_wanted`:
    // the CRC32 may be out with another unit and back by now.
    let ran_crc = member.checked && !member.blake;
    let matches = match file.checksum {
        Some(Checksum::Crc32(_)) if !ran_crc => Some(false),
        Some(Checksum::Blake2sp(_)) if !member.blake => Some(false),
        Some(Checksum::Crc32(stored)) => {
            let computed = member.crc.finish();
            let computed = match &mac {
                Some(keys) => keys.stored_word_under_key(computed),
                None => computed,
            };
            Some(computed == stored)
        }
        Some(Checksum::Blake2sp(stored)) => {
            blake_state.as_mut().map(|b| {
                // Finalised IN PLACE: the operation keeps its one
                // hasher and its one stage, where taking the digest by
                // value would copy the stage once per member.
                let digest = b.finalize_reset();
                let digest = match &mac {
                    Some(keys) => keys.mac_digest(&digest),
                    None => digest,
                };
                digest == stored
            })
        }
        // The first header NAMED a kind, which was run, and the last
        // names none: there is nothing to meet it, and a member that was
        // to be checked is never good unchecked (10 Oct 2026). Only a
        // split member's two headers can part like this. The reference
        // prints ` ?` for it and exits 0, a changed byte or not; here it
        // fails. A member NEITHER of whose headers names one is the
        // ordinary member without a checksum, below.
        None if member.named => Some(false),
        // RAR 1.3 reports no checksum through the API, so it is
        // verified internally: a damaged member still fails
        // (spec F 3.4.3).
        None => member.sum16.map(|s| s.finish() == file.raw_checksum as u16),
    };
    // A SIZE THAT ONLY THE LAST HEADER DECLARES (spec F 3.5.4 J5, 10 Oct
    // 2026). A member genuine rar read from standard input and split has
    // the unknown size flag on every fragment header but the last, so it
    // was built with no size and decoded to the end of its packed data;
    // its size is the last header's, and bytes delivered that are fewer
    // or more than that are a failed member whatever its checksum says.
    // The reference lets no size field into its verdict. Only a split
    // member's first and last headers can part like this: for any other
    // `file` is the header the member was built from.
    let misses_late_size = file.redirect.is_none()
        && member.unpacked_size.is_none()
        && file
            .unpacked_size
            .is_some_and(|declared| member.written != declared);
    if misses_late_size || (short && (file.checksum.is_none() || member.in_set)) {
        Some(false)
    } else if matches.is_none() && file.unsound() {
        // Spec F 4.6 rule 4: a member under a header whose checksum
        // failed is good only by its own data checksum. With none,
        // nothing vouches for its size, its method or its data.
        Some(false)
    } else {
        matches
    }
}

/// Tell the driver, before a member's `close`, of each leading fragment
/// whose packed CRC32 disagreed with its header's field (spec F 3.5.6, API
/// 4.4), in the order the fragments ended, and count them for the
/// member's `MemberOutcome::fragment_mismatches`.
fn report_mismatches<D: Driver>(
    run: &mut Run<'_, D>,
    info: &MemberInfo<'_>,
    volumes: &[u32],
) -> Result<u32> {
    for &volume in volumes {
        run.driver.fragment_mismatch(info, volume)?;
    }
    Ok(u32::try_from(volumes.len()).unwrap_or(u32::MAX))
}

/// Close one member with its integrity verdict.
fn finish<D: Driver>(
    run: &mut Run<'_, D>,
    member: Member<D::Out>,
    file: &FileHdr,
    info: &MemberInfo<'_>,
    refused: Option<ErrorKind>,
    fragment_mismatches: u32,
) -> Result<()> {
    let checksum_ok = verdict(&member, &mut run.blake, file, refused.is_some());
    let written = member.written;
    // As in `close_member`: only a skipped member reaches here without one.
    let skipped = member.out.is_none();
    let value = match member.out {
        Some(Out::Write(w)) => Some(w),
        _ => None,
    };
    if refused.is_some() {
        run.driver.note_refused();
    }
    let err = refused.map(|kind| Error::new(kind).with_member(info.name));
    close_or_skip(
        run,
        skipped,
        info,
        value,
        &MemberOutcome {
            checksum_ok,
            bytes: written,
            password_refused: crate::read::password_refused(err.as_ref()),
            fragment_mismatches,
        },
        err,
    )
}

/// A single archive or set, with a throwaway session.
pub(crate) fn extract_free<V: Volumes, K: Sink, P: Progress>(
    volumes: V,
    opts: &crate::read::ReadOptions,
    sink: &mut K,
    progress: &mut P,
) -> Result<ExtractReport> {
    let mut ctx = ReadCtx::new(opts.clone());
    extract_with(volumes, &mut ctx, sink, progress)
}

#[cfg(test)]
mod tests;

/// The seam's lent stored path, in a module of its own and behind one
/// `#[inline(never)]` entry, so nothing on a decoder's path compiles any
/// differently for its existence.
#[cfg(feature = "parallel")]
pub(crate) mod lent;

/// The x86-64 admission of small batches by disposition,
/// pinned with injected inputs so it does not depend on the environment.
#[cfg(all(test, feature = "parallel", target_arch = "x86_64"))]
mod batches_for_tests {
    use super::{batches_for, WRITTEN_BATCHED_BY_DEFAULT};

    /// (batches on, set by name, verify) -> batched, for an operating
    /// system that does not batch written members by default.
    #[test]
    fn off_linux_x86_x_stays_on_the_walk_and_t_is_batched() {
        let os = false;
        assert!(batches_for(true, false, true, os), "t at the default");
        assert!(!batches_for(true, false, false, os), "x at the default");
        assert!(
            batches_for(true, true, false, os),
            "x with the knob by name"
        );
        assert!(batches_for(true, true, true, os), "t with the knob by name");
        assert!(!batches_for(false, false, true, os), "batches off");
        assert!(!batches_for(false, true, false, os), "batches off by name");
    }

    /// The same on Linux, which batches written members by default.
    #[test]
    fn on_linux_x86_x_and_t_are_batched() {
        let os = true;
        assert!(batches_for(true, false, true, os), "t at the default");
        assert!(batches_for(true, false, false, os), "x at the default");
        assert!(
            batches_for(true, true, false, os),
            "x with the knob by name"
        );
        assert!(!batches_for(false, false, false, os), "batches off");
        assert!(!batches_for(false, false, true, os), "batches off, t");
    }

    /// Which of the two this build is: Linux, and no other.
    #[test]
    fn written_members_are_batched_by_default_on_linux_only() {
        assert_eq!(WRITTEN_BATCHED_BY_DEFAULT, cfg!(target_os = "linux"));
    }
}

/// API section 8's charge, on every target (it sat in the x86-64
/// batches module at first, where aarch64 never ran it).
#[cfg(test)]
mod charge_for_tests {
    use super::*;

    /// API section 8: the process counters are charged with exactly what
    /// the decoders hold, as each is built and as one is replaced, for
    /// every method `decode` dispatches to (the RAR 1.5 window, which no
    /// committable fixture can tell from the cursor's read-ahead,
    /// included). The integration test `tests/memory_peak.rs` holds the
    /// same from outside, through `memory::peak`.
    #[test]
    fn the_charge_follows_what_the_decoders_hold() {
        let policy = crate::MemoryPolicy::default();
        let mut decoders = Decoders::default();
        assert_eq!(decoders.charge.bytes(), 0);

        decoders.rar15();
        assert!(decoders.charge.bytes() >= 64 << 10, "the RAR 1.5 window");
        assert_eq!(decoders.charge.bytes(), decoders.held_bytes());

        decoders.rar20(1 << 20, false);
        decoders.rar3(1 << 20, false, &policy).expect("rar3");
        assert_eq!(decoders.charge.bytes(), decoders.held_bytes());

        decoders
            .rar5(4 << 20, 4 << 20, false, &policy)
            .expect("rar5");
        let with_four = decoders.charge.bytes();
        assert_eq!(with_four, decoders.held_bytes());
        // A larger window replaces the ring: charged once, never twice.
        decoders
            .rar5(8 << 20, 8 << 20, false, &policy)
            .expect("rar5");
        assert_eq!(decoders.charge.bytes(), decoders.held_bytes());
        assert!(decoders.charge.bytes() >= with_four + (4 << 20));
        assert!(decoders.charge.bytes() < with_four + (8 << 20));
    }
}

/// The pre-scan runs only under a NAMED budget: without one no
/// volume is asked for before the walk (the default path pays nothing).
#[cfg(test)]
mod budget_floor_for_tests {
    use super::*;

    struct Untouched;

    impl Volumes for Untouched {
        fn volume(&mut self, index: u32) -> Result<Option<std::sync::Arc<dyn crate::RangeSource>>> {
            panic!("volume {index} was asked for with no named budget");
        }
    }

    #[test]
    fn no_pre_scan_runs_without_a_named_budget() {
        for memory in [
            crate::MemoryPolicy::default(),
            crate::MemoryPolicy::process_default(8 << 20),
        ] {
            let ctx = ReadCtx::new(crate::ReadOptions::default().with_memory(memory));
            let (_, room) = budget_floor(Untouched, &ctx).expect("no scan");
            assert!(room.is_none());
        }
    }
}
