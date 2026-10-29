//! What `Writer::new` decides, and everything it refuses (spec G sections
//! 3.8.1, 3.14.9 and 4).
//!
//! Every combination a format cannot represent is refused HERE, before a
//! byte is written, so that a caller learns from `new` rather than part
//! way through a run, and so that one copy of each rule exists.

use crate::error::{Error, ErrorKind, Resource, Unsupported};
use crate::memory::MemoryPolicy;
use crate::types::{HostOs, Password};
use crate::write::rar5::Reserve;
use crate::write::{
    ChecksumKind, Entropy, FilterPolicy, Layout, MemberOrder, VolumeNaming, WriteFormat,
    WriteMethod, WriteOptions,
};
use crate::Result;

/// The RAR 5 dictionary floor and quantum: a declared dictionary is this
/// shifted left by the power the header carries (spec G 3.4.1).
pub(crate) const DICTIONARY_QUANTUM: u64 =
    crate::carry::b_writers::rar50::write::RAR50_DICTIONARY_QUANTUM;

/// The dictionary a caller who names none gets (spec G 3.8.1), as a
/// ceiling that step 3's fit brings down to what the input can reach.
///
/// Still 2 MiB after the 27 Sep 2026 hold: a 32 MiB default searched
/// every link alike wrote solid
/// archives 4 to 22 per cent smaller on 1 GiB of text but failed the
/// project's wall condition (a smaller default only if wall is no worse) at every
/// level, create 22 per cent slower at level 3 and 2.1 times at level 5,
/// `rarfast x` 1 to 7 per cent slower (measured 27 Sep 2026).
/// A larger default is a lever
/// still to be earned.
pub(crate) const DEFAULT_DICTIONARY: u64 = 2 << 20;

/// The dictionary a caller who names none gets at LEVEL 1 in a NON-SOLID
/// RAR 5 archive (spec G 3.8.1), the one form whose default is not
/// [`DEFAULT_DICTIONARY`]. The same figure on every machine, so the bytes
/// a create writes never depend on how much memory the machine has.
///
/// 4 MiB since 1 Oct 2026: level 1's fast parse keeps one chain link, so
/// a window twice as long costs it little, and on 4 GiB of binaries it
/// wrote 4.2 per cent less archive and finished sooner at width (the
/// writer is the slower side there, and it has less to write). Levels 2
/// to 5 lose wall by the same change and every solid form loses more,
/// which is why neither moved. The RAR 4 family did not move either:
/// `rarfast` cannot write it, so no row stands behind a change there.
/// `WriteOptions::level1_dictionary_2mib` keeps [`DEFAULT_DICTIONARY`]
/// here too.
pub(crate) const LEVEL1_DICTIONARY: u64 = 4 << 20;

/// The dictionary a caller who names none gets at LEVEL 3 in a NON-SOLID
/// RAR 5 archive (spec G 3.8.1), searched under [`LEVEL3_FAR_LINKS`]. The
/// same figure on every machine.
///
/// 16 MiB since 9 Oct 2026. A longer dictionary searched as the 2 MiB one
/// is, every link alike, fails the wall condition by a wide margin: on
/// 4 GiB of binaries at 16 threads (x86-64, plain builds, K=5, 9 Oct
/// 2026) 8 MiB took 30.3 s against 16.3 s, 16 MiB 48.0 s and 32 MiB
/// 77.3 s, slower than reference `rar` at its own 32 MiB. Under a
/// far-link budget of 1 the 16 MiB create took 16.27 s against 16.23 s
/// (0.997x, the null 1.000x) and wrote 10.6 percent less archive
/// (161.3 MB), and the 8 MiB one 0.998x for 7.8 percent less, 1.018x at
/// one thread, with test and extract no slower. At 32 MiB the window
/// alone, no far link followed, cost 8 percent of wall, and with one far
/// link it wrote 11.9 percent less at 0.923x, which is not this
/// project's trade; 128 MiB read 0.659x. Levels 2, 4 and 5 and every
/// solid form have no row and did not move.
/// `WriteOptions::level3_dictionary_2mib` keeps [`DEFAULT_DICTIONARY`]
/// and no budget here too, and so does a memory ceiling the caller named
/// (`resolve` says why).
pub(crate) const LEVEL3_DICTIONARY: u64 = 16 << 20;

/// The far-link budget a level 3 search runs under where the dictionary
/// is [`LEVEL3_DICTIONARY`] BY DEFAULT (`WriteOptions::far_link_budget`
/// says what a budget is): the search walks its chain as it does at
/// 2 MiB and then follows one link past that. A budget of 2 at 8 MiB
/// wrote 0.2 percent less than 1 at 0.871x of the 2 MiB wall. A caller
/// who names a dictionary gets no budget from here, and one who names a
/// budget keeps their own.
pub(crate) const LEVEL3_FAR_LINKS: u32 = 1;

/// The dictionary a caller who names none gets in a SOLID RAR 5 archive
/// at levels 2 to 5 (spec G 3.8.1), as a ceiling step 3's fit brings down
/// to what the set can reach. The same figure on every machine.
///
/// 32 MiB since 10 Oct 2026, the figure reference `rar` 7.23 lists for
/// its own solid default at levels 1 to 5 (70 archives of 64 KiB to
/// 512 MiB, measured by calling it). A solid set's copies lie a whole
/// member and more apart, so at 2 MiB a tree of 5,000 files of which
/// 3,100 repeat another wrote 1.67 of rar's bytes and at this figure
/// 1.04, for less CPU (6.8 s against 10.5 at level 3, a plain build).
/// It is searched under [`SOLID_FAR_LINKS`].
///
/// LEVEL 1 KEEPS [`DEFAULT_DICTIONARY`] (decided 11 Oct 2026): its searches
/// take no budget, so it would take the window alone, and the x86-64
/// shipped pair of that day read a solid level 1 create 0.945 of the
/// 2 MiB wall on a tree of copies (for 41 percent less archive) and
/// 0.964 on binaries with none (for 0.35 percent less). Level 1 is the
/// level picked for wall; `-md` names the window for who wants the bytes.
/// `WriteOptions::solid_dictionary_2mib` keeps [`DEFAULT_DICTIONARY`] and
/// no budget, and so does a memory ceiling the caller named (`resolve`
/// says why). The RAR 4 family did not move: `rarfast` cannot write it,
/// so no row stands behind a change there.
pub(crate) const SOLID_DICTIONARY: u64 = 32 << 20;

/// The far-link budget a solid search runs under where
/// the dictionary is [`SOLID_DICTIONARY`] BY DEFAULT: 1, as at level 3's
/// own default. Every link followed alike wrote 1 percent less on the
/// tree above for three times the CPU (22.0 s). A caller who names a
/// dictionary gets no budget from here, and one who names a budget keeps
/// their own.
pub(crate) const SOLID_FAR_LINKS: u32 = 1;

/// The copy buffer every payload passes through, whatever the member's
/// size (spec G 3.7.1).
pub(crate) const COPY_CHUNK: usize = 1 << 20;

/// Options after `Writer::new` has checked them. Nothing below re-reads
/// [`WriteOptions`].
pub(crate) struct Resolved {
    pub(crate) format: WriteFormat,
    pub(crate) layout: Layout,
    /// The widths the layout asks for.
    pub(crate) reserve: Reserve,
    /// 0 stored, 1 to 5 the levels of the same number.
    pub(crate) method: u8,
    /// The dictionary the caller asked for, before the payload fit.
    pub(crate) dictionary: u64,
    pub(crate) checksum: ChecksumKind,
    pub(crate) solid: bool,
    /// The order a solid compressed archive's members are written in.
    pub(crate) order: MemberOrder,
    /// Payload bytes per volume, as the API documents the field.
    pub(crate) volume_size: Option<u64>,
    /// The whole volume FILE's cap, when the caller asked for the budget
    /// in that form instead.
    pub(crate) volume_file_size: Option<u64>,
    pub(crate) volume_naming: VolumeNaming,
    pub(crate) recovery_percent: Option<u32>,
    pub(crate) password: Option<Password>,
    pub(crate) encrypt_headers: bool,
    pub(crate) comment: Option<Vec<u8>>,
    pub(crate) lock: bool,
    // Resolved from `WriteOptions` (spec G 3.8.2) but not yet read by the
    // engine: spec G 3.8.2 is what should read it. Not done yet.
    #[allow(dead_code)]
    pub(crate) filters: FilterPolicy,
    // Resolved but not yet read: spec G 3.8.1 keeps the least-bits parse
    // behind it. Not done yet.
    #[allow(dead_code)]
    pub(crate) optimal_parse: bool,
    /// `WriteOptions::small_member_lazy`.
    pub(crate) small_member_lazy: bool,
    /// `WriteOptions::solid_store` (spec G 3.8.3: the store rule judges
    /// the members of a solid set too).
    pub(crate) solid_store: bool,
    /// `WriteOptions::level3_floor_lazy`.
    pub(crate) level3_floor_lazy: bool,
    /// `WriteOptions::level3_optimal`.
    pub(crate) level3_optimal: bool,
    /// `WriteOptions::level3_deep` (the backward extension's option).
    pub(crate) level3_deep: bool,
    /// `WriteOptions::low_levels_extend` (the backward extension's option).
    pub(crate) low_levels_extend: bool,
    /// `WriteOptions::level4_optimal`.
    pub(crate) level4_optimal: bool,
    /// `WriteOptions::level4_tree` (level 4's tree plan, SPEC-H3 8.1).
    pub(crate) level4_tree: bool,
    /// `WriteOptions::level5_tree` (level 5's tree for every member,
    /// SPEC-H3 8.1).
    pub(crate) level5_tree: bool,
    /// `WriteOptions::level5_far_links_only` (level 5's class without its
    /// second statistic, SPEC-H3 8.1).
    pub(crate) level5_far_links_only: bool,
    /// `WriteOptions::level5_optimal`.
    pub(crate) level5_optimal: bool,
    /// `WriteOptions::level1_priced`.
    pub(crate) level1_priced: bool,
    /// `WriteOptions::far_link_budget`, or [`LEVEL3_FAR_LINKS`] where the
    /// caller set none and level 3 took its own default dictionary.
    pub(crate) far_link_budget: Option<u32>,
    // `WriteOptions::level1_dictionary_2mib` and `level3_dictionary_2mib`
    // are spent in `resolve`, on `dictionary` above (and the second on
    // `far_link_budget` too), and are not carried further.
    /// `WriteOptions::store_one_miss` (spec G 3.8.3). Read through
    /// [`Resolved::store_misses`].
    pub(crate) store_one_miss: bool,
    /// `WriteOptions::encrypted_read_ahead` (SPEC-API 7.1).
    pub(crate) encrypted_read_ahead: bool,
    /// `WriteOptions::store_packed_samples` (spec G 3.8.3): how a sample's
    /// length is come by, never what it is.
    pub(crate) store_packed_samples: bool,
    pub(crate) entropy: Entropy,
    pub(crate) memory: MemoryPolicy,
    /// `WriteOptions::refuse_over_ceiling`, as the caller set it.
    pub(crate) refuse_over_ceiling: bool,
    /// The encoder's width dial, apart from the memory ceiling above
    /// (API 7.2 and 8.2). `None` means the caller's
    /// pool decides. Read through [`Resolved::encoder_width`], never
    /// directly, so that the `None` case has one spelling.
    pub(crate) workers: Option<usize>,
    /// The host byte a SERVICE block carries: the machine doing the
    /// writing, which is the opposite of a member's rule (spec G 3.3.4).
    pub(crate) host_os: HostOs,
}

impl Resolved {
    /// Whether this run writes a volume SET, in either budget form.
    pub(crate) fn volume_set(&self) -> bool {
        self.volume_size.is_some() || self.volume_file_size.is_some()
    }

    /// Whether this is a RAR 4 family target.
    pub(crate) fn is_rar4(&self) -> bool {
        matches!(self.format, WriteFormat::Rar4(_))
    }

    /// Whether the reference layout's quick-open block and locator record
    /// are wanted.
    pub(crate) fn quick_open(&self) -> bool {
        matches!(self.layout, Layout::Reference { quick_open: true })
    }

    /// Whether the layout is the reference one at all.
    pub(crate) fn reference_layout(&self) -> bool {
        matches!(self.layout, Layout::Reference { .. })
    }

    /// Whether members are stored rather than compressed.
    pub(crate) fn stored(&self) -> bool {
        self.method == 0
    }

    /// How many of spec G 3.8.3's sixteen samples may compress and a
    /// member of `size` declared bytes still be stored: four from 128 MiB,
    /// one below it, and one at every size under
    /// [`WriteOptions::store_one_miss`](crate::WriteOptions::store_one_miss).
    pub(crate) fn store_misses(&self, size: u64) -> usize {
        crate::write::store::most_misses(size, self.store_one_miss)
    }

    /// The ceiling to hand the encoder for its tree walk, from
    /// [`WriteOptions::workers`](crate::WriteOptions::workers).
    ///
    /// `None` becomes `usize::MAX`, which is the encoder's spelling for
    /// "no ceiling of my own": the walk then takes
    /// `min(pool width, the engine's own ceiling)` and the caller's pool
    /// is what decides, which is exactly what `None` promises. A zero is
    /// lifted to one rather than refused, because the field is a ceiling
    /// and a ceiling of nothing has no useful meaning; this is the same
    /// `max(1)` the encoder applies to its own copy.
    ///
    /// The MEMORY ceiling is deliberately not consulted here. API 8.2
    /// assigns the encoder walk row to `workers` and leaves the other
    /// rows, the BLAKE2sp leaf team among them, to
    /// `MemoryPolicy::max_workers`.
    pub(crate) fn encoder_width(&self) -> usize {
        match self.workers {
            Some(n) => n.max(1),
            None => usize::MAX,
        }
    }
}

/// Refuses what the format cannot represent, and fills the defaults in.
pub(crate) fn resolve(options: WriteOptions) -> Result<Resolved> {
    let WriteOptions {
        format,
        method,
        password,
        encrypt_headers,
        solid,
        order,
        volume_size,
        volume_file_size,
        volume_naming,
        recovery_percent,
        checksum,
        filters,
        optimal_parse,
        small_member_lazy,
        solid_store,
        level3_floor_lazy,
        level3_optimal,
        level3_deep,
        low_levels_extend,
        level4_optimal,
        level4_tree,
        level5_tree,
        level5_far_links_only,
        level5_optimal,
        level1_priced,
        level1_dictionary_2mib,
        level3_dictionary_2mib,
        solid_dictionary_2mib,
        far_link_budget,
        store_one_miss,
        encrypted_read_ahead,
        store_packed_samples,
        comment,
        lock,
        layout,
        entropy,
        memory,
        refuse_over_ceiling,
        workers,
        host_os,
    } = options;

    let rar4 = matches!(format, WriteFormat::Rar4(_));

    let (level, dictionary, far_link_budget) = match method {
        WriteMethod::Stored => (
            0u8,
            default_dictionary(DEFAULT_DICTIONARY, &memory),
            far_link_budget,
        ),
        WriteMethod::Compressed { level, dictionary } => {
            if level > 5 {
                return Err(refuse("a compression level outside 0 to 5"));
            }
            // A NAMED dictionary always wins. Unnamed, levels 1 and 3 in
            // a non-solid RAR 5 archive take their own defaults unless
            // the caller kept the general one.
            //
            // Level 3's is not taken under a ceiling the caller NAMED
            // (`MemoryPolicy::limit_named`): a named budget is a promise,
            // and the writer's charges do not yet follow a 16 MiB window
            // through the worker team (`tests/named_ceiling_heap.rs`: a
            // set of 499 members under a named 512 MiB held 85 MiB more
            // live heap at 16 MiB than at 2 MiB and stated 15 MiB more).
            // So a named budget writes the 2 MiB archive it always wrote.
            // An allowance nobody named, which follows the machine, never
            // decides this: the bytes do not depend on the machine.
            let own = !solid && !rar4;
            let level3_default = level == 3
                && own
                && !level3_dictionary_2mib
                && dictionary.is_none()
                && !memory.limit_named;
            // A solid RAR 5 archive's default is its own at levels 2 to 5
            // (level 1 keeps the general one: `SOLID_DICTIONARY`), and is
            // not taken under a NAMED ceiling for the reason level 3's is
            // not: the charges do not yet follow a longer window.
            let solid_default = solid
                && !rar4
                && level >= 2
                && !solid_dictionary_2mib
                && dictionary.is_none()
                && !memory.limit_named;
            let unnamed = if level == 1 && own && !level1_dictionary_2mib {
                LEVEL1_DICTIONARY
            } else if level3_default {
                LEVEL3_DICTIONARY
            } else if solid_default {
                SOLID_DICTIONARY
            } else {
                DEFAULT_DICTIONARY
            };
            // A default dictionary longer than 2 MiB comes with its
            // budget; a budget the caller set is the caller's.
            let far_link_budget = match far_link_budget {
                None if level3_default => Some(LEVEL3_FAR_LINKS),
                None if solid_default => Some(SOLID_FAR_LINKS),
                given => given,
            };
            (
                level,
                dictionary.unwrap_or_else(|| default_dictionary(unnamed, &memory)),
                far_link_budget,
            )
        }
    };

    if dictionary < DICTIONARY_QUANTUM
        || !dictionary.is_power_of_two()
        || dictionary > DICTIONARY_QUANTUM << crate::write::consts::MAX_DICTIONARY_POWER
    {
        return Err(refuse(
            "a dictionary that is not a power-of-two multiple of 128 KiB between 128 KiB and 4 GiB",
        ));
    }
    if dictionary > memory.max_dictionary {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: Resource::Dictionary,
            needed: dictionary,
            limit: memory.max_dictionary,
        }));
    }
    // A dictionary this TARGET cannot address, as opposed to one the
    // policy will not budget. On a 64-bit target the conversion cannot
    // fail and nothing here changes. On a 32-bit one the format's own
    // maximum, 4 GiB, IS the whole address space, and each encoder takes
    // the figure through a narrowing cast: without this the encoder would
    // be built with a dictionary of some unrelated size and would compress
    // against the wrong history rather than refuse. `MemoryPolicy`'s
    // fields are public, so the clamp in `memory.rs` is not on its own
    // enough to make that unreachable.
    if usize::try_from(dictionary).is_err() {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: Resource::Dictionary,
            needed: dictionary,
            limit: usize::MAX as u64,
        }));
    }

    if rar4 && checksum == ChecksumKind::Blake2sp {
        return Err(refuse(
            "BLAKE2sp under the RAR 4 family, which has no hash record",
        ));
    }
    let volume_set = volume_size.is_some() || volume_file_size.is_some();
    if volume_size.is_some() && volume_file_size.is_some() {
        return Err(refuse(
            "volume_size and volume_file_size together, which are two ways to say one budget",
        ));
    }
    if !rar4 && volume_naming == VolumeNaming::Classic && volume_set {
        return Err(refuse("classic volume naming under RAR 5"));
    }
    if rar4 && matches!(layout, Layout::Reference { .. }) {
        return Err(refuse(
            "the reference layout under the RAR 4 family, which the reference cannot write",
        ));
    }
    if matches!(layout, Layout::Reference { .. }) {
        if volume_set {
            return Err(refuse(
                "the reference layout on a volume set, whose padding nothing observable predicts",
            ));
        }
        if level != 0 {
            return Err(refuse(
                "the reference layout for a compressed member, where byte identity is not claimed",
            ));
        }
    }
    if rar4 && recovery_percent.is_some() {
        if encrypt_headers {
            return Err(refuse("a RAR 4 recovery record beside header encryption"));
        }
        if volume_set {
            return Err(refuse("a RAR 4 recovery record on a split set"));
        }
    }
    // A RAR 5 record takes what the reference stores as given, 1 to 1,000
    // (spec L 3.5.1). The RAR 4 family's is parity sectors, never more of
    // them than the sectors protected (spec L 3.7), so it stops at 100.
    match recovery_percent {
        Some(percent) if rar4 && !(1..=100).contains(&percent) => {
            return Err(refuse(
                "a RAR 4 recovery record percentage outside 1 to 100",
            ));
        }
        Some(percent) if !crate::recovery::rr5::PERCENT_RANGE.contains(&percent) => {
            return Err(refuse("a recovery record percentage outside 1 to 1000"));
        }
        _ => {}
    }
    if let Some(size) = volume_size {
        if size == 0 {
            return Err(refuse(
                "a volume size of zero: at least one payload byte must fit in a volume",
            ));
        }
        // Under a password a fragment that is not a member's last holds
        // whole cipher blocks, so a budget under one block never takes a
        // byte of a member longer than itself and the run opened volumes
        // for ever (spec G section 4: no unbounded loop on any caller
        // input, and at least one payload byte must fit).
        if password.is_some() && size < crate::write::crypt::CIPHER_BLOCK as u64 {
            return Err(refuse(
                "a volume size under one cipher block of 16 bytes with a password",
            ));
        }
    }
    // A FILE budget has to pay for the volume's own blocks before a
    // payload byte fits, so a cap under that floor is refused HERE rather
    // than discovered as a run that can never place a byte and loops
    // opening volumes (spec G section 4's `volume_size` row, read for the
    // budget that counts the whole file).
    if let Some(cap) = volume_file_size {
        let floor = min_volume_file_size(format, recovery_percent.is_some());
        if cap < floor {
            return Err(refuse(
                "a volume file size under the room one volume's own blocks need",
            ));
        }
    }
    if encrypt_headers && password.is_none() {
        return Err(refuse("header encryption with no password"));
    }
    if encrypt_headers && matches!(layout, Layout::Reference { .. }) {
        // The reference layout lays its main header out before it knows
        // where the quick-open block will land, and under header
        // encryption every block's length on the wire is its padded one,
        // so the offsets it records are not the offsets a reader counts.
        // Byte identity is not claimed for this combination either
        // (spec G 3.6 covers a stored archive's options, and `-hp` draws
        // a salt that nothing can reproduce).
        return Err(refuse("the reference layout beside header encryption"));
    }
    if password.is_some()
        && matches!(layout, Layout::Reference { .. })
        && recovery_percent.is_some()
    {
        return Err(refuse(
            "a recovery record beside encryption in the reference layout",
        ));
    }

    // The seam of spec G 3.14.7 is CLOSED, and not by this package:
    // SPEC-J says the RAR 4 family writes no filter record, and
    // `Writer::new` refuses a filter request for it by name through
    // `rar3_filters::refuse_written_filters` rather than resolving it to
    // `Off` behind the caller's back. Nothing here emits a filter
    // program, in either family.

    let reserve = match layout {
        Layout::Default => Reserve::Natural,
        Layout::Reference { .. } => Reserve::Reference,
    };

    Ok(Resolved {
        format,
        layout,
        reserve,
        method: level,
        dictionary,
        checksum,
        solid,
        order,
        volume_size,
        volume_file_size,
        volume_naming,
        recovery_percent,
        password,
        encrypt_headers,
        comment,
        lock,
        filters,
        optimal_parse,
        small_member_lazy,
        solid_store,
        level3_floor_lazy,
        level3_optimal,
        level3_deep,
        low_levels_extend,
        level4_optimal,
        level4_tree,
        level5_tree,
        level5_far_links_only,
        level5_optimal,
        level1_priced,
        far_link_budget,
        store_one_miss,
        encrypted_read_ahead,
        store_packed_samples,
        entropy,
        memory,
        refuse_over_ceiling,
        workers,
        host_os,
    })
}

/// The default dictionary `unnamed` under `memory` (spec G 3.8.1 steps 1
/// and 2).
///
/// A policy is an allowance and never a request, so a DEFAULT the policy
/// would not budget is reduced to the largest power of two it admits
/// rather than refused: a caller who asked for no particular dictionary
/// has asked for nothing the policy can turn down. A dictionary the caller
/// NAMED is still refused over the policy, below, because that caller
/// asked for a figure and should get an answer about it.
fn default_dictionary(unnamed: u64, memory: &MemoryPolicy) -> u64 {
    let mut dictionary = unnamed;
    while dictionary > DICTIONARY_QUANTUM && dictionary > memory.max_dictionary {
        dictionary /= 2;
    }
    dictionary
}

/// An option combination the chosen format cannot represent.
pub(crate) fn refuse(reason: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported(Unsupported::WriteFeature(reason)))
}

/// The dictionary a RAR 5 header declares, fitted to the payload
/// (spec G 3.8.1 step 3): halved while it is still at least the quantum
/// and still more than twice the largest payload the members can reach.
pub(crate) fn fitted_dictionary(requested: u64, largest_payload: u64) -> u64 {
    let mut fitted = requested;
    while fitted > DICTIONARY_QUANTUM && fitted > largest_payload.saturating_mul(2) {
        fitted /= 2;
    }
    fitted
}

/// The dictionary power a RAR 5 compression information field carries.
pub(crate) fn dictionary_power(dictionary: u64) -> u32 {
    (dictionary / DICTIONARY_QUANTUM).trailing_zeros()
}

/// The RAR 5 host byte of a member (spec G 3.4.3): 0 Windows, 1 Unix.
pub(crate) fn rar5_host_byte(host: HostOs) -> u64 {
    match host {
        HostOs::MsDos | HostOs::Windows => 0,
        HostOs::Other(n) => u64::from(n),
        _ => 1,
    }
}

/// The RAR 4 host byte of a member (spec G 3.14.3).
pub(crate) fn rar4_host_byte(host: HostOs) -> u8 {
    match host {
        HostOs::MsDos => 0,
        HostOs::Os2 => 1,
        HostOs::Windows => 2,
        HostOs::Unix => 3,
        HostOs::MacOs => 4,
        HostOs::BeOs => 5,
        HostOs::Other(n) => n,
    }
}

/// The smallest whole-file volume budget that can hold a volume's own
/// blocks and still place one payload byte (spec G 3.10.3 lists the
/// blocks; this is their floor).
///
/// It is deliberately a floor and not an exact figure: the member header
/// that goes with a payload byte follows the member's NAME, which
/// `Writer::new` has not been told yet. A cap over this floor that still
/// cannot fit a particular member's header is caught by the run itself,
/// which refuses rather than opening volume after empty volume.
pub(crate) fn min_volume_file_size(format: WriteFormat, recovery: bool) -> u64 {
    // Signature or marker, a main header, the shortest member header a
    // name of one byte can make, the end block, and one payload byte.
    let frame = match format {
        WriteFormat::Rar5 => 8 + 16 + 30 + 8,
        WriteFormat::Rar4(_) => 7 + 13 + 32 + 20,
    };
    // A recovery record's own header and its smallest possible body
    // (SPEC-L 3.5.1 with `k = 1`).
    // With a record, the RAR 5 main header may also carry the recovery
    // locator (spec G 3.11): its record's size, type and flags, and an
    // offset of at most ten bytes, and one more for the extra area's size.
    let locator = match format {
        WriteFormat::Rar5 if recovery => 4 + 10,
        _ => 0,
    };
    frame + 1 + locator + if recovery { 0x48 + 8 } else { 0 }
}
