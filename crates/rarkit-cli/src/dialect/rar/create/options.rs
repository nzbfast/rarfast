//! What the command line asks of the writer: its options, its memory
//! policy, and the dials a count build reads.

use super::*;

/// The options the switches on the command line resolve to.
pub(super) fn write_options(
    opts: &Options,
    files: &[Chosen],
    comment: Option<Vec<u8>>,
) -> WriteOptions {
    let level = opts.level.as_u8();
    let method = if opts.level.is_store() {
        WriteMethod::Stored
    } else {
        WriteMethod::Compressed {
            level,
            dictionary: opts.dictionary,
        }
    };
    let password = opts
        .shared
        .password
        .as_deref()
        .map(|text| Password::from(text.as_bytes()));
    // `Layout::Reference` is the reference's own byte layout and rarkit
    // offers it only for a single stored archive in clear. Everywhere
    // else the archive is rarkit's own and valid, which is what the
    // conformance claim rests on outside stored mode.
    let reference_layout = opts.level.is_store()
        && opts.volume_size.is_none()
        && password.is_none()
        && opts.recovery_percent.is_none();
    let layout = if reference_layout {
        Layout::Reference {
            // Measured on `rar a -m0 arc.rar text.txt rand.bin`: the
            // archive carries a `QO` service block, so the quick-open
            // index is ON unless `-qo-` turned it off.
            quick_open: opts.quick_open.unwrap_or(true),
        }
    } else {
        Layout::Default
    };
    WriteOptions {
        // 7.23 writes RAR 5 and nothing else, and refuses `-ma4` as an
        // unknown option; rarkit's RAR 4 writer is reachable only if the
        // pin moves to a reference that accepts the switch.
        format: WriteFormat::Rar5,
        method,
        // `-mc-`: no filter (rar 7.23 writes the unfiltered bytes for
        // it, `tests/create_mc_switches.rs`).
        filters: if opts.filters_off {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::default()
        },
        password,
        encrypt_headers: opts.encrypt_headers,
        solid: opts.solid,
        // The selection already put a solid archive's files in the
        // writer's by-type order, or kept them as found under `-ds`
        // (`select::collect`); the progress lines follow that list, so
        // the writer must not reorder it again.
        order: MemberOrder::AsAdded,
        // `-v<size>` is the volume FILE's cap to the reference: measured
        // on rar 7.23, 28 Sep 2026, `a -m0 -v1g` over a 4 GiB file writes
        // four volumes of exactly 1,073,741,824 bytes and a fifth of 823.
        // Passed as `volume_size`, the PAYLOAD budget, it wrote four
        // volumes of 1,073,741,898, each 74 bytes over the cap the user
        // named, and a set one volume short of the reference's.
        volume_file_size: opts.volume_size,
        volume_naming: if opts.old_volume_names {
            VolumeNaming::Classic
        } else {
            VolumeNaming::Numbered
        },
        recovery_percent: opts.recovery_percent.map(|p| p as u32),
        checksum: match opts.hash {
            HashType::Crc32 => ChecksumKind::Crc32,
            HashType::Blake2sp => ChecksumKind::Blake2sp,
        },
        comment,
        lock: false,
        layout,
        memory: memory_policy(opts, files),
        // A named `-mm` is kept or refused, never passed in silence: a
        // create whose encoder cannot fit inside it is refused before a
        // byte, as `rv` under `-mm` is (`least_mm_that_holds` names the
        // figure that would do). Unset, nothing moves.
        refuse_over_ceiling: opts.memory_cap.is_some(),
        workers: encoder_workers(opts),
        small_member_lazy: small_member_lazy(),
        solid_store: solid_store(),
        level3_floor_lazy: level3_floor_lazy(),
        level3_optimal: level3_optimal(),
        level3_deep: level3_deep(),
        low_levels_extend: low_levels_extend(),
        level4_optimal: knob_on("RARKIT_L4_OPTIMAL"),
        level4_tree: knob_on("RARKIT_L4_TREE"),
        level5_tree: knob_on("RARKIT_L5_TREE"),
        level5_far_links_only: knob_on("RARKIT_L5_FAR_ONLY"),
        level5_optimal: knob_on("RARKIT_L5_OPTIMAL"),
        level1_priced: level1_priced(),
        level1_dictionary_2mib: knob_on("RARKIT_L1_DICT_2M"),
        level3_dictionary_2mib: knob_on("RARKIT_L3_DICT_2M"),
        solid_dictionary_2mib: knob_on("RARKIT_SOLID_DICT_2M"),
        far_link_budget: far_link_budget(),
        store_one_miss: store_one_miss(),
        // Every member here is its own file, which is what the option asks
        // of a caller (SPEC-API 7.1), so rarfast sets it;
        // `RARKIT_ENCRYPTED_READ_AHEAD=0` is the walk without it.
        encrypted_read_ahead: crate::knob::writer_var_os("RARKIT_ENCRYPTED_READ_AHEAD")
            .is_none_or(|value| value != "0"),
        store_packed_samples: knob_on("RARKIT_STORE_PACKED_SAMPLES"),
        ..WriteOptions::default()
    }
}

/// `-mm<size>`: a ceiling on the encoder's working memory, which rarkit
/// takes as a [`MemoryPolicy`](rarkit::MemoryPolicy) dictionary cap AND,
/// since 21 Sep 2026, as
/// [`MemoryPolicy::working_limit`](rarkit::MemoryPolicy::working_limit).
///
/// Before this the switch reached `max_dictionary` alone, so no
/// `rarkit-cli` invocation ever set a `working_limit` other than
/// [`MemoryPolicy::DEFAULT_LIMIT`](rarkit::MemoryPolicy::DEFAULT_LIMIT) -
/// the one spelling spec G 3.5 reads as "the caller set a ceiling" - and
/// SPEC-G 3.5 case (b)'s budgeted streaming mode had no door
/// through the shipped tool at all, whatever `-mm` was given. Setting
/// both fields to the same figure is spec G 3.5's own recommendation
/// (SPEC errata batch 3, reading (a)): the one CLI
/// memory switch now reaches both dials it is already documented as
/// bounding, and no new spelling is added.
pub(super) fn memory_policy(opts: &Options, files: &[Chosen]) -> rarkit::MemoryPolicy {
    // With no `-mm` the budget is the WHOLE PROCESS's
    // (SPEC-API 8.4.1), as the read path's is (`engine::read_options_capped`):
    // `process_default(caller_resident)`, the machine's default budget,
    // so the writer's admission (its
    // worker team, the lead's staged flushes, spec G 3.5's held members)
    // leaves room for the process's headroom and what this binary holds.
    // Until 30 Sep 2026 it took `default()`, the ENGINE's 512 MiB, and
    // bin4g at `-m3` ran the process to 530 to 666 MiB at 32 threads with
    // its engine inside 512.
    //
    // A stated `-mm<size>` of 512 MiB and more is the WHOLE PROCESS's too
    // (`for_process`, SPEC-API 8.4.1; spec G 3.7.3's named-ceiling rule
    // of 1 Oct 2026): inside it the writer admits what the default admits,
    // so the process is held to the figure by the same arithmetic as the
    // default's. Taken as the engine's figure with that admission, bin4g at
    // `-m3 -mm512m` held 493 to 545 MiB of footprint on macOS at 32
    // threads (1 Oct 2026).
    //
    // **Under 512 MiB a stated `-mm` is the whole process's too** (since
    // 24 Oct 2026; a named `-mm` is a promise the user reads in the
    // PROCESS). Until then it was the ENGINE's figure there, and the
    // process passed it by what the engine does not count: counted on the
    // M5 Ultra under `-mm420m` at `-m5 -md32m`, phys_footprint passed the
    // write's stated peak by 15 to 26 MiB at four threads, by 28 to 71 at
    // sixteen and by 42 to 70 at thirty-six, growing with the members to
    // about 70 MiB from eight of them on (`mm_room`). The ENGINE's path
    // for a small ceiling is unchanged: which path a run takes is read
    // from the budget, which is still the figure named.
    let policy = match opts.memory_cap {
        Some(cap) => {
            let cap = cap.max(1 << 17);
            let mut policy = rarkit::MemoryPolicy::default();
            policy.max_dictionary = policy.max_dictionary.min(cap);
            // **A ceiling the caller NAMED is named whatever its figure**
            // (`MemoryPolicy::limit_named`, SPEC-API 8): `-mm512m` names
            // exactly the default, and before the field existed the engine
            // read that as no ceiling at all, so case (b) never streamed
            // under it, over any output.
            policy.limit_named = true;
            let process = rarkit::MemoryPolicy::for_process(cap, mm_room(files, opts));
            policy.working_limit = process.working_limit;
            policy.process_overhead = process.process_overhead;
            policy
        }
        None => {
            // `process_default`'s limit and overhead; every other field is
            // `default()`'s, as it was, so the dictionary and the BLAKE2sp
            // leaf team's `max_workers` are unchanged.
            let process = rarkit::MemoryPolicy::process_default(create_resident(files, opts));
            rarkit::MemoryPolicy {
                working_limit: process.working_limit,
                process_overhead: process.process_overhead,
                environment_cap: process.environment_cap,
                ..rarkit::MemoryPolicy::default()
            }
        }
    };
    // `max_workers` is LEFT ON ITS DERIVATION here, which it was not
    // before 20 Sep 2026. This function used to SET it to the encoder's
    // width, because the encoder's width was the only thing it could be
    // set through: `from_limit` derives it from the MEMORY budget - 8 at
    // the default - and that figure has nothing to say about how many
    // tree walkers an encode wants, so letting it bind cost 15.2 s
    // against 14.6 s on `rar a -m3` over 4 x 64 MiB here, a paired median
    // of 0.972x and straddling the 0.97x gate for no CPU saving worth
    // having. The two dials were then split, so the width now goes to
    // `WriteOptions::workers` (see `encoder_workers`) and this field goes
    // back to meaning only what API 8.2 says it means: the memory
    // ceiling, which on this path bounds the BLAKE2sp leaf team.
    //
    // The pool those walkers run on is still sized here, and still at the
    // box's own width when `-mt` is absent.
    //
    // A pool the system refused was already answered by `add`, before it
    // created anything; a second call here only repeats that answer.
    let _ = crate::workers::configure(opts.shared.threads, crate::workers::Work::Write);
    policy
}

/// The width `mm_room` is counted at under a named `-mm`: sixteen
/// threads, or fewer where `-mt` asks for fewer. A run on the small path's
/// dials runs no wider (the engine narrows it), and a run on the default's
/// plan, which runs at the pool's width, is admitted only where the
/// threads past sixteen fit beside it (`rarkit` `Run::choose_rung`). Fixed,
/// never the machine's, because the room decides which members are held
/// whole and which streamed, which moves bytes (`mm_room`).
pub(super) const MM_WIDTH_MOST: u64 = 16;

/// What the process holds beside the engine under a named `-mm`, apart
/// from what `create_resident` names: a fixed part and a part per thread
/// of the named width (`mm_room`).
const MM_ROOM_BASE: u64 = 16 << 20;
const MM_ROOM_PER_THREAD: u64 = 1 << 20;

/// The width `mm_room` is counted at under a named `-mm`
/// (`MM_WIDTH_MOST`, or fewer where `-mt` asks for fewer), or `None` with
/// no `-mm`. The figure the command line implies, never the machine's.
pub(super) fn named_width(opts: &Options) -> Option<u64> {
    opts.memory_cap?;
    Some(
        opts.shared
            .threads
            .unwrap_or(MM_WIDTH_MOST)
            .clamp(1, MM_WIDTH_MOST),
    )
}

/// What a create's process holds beside its engine under a named `-mm`,
/// the `caller_resident` its policy is taken with (`for_process`, which
/// adds `MemoryPolicy::PROCESS_HEADROOM`): the chosen files and their
/// names, the read-ahead at its most at the named width, the output's held
/// corrections, `MM_ROOM_BASE`, and `MM_ROOM_PER_THREAD` a thread of the
/// named width.
///
/// **Counted, and why each term.** On the M5 Ultra under `-mm420m` (`-m5
/// -md32m`, macOS system binaries) phys_footprint passed the write's
/// stated peak by 25.4 MiB at one thread and 26.2 at four (two 256 MiB
/// members), by 34.9 to 70.7 at sixteen and 41.6 to 70.7 at thirty-six,
/// growing with the members (one, two, eight, sixteen) to about 70 from
/// eight on (thirty-two 64 MiB members 64.7 to 69.1; 11,114 small files
/// 62 to 68): thread stacks and per-thread allocator caches, and memory
/// the allocator keeps across each member's encoder buffers. At sixteen
/// threads this room is 32 + 16 + 16 + 16 MiB, 80, above the 70.7 counted.
///
/// **Machine-independent on purpose**: the room decides the engine's limit
/// and so which members are held whole and which are streamed, which moves
/// bytes, and an archive's bytes must not follow the machine (SPEC-API
/// 8.4.1). So every term is taken at the NAMED width, never the box's.
pub(super) fn mm_room(files: &[Chosen], opts: &Options) -> u64 {
    let width = named_width(opts).unwrap_or(MM_WIDTH_MOST);
    let table = std::mem::size_of_val(files);
    let names: usize = files
        .iter()
        .map(|file| file.shown.len() + file.stored.len() + file.disk.as_os_str().len())
        .sum();
    (table + names) as u64
        + super::ahead::held_bytes_most(width as usize)
        + crate::unbuffered::HELD_MOST
        + MM_ROOM_BASE
        + MM_ROOM_PER_THREAD.saturating_mul(width)
}

/// The `-mm`, in bytes, under which a create with `opts`' width and no
/// chosen files gets exactly `limit` as its engine's `working_limit`: what
/// a test that pins the ENGINE at a figure names, now that a named `-mm`
/// is the whole process's (`memory_policy`).
#[cfg(test)]
pub(super) fn mm_for_engine_limit(limit: u64, opts: &Options) -> u64 {
    let mut named = opts.clone();
    named.memory_cap = Some(1);
    limit + rarkit::MemoryPolicy::PROCESS_HEADROOM + mm_room(&[], &named)
}

/// The least `-mm`, in whole MiB, under which a create whose encoder
/// needs `needed` bytes of working memory would run: the figure a refusal
/// under a named `-mm` names. A named `-mm` is the whole process's at
/// every figure (`memory_policy`), so the process headroom and `mm_room`
/// come on top of `needed`, and a larger `-mm` always holds what a smaller
/// one holds.
pub(super) fn least_mm_that_holds(needed: u64, files: &[Chosen], opts: &Options) -> u64 {
    let room = mm_room(files, opts);
    let holds = |cap: u64| {
        rarkit::MemoryPolicy::for_process(cap.max(1 << 17), room).working_limit >= needed
    };
    let mut mib = needed.div_ceil(1 << 20).max(1);
    while !holds(mib << 20) {
        mib += 1;
    }
    mib
}

/// What this binary holds beside the writer for a create (the policy's
/// `caller_resident`): the chosen files and their three spellings of a
/// path, the small-member read-ahead at its most (`ahead`), and the
/// corrections a cached output holds until its close, at their most
/// (`unbuffered::HELD_MOST`; one output is open at a time). That last
/// term is charged on EVERY system, though only macOS holds corrections
/// (`unbuffered::HOLDS`): what the writer is left under a named `-mm`
/// decides bytes, and bytes must not depend on the machine.
pub(super) fn create_resident(files: &[Chosen], opts: &Options) -> u64 {
    let table = std::mem::size_of_val(files);
    let names: usize = files
        .iter()
        .map(|file| file.shown.len() + file.stored.len() + file.disk.as_os_str().len())
        .sum();
    (table + names) as u64
        + super::ahead::held_bytes_most(ahead_width(opts))
        + crate::unbuffered::HELD_MOST
}

/// The pool width the small-member read-ahead is sized for: the pool's
/// own, or TWO where the default policy's process budget here is under
/// the 512 MiB floor (an environment's memory cap binds, SPEC-API 8.1
/// term 2), which is the read-ahead at its least: two loaders and 4 MiB
/// held, where sixteen threads' worth is 16 MiB of a working limit of 24
/// under a 96 MiB cgroup. It moves no byte: a member is a reader either
/// way, and the read-ahead only serves its pulls (`ahead`). A named `-mm`
/// keeps the pool's width, as it had.
pub(super) fn ahead_width(opts: &Options) -> usize {
    let width = crate::workers::width(opts.shared.threads, crate::workers::Work::Write);
    if opts.memory_cap.is_none() && small_default_budget() {
        width.min(2)
    } else {
        width
    }
}

/// Whether the default policy's process budget on this machine is under
/// `DEFAULT_LIMIT`: only under a cgroup limit or a finite `RLIMIT_AS`
/// (`MemoryPolicy::process_default`).
pub(super) fn small_default_budget() -> bool {
    let policy = rarkit::MemoryPolicy::process_default(0);
    policy.working_limit.saturating_add(policy.process_overhead)
        < rarkit::MemoryPolicy::DEFAULT_LIMIT
}

/// `RARKIT_SMALL_LAZY`: the small member's lazy parse, on by default
/// (spec G 3.8.1): `0` off, which gives a small non-solid member at
/// `-m4` and `-m5` level 3's optimal chain parse for a few bytes at about
/// twice the CPU; unset, `1` or anything else on. rarkit's own knobs are
/// environment variables, beside `RARKIT_SMALL_TEAM` and
/// `RARKIT_SMALL_BATCH`, because the rar dialect's switch set stays
/// exactly rar's: no switch sets this.
pub(super) fn small_member_lazy() -> bool {
    crate::knob::writer_var_os("RARKIT_SMALL_LAZY").is_none_or(|v| v != "0")
}

/// `RARKIT_SOLID_STORE`: the store rule inside a solid set
/// (`WriteOptions::solid_store`, spec G 3.8.3), on by default: `0` off,
/// which keeps every member of a solid archive in the compressor, as
/// before 1 Oct 2026; unset, `1` or anything else on. An environment
/// variable for the same reason as `RARKIT_SMALL_LAZY`: no rar switch
/// sets it.
pub(super) fn solid_store() -> bool {
    crate::knob::writer_var_os("RARKIT_SOLID_STORE").is_none_or(|v| v != "0")
}

/// `RARKIT_L3_FLOOR_LAZY`: an option (spec G 3.8.3), `1` on,
/// unset or anything else off: level 3 parses a block with nothing to find
/// by the floor's lazy parse, as it once did, instead of the floor
/// scan. Beside `RARKIT_SMALL_LAZY`, and for the same reason: no switch
/// in the rar dialect sets it.
pub(super) fn level3_floor_lazy() -> bool {
    crate::knob::writer_var_os("RARKIT_L3_FLOOR_LAZY").is_some_and(|v| v == "1")
}

/// `RARKIT_L3_OPTIMAL`: an option (`WriteOptions::level3_optimal`),
/// `1` on, unset or anything else off. On, `-m3` parses with the optimal
/// parse over 8 chain links, as it once did, instead of the
/// lazy parse (32 links deep, or 64 with `RARKIT_L3_DEEP`): a few tenths of a percent of archive on
/// source trees for 2x to 5x the CPU. An environment variable for the
/// same reason as `RARKIT_SMALL_LAZY`: no rar switch sets it.
pub(super) fn level3_optimal() -> bool {
    crate::knob::writer_var_os("RARKIT_L3_OPTIMAL").is_some_and(|v| v == "1")
}

/// `RARKIT_FAR_LINKS`: the far-link budget
/// (`WriteOptions::far_link_budget`), a count; unset, empty or not a
/// number is no budget. With `RARKIT_FAR_LINKS=1 -md4m`, a chain search at
/// `-m2` or `-m3` walks its chain as it does at the 2 MiB default and then
/// follows one link past 2 MiB, which finds most of what the whole 4 MiB
/// search finds at about the 2 MiB search's cost. It names no dictionary,
/// at 2 MiB or less it moves no byte, and `-m1` reads nothing of it. No
/// rar switch sets it.
pub(super) fn far_link_budget() -> Option<u32> {
    crate::knob::writer_var("RARKIT_FAR_LINKS")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// `RARKIT_L3_DEEP`: the backward extension's option
/// (`WriteOptions::level3_deep`), `1` on, unset or anything else off. On,
/// `-m3`'s lazy parse follows its chains 64 links deep, the depth first planned,
/// instead of 32: a few tenths of a percent of archive for 6 to 40 percent
/// more create wall. No rar switch sets it.
pub(super) fn level3_deep() -> bool {
    crate::knob::writer_var_os("RARKIT_L3_DEEP").is_some_and(|v| v == "1")
}

/// `RARKIT_L12_EXTEND`: the backward extension's option at levels 1 and 2
/// (`WriteOptions::low_levels_extend`), `1` on, unset or anything else off.
/// On, `-m1` and `-m2` write 2.3 to 5.0 percent smaller archives of text
/// for up to 3 percent more create wall. No rar switch sets it.
pub(super) fn low_levels_extend() -> bool {
    crate::knob::writer_var_os("RARKIT_L12_EXTEND").is_some_and(|v| v == "1")
}

/// `RARKIT_L4_OPTIMAL` and `RARKIT_L5_OPTIMAL`: options
/// (spec G 3.8.1), `1` on, unset or anything else off: level 4 or 5 keeps
/// the optimal parse over the tree it once had, instead of
/// the lazy one, on a member that is not lone. `RARKIT_L4_TREE`, read the
/// same way: level 4 keeps the lazy parse over the TREE instead of the
/// chains at 64 links (`WriteOptions::level4_tree`); `RARKIT_L4_OPTIMAL`
/// overrides it. `RARKIT_L5_TREE`, the same way: level 5 keeps the lazy
/// parse over the tree for every member, where by default a member's class
/// or a solid run gives it the chains (`WriteOptions::level5_tree`);
/// `RARKIT_L5_OPTIMAL` overrides it. `RARKIT_L5_FAR_ONLY`, the same way:
/// level 5's class goes by far links alone, so a member reading many keeps
/// the tree whatever long matches its head holds, where by default one
/// that holds enough takes the chains
/// (`WriteOptions::level5_far_links_only`); both of the others override
/// it. Beside `RARKIT_SMALL_LAZY`, and for the same reason: no
/// switch in the rar dialect sets any of them.
pub(super) fn knob_on(name: &str) -> bool {
    crate::knob::writer_var_os(name).is_some_and(|v| v == "1")
}

/// `RARKIT_L1_PRICED`: an option (`WriteOptions::level1_priced`),
/// `1` on, unset or anything else off. On, `-m1` parses with the lazy
/// parse over four byte chains three links deep, as it once did,
/// instead of the fast parse: 0.2 to 5.6 percent less archive for
/// about twice the create wall at one thread. No rar switch sets it.
pub(super) fn level1_priced() -> bool {
    crate::knob::writer_var_os("RARKIT_L1_PRICED").is_some_and(|v| v == "1")
}

/// `RARKIT_STORE_ONE_MISS`: the store rule's option
/// (`WriteOptions::store_one_miss`, spec G 3.8.3), `1` on, unset or anything
/// else off. On, a member of 128 MiB and more is stored only when at least 15
/// of its 16 samples will not compress, as before 1 Oct 2026 and as a
/// smaller member still is, instead of at least 12: a big member whose opening
/// packs is then compressed whole. No rar switch sets it.
pub(super) fn store_one_miss() -> bool {
    knob_on("RARKIT_STORE_ONE_MISS")
}

/// `-mt<n>` on the create path, as the ENCODER'S width (API 7.2).
///
/// It was parsed and then dropped before 19 Sep 2026, and the switch's
/// own doc comment claimed otherwise; the encoder took
/// `rayon::current_num_threads()` instead, so the archive was written at
/// the box's core count whatever the command line said. The archive's
/// bytes do not depend on the number either way (API promise 2.6).
///
/// With no `-mt` this is `None`, which asks the engine for the width of
/// the pool the caller owns; `memory_policy` has just sized that pool at
/// the box's own width, so the create path's default is unchanged by the
/// split. With `-mt<n>` it is exactly `n`, bounded to what the box has by
/// [`crate::workers::width`], the same figure the pool gets.
pub(super) fn encoder_workers(opts: &Options) -> Option<usize> {
    opts.shared
        .threads
        .map(|_| crate::workers::width(opts.shared.threads, crate::workers::Work::Write))
}
