//! The decoders one extract keeps: which codec a member names, the windows
//! held between members and what they are charged, and the decode of one
//! member through them.

use super::*;

/// The decoder this member's method selects (spec F 3.3.5, 3.4.4).
pub(crate) enum Codec {
    /// No codec at all: the packed bytes are the member.
    Stored,
    /// Spec H2's RAR 5 LZ decoder, with the member's declared dictionary
    /// and the algorithm version its compression info names.
    Rar5 {
        window: u64,
        /// What the member can reach, `min(window, unpacked)` outside a
        /// solid archive and `window` inside one.
        reach: u64,
        algorithm: u8,
    },
    /// Spec A's RAR 1.5 algorithm, which the RAR 1.3 and 1.4 container uses
    /// too (spec F 3.3.5 maps unpack versions 13, 14 and 15 to it, and
    /// 3.4.2's container declares version 2 with a method of its own).
    Rar15,
    /// Spec H3 part A's RAR 2.0 codec, with spec D's multimedia predictor:
    /// unpack versions 20 and 26.
    Rar20 { dictionary: u32 },
    /// Spec H1's RAR 2.9 / 3.x / 4.x codec, which carries spec I's text
    /// model and spec J's filters inside it: unpack version 29 and above.
    Rar3 { dictionary: u32 },
    /// A member this build cannot decode. It is refused BY NAME through its
    /// own `close`, never skipped with no trace (spec F 8).
    Missing(ErrorKind),
}

/// The decoder states of one operation.
///
/// Built once per method and dictionary size and reused across members
/// (spec F 7.3.5): a dictionary never shrinks and regrows inside one
/// operation, and a solid chain's decoder is simply not reset.
#[derive(Default)]
pub(crate) struct Decoders {
    /// The lanes every member decoding at once may open between them
    /// (SPEC-API 8.3). `None` is the arrangement that divides the ceiling
    /// at dispatch instead; see `read::lanes`.
    #[cfg(feature = "parallel")]
    pub(crate) budget: Option<std::sync::Arc<crate::read::lanes::LaneBudget>>,
    /// The width the tape decode may spread one member over:
    /// `ReadOptions::workers` as the read resolved it (API 8.4.2), or the
    /// share of it a worker was dispatched with (8.3). Set by whoever owns
    /// this set of decoders before it decodes anything; zero, which is
    /// what `Default` gives, reads as one, and a narrower decode is in
    /// contract.
    pub(crate) decode_width: usize,
    /// Whether the caller STATED that width (`ReadOptions::workers` was
    /// `Some`). A stated width reaches the tape's lanes as it always did;
    /// the engine's own default counts physical cores there
    /// (`rar5_lz::tape::workers`). `Default` gives false, the default.
    pub(crate) width_stated: bool,
    /// The lanes a solid chain's decode-ahead opens, when they are not
    /// `decode_width` (`read::lanes::ahead_lanes`). `None`, which is what
    /// `Default` gives and what a worker inside `concurrent` keeps,
    /// follows `decode_width` exactly as before the policy existed.
    #[cfg(feature = "parallel")]
    pub(crate) ahead_lanes: Option<usize>,
    /// The cursor that walks the headers in front of a SOLID CHAIN and
    /// offers the members it finds to the RAR 5 decoder's decode-ahead
    /// (SPEC-H2 3.8, `read::ahead`). One for the operation, so the lever
    /// adds no allocation per member (7.3.5).
    #[cfg(feature = "parallel")]
    pub(super) lookahead: crate::read::ahead::Lookahead,
    pub(super) rar5: Option<Rar5Lz>,
    /// The declared dictionary `rar5` was built for.
    pub(super) rar5_window: u64,
    /// The reach `rar5`'s window was sized to: at most
    /// `rar5_window`, and what a later member may reuse without a new ring.
    pub(super) rar5_reach: u64,
    /// How eagerly a held RAR 5 ring is rebuilt smaller ([`Shrink`]).
    pub(crate) shrink: Shrink,
    pub(super) rar15: Option<Rar1x>,
    pub(super) rar3: Option<Rar3Stream>,
    pub(super) rar20: Option<Rar20Stream>,
    /// What the decoders above hold, charged to `memory::current` (API
    /// section 8: the process counters include every window the engine
    /// commits). Kept HERE, beside the decoders and not inside them, so
    /// the decode loops read exactly the structures they did before: a
    /// field added to a decoder moves the code of every loop that touches
    /// it. Set by [`Decoders::recharge`] whenever a decoder is built or
    /// replaced and after every member, and released when the decoders
    /// drop, idle ones kept for reuse included.
    pub(super) charge: crate::memory::Held,
    /// The live bytes of the [`Scratch`] these decoders run with (its
    /// packed, copy and target buffers), charged the same way after every
    /// member: each `Decoders` is paired with exactly one `Scratch`, on a
    /// worker's bench and on the walking thread alike, so the scratch is
    /// charged once, by whoever decodes with it.
    pub(super) scratch_charge: crate::memory::Held,
}

/// A held RAR 5 ring is rebuilt smaller, not reused, when it reaches at
/// least this far and at least [`SHRINK_RATIO`] times what the member
/// needs. Below it the rebuild's fresh pages cost more than holding: on a
/// Zen 4 (kernel 6.8) rebuilding at 8 MiB and 4x cost `t` of bin4g 6
/// percent in re-faults, at 32 MiB and 8x nothing (measured when the
/// member-sized window was adopted).
pub(super) const SHRINK_FROM: u64 = 32 << 20;

/// See [`SHRINK_FROM`].
pub(super) const SHRINK_RATIO: u64 = 8;

/// How eagerly a worker's held RAR 5 ring is rebuilt smaller, and whether
/// every rebuild gives the old ring's pages back.
///
/// **Why two.** The pool's workers (`t`, `x`) and the walking thread take
/// [`Shrink::Wide`]: rebuilding often re-faults the next ring's pages, which
/// cost bin4g's `t` 6 percent on a Zen 4 at 8 MiB and 4x and nothing at
/// 32 MiB and 8x. The sequential look-ahead's workers (`p`) take
/// [`Shrink::Tight`]: their admission keeps its high-water figure, and
/// only rebuilding small and releasing every ring kept `p` of bin4g under
/// the control's resident figure on x86, where glibc keeps a freed ring resident.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Shrink {
    /// Rebuild at [`SHRINK_FROM`] and [`SHRINK_RATIO`]; release a ring only
    /// when dropping it for being far larger.
    #[default]
    Wide,
    /// Rebuild at 8 MiB and 4x; release every ring dropped. Only the
    /// sequential look-ahead's workers ask for it, and they exist only
    /// with the `parallel` feature.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    Tight,
    /// For ONE member, on a pool's order: a held ring larger than this
    /// member reaches is rebuilt at the member's reach, whatever its size.
    /// The pools order it under a NAMED budget when the rings the workers
    /// keep between members no longer fit beside a member's need: a ring
    /// kept for reuse costs nothing new to admit and so was never refused,
    /// and sixteen workers each keeping a ring of a few MiB for members of
    /// a few KiB held more than the budget while every dispatch read as
    /// free (counted on bin4g).
    /// Memory is
    /// bytes, so the lever is the ring, not the breadth (8.4.1).
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    Exact,
}

impl Shrink {
    pub(super) fn from(self) -> u64 {
        match self {
            Shrink::Wide => SHRINK_FROM,
            Shrink::Tight => 8 << 20,
            Shrink::Exact => 0,
        }
    }

    pub(super) fn ratio(self) -> u64 {
        match self {
            Shrink::Wide => SHRINK_RATIO,
            Shrink::Tight => 4,
            Shrink::Exact => 1,
        }
    }
}

/// What a worker holding `held` working bytes will hold once it takes a
/// member charged `need`: the need itself where `Decoders::rar5` will
/// rebuild its ring smaller for it ([`SHRINK_FROM`], [`SHRINK_RATIO`]),
/// otherwise the larger of the two. The pools' admission charges THIS, so
/// `MemoryPolicy::working_limit` bounds what the workers actually hold,
/// not what their members declare (the member-sized window, made to count what it
/// holds).
#[cfg(feature = "parallel")]
pub(crate) fn charge_after(held: u64, need: u64) -> u64 {
    if held >= SHRINK_FROM && held >= need.saturating_mul(SHRINK_RATIO) {
        need
    } else {
        held.max(need)
    }
}

impl Decoders {
    /// What the walk's own RAR 5 ring will be after a member of `reach`
    /// under `window`, given the ring it keeps now (`kept_reach`), by the
    /// rule `rar5` applies under `Shrink::Tight`: the look-ahead mirrors
    /// it to price the walk's own member before the walk decodes it
    /// (`read::sequential`). Returns the reach the ring is built or kept
    /// at; the bytes are `ring_bytes` of that.
    #[cfg(feature = "parallel")]
    pub(crate) fn tight_reach_after(
        kept_reach: u64,
        window: u64,
        reach: u64,
        solid: bool,
        policy: &crate::MemoryPolicy,
    ) -> u64 {
        let floor_reach = ((crate::rar5_lz::output::RING_FLOOR - crate::rar5_lz::output::SPILL)
            as u64)
            .min(policy.max_window);
        let reach = reach.max(floor_reach).min(window);
        let far_larger = !solid
            && kept_reach >= Shrink::Tight.from()
            && kept_reach >= reach.saturating_mul(Shrink::Tight.ratio());
        if kept_reach >= reach && !far_larger {
            kept_reach
        } else {
            reach
        }
    }

    /// The bytes a RAR 5 ring at `reach` under `ceiling` holds
    /// (`rar5_lz::ring_len`), 0 for no ring.
    #[cfg(feature = "parallel")]
    pub(crate) fn ring_bytes(reach: u64, ceiling: u64) -> u64 {
        if reach == 0 {
            return 0;
        }
        crate::rar5_lz::ring_len(reach, ceiling).map_or(reach, |n| n as u64)
    }

    /// The RAR 5 decoder for a member declaring a `window` byte dictionary
    /// and reaching `reach` bytes, continuing the solid chain when `solid`
    /// (spec F 3.6).
    ///
    /// A decoder already holding a window of at least `reach` is reused, so
    /// a non-solid archive's members commit ONE ring, as large as the
    /// largest reach among them and never larger than the dictionary. A
    /// solid archive's members all carry `reach == window`, so there the
    /// rule is exactly the declared dictionary's.
    pub(super) fn rar5(
        &mut self,
        window: u64,
        reach: u64,
        solid: bool,
        policy: &crate::MemoryPolicy,
    ) -> Result<&mut Rar5Lz> {
        // A solid member whose dictionary differs from the chain's cannot
        // continue it: the chain IS the window the member before it left.
        #[cfg(feature = "parallel")]
        let budget = self.budget.clone();
        // A member whose reach fits the floor ring is built at the most the
        // floor ring holds (capped at the dictionary): the same ring, and a
        // decoder the next small member can reuse instead of rebuilding.
        // The floor raise never passes the caller's window ceiling, so a
        // member the policy admits is never refused for it.
        let floor_reach = ((crate::rar5_lz::output::RING_FLOOR - crate::rar5_lz::output::SPILL)
            as u64)
            .min(policy.max_window);
        let reach = reach.max(floor_reach).min(window);
        // A held ring FAR larger than this member needs is not reused: it
        // stays resident for the rest of the operation otherwise, one per
        // worker (32 MiB rings
        // held by every worker over a 4 GiB archive of small members).
        // Outside a solid stream only; a chain needs its window.
        let far_larger = !solid
            && match self.shrink {
                Shrink::Exact => self.rar5_reach > reach,
                _ => {
                    self.rar5_reach >= self.shrink.from()
                        && self.rar5_reach >= reach.saturating_mul(self.shrink.ratio())
                }
            };
        let reusable = self.rar5.is_some()
            && self.rar5_window == window
            && self.rar5_reach >= reach
            && !far_larger;
        if !reusable {
            // The old ring goes first, so the two are never held at once.
            // A ring dropped for being far larger gives its pages back to
            // the kernel first (`crate::pages::release`, on
            // Linux, and on macOS, where the allocator's large cache
            // would otherwise keep them resident); under `Shrink::Wide` a
            // ring dropped for being too small is not released, since its
            // heap block is the next ring's and would only fault in again.
            // Linux and macOS only at the call site too, so every other
            // target compiles exactly the code it did without the helper.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if far_larger || self.shrink != Shrink::Wide {
                if let Some(old) = self.rar5.as_mut() {
                    old.release_ring();
                }
            }
            self.rar5 = None;
            self.recharge();
            self.rar5 = Some(Rar5Lz::with_reach(window, reach, policy)?);
            self.rar5_window = window;
            self.rar5_reach = reach;
            self.recharge();
        } else if !solid {
            self.rar5.as_mut().expect("just checked").reset();
        }
        // The width every time, not at construction: the decoder outlives
        // the member, and the member is what carries a width (8.4.2).
        self.rar5
            .as_mut()
            .expect("built or reused just above")
            .set_tape_width(self.decode_width.max(1));
        self.rar5
            .as_mut()
            .expect("built or reused just above")
            .set_width_stated(self.width_stated);
        #[cfg(feature = "parallel")]
        if let Some(lanes) = self.ahead_lanes {
            self.rar5
                .as_mut()
                .expect("built or reused just above")
                .set_ahead_lanes(lanes);
        }
        #[cfg(feature = "parallel")]
        self.rar5
            .as_mut()
            .expect("built or reused just above")
            .set_lane_budget(budget);
        Ok(self.rar5.as_mut().expect("built above"))
    }

    /// The RAR 5 decoder, with the members in front of this one offered
    /// to its decode-ahead.
    ///
    /// The offering happens HERE and not in the caller, because it has to
    /// happen after `rar5` above has decided which decoder this member
    /// runs on: a member whose window differs from the chain's gets a new
    /// decoder, and offering first would fill the queue of the one the
    /// next line throws away. (A member that merely restarts the chain
    /// keeps its queue: see `Rar5Lz::reset`.)
    #[cfg(feature = "parallel")]
    pub(super) fn rar5_chain(
        &mut self,
        window: u64,
        reach: u64,
        solid: bool,
        policy: &crate::MemoryPolicy,
        feed: Option<&crate::read::ahead::Feed>,
    ) -> Result<&mut Rar5Lz> {
        self.rar5(window, reach, solid, policy)?;
        let Decoders {
            rar5, lookahead, ..
        } = self;
        let lz = rar5.as_mut().expect("built or reused just above");
        match feed {
            Some(feed) => lookahead.feed(feed, lz),
            // Not a chain, or not a source the cursor can read: the member
            // decodes exactly as it did before this stage existed.
            None => lookahead.stop(),
        }
        Ok(lz)
    }

    /// The RAR 1.5 decoder, whose window is a fixed 64 KiB, so one serves
    /// every member of the operation.
    pub(super) fn rar15(&mut self) -> &mut Rar1x {
        if self.rar15.is_none() {
            self.rar15 = Some(Rar1x::new());
            self.recharge();
        }
        self.rar15.as_mut().expect("built above")
    }

    /// The RAR 3 stream, whose window, tables, text model arena and filter
    /// staging are allocated once and reused. A NON solid member begins a
    /// new stream in the same allocations; a solid one continues the chain
    /// (spec H1 3.1).
    pub(super) fn rar3(
        &mut self,
        dictionary: u32,
        solid: bool,
        policy: &crate::MemoryPolicy,
    ) -> Result<&mut Rar3Stream> {
        match &mut self.rar3 {
            Some(stream) => {
                if !solid {
                    stream.begin_stream(dictionary);
                }
            }
            slot => *slot = Some(Rar3Stream::new(dictionary, policy)?),
        }
        self.recharge();
        Ok(self.rar3.as_mut().expect("built above"))
    }

    /// Whether a RAR 3 stream is held.
    pub(super) fn holds_rar3(&self) -> bool {
        self.rar3.is_some()
    }

    /// Give the RAR 3 stream back, window and all, and bring the charge
    /// down with it.
    pub(super) fn release_rar3(&mut self) {
        self.rar3 = None;
        self.recharge();
    }

    /// Bring the charge for the scratch these decoders run with to what
    /// it holds now, as the end of a member's decode does.
    pub(super) fn recharge_scratch(&mut self, scratch: &Scratch) {
        self.scratch_charge.set(scratch.live_bytes());
    }

    /// The RAR 2.0 stream, on the same terms.
    pub(super) fn rar20(&mut self, dictionary: u32, solid: bool) -> &mut Rar20Stream {
        let fresh = self.rar20.is_none();
        let stream = self
            .rar20
            .get_or_insert_with(|| Rar20Stream::new(dictionary));
        if !fresh && !solid {
            stream.begin_stream(dictionary);
        }
        self.recharge();
        self.rar20.as_mut().expect("built above")
    }

    /// The dictionaries these decoders hold, which the report counts as
    /// part of the operation's working memory: a decoder's window is the
    /// largest thing an extraction allocates.
    pub(crate) fn window_bytes(&self) -> u64 {
        // The SOLID CHAIN's decode-ahead and the cursor that feeds it, both
        // of which hold bytes for as long as an operation does and neither
        // of which is a dictionary. Reported because API 5.2's figure is
        // the operation's working set and not the windows alone.
        #[cfg(feature = "parallel")]
        let ahead = self
            .rar5
            .as_ref()
            .map_or(0, Rar5Lz::ahead_peak_bytes)
            .saturating_add(self.lookahead.held_bytes());
        #[cfg(not(feature = "parallel"))]
        let ahead = 0;
        self.held_bytes() + ahead
    }

    /// What the decoders hold NOW: every window, and the RAR 3 stream's
    /// tables, staging and text model beside its window. The figure the
    /// process counters are charged with, and the report's figure less
    /// the decode-ahead's high-water mark, which is a peak and not a
    /// holding.
    pub(super) fn held_bytes(&self) -> u64 {
        let rar5 = self.rar5.as_ref().map_or(0, |lz| lz.window_bytes() as u64);
        let rar15 = self.rar15.as_ref().map_or(0, |lz| lz.window_bytes() as u64);
        let rar3 = self.rar3.as_ref().map_or(0, Rar3Stream::held_bytes);
        let rar20 = self.rar20.as_ref().map_or(0, Rar20Stream::held_bytes);
        rar5 + rar15 + rar3 + rar20
    }

    /// Bring the process counters' charge to what the decoders hold.
    pub(super) fn recharge(&mut self) {
        let held = self.held_bytes();
        self.charge.set(held);
    }
}

/// What a WORKER commits when it takes a member, in bytes.
///
/// The pool charges this before the decoder exists, so the sum stays inside
/// `MemoryPolicy::working_limit` (SPEC-API 5.2; a stated
/// budget is hard). For RAR 5 it is what the decoder will actually hold: the
/// ring as [`crate::rar5_lz::ring_len`] sizes it for the member's REACH
/// under `ceiling` (the same function `Window::new` calls), the packed
/// buffer `Buffered::fill` grows (geometric, so at most twice the member's
/// packed bytes, never past `MAX_PACKED`, plus the cipher's `SPILL`), and
/// the worker's read window. Before the member-sized window the charge was the declared
/// dictionary alone, whose slack over a smaller member hid the other terms;
/// charged at the reach alone they let a third member in over the budget
/// (`read_width::a_small_budget_binds_however_wide_the_dial_is_set`).
#[cfg(feature = "parallel")]
pub(crate) fn window_of(codec: &Codec, packed: u64, ceiling: u64) -> u64 {
    match codec {
        Codec::Stored | Codec::Missing(_) => 0,
        Codec::Rar5 { reach, .. } => {
            let ring = crate::rar5_lz::ring_len(*reach, ceiling).map_or(*reach, |n| n as u64);
            let packed = packed.saturating_mul(2).min(MAX_PACKED as u64)
                + crate::rar5_lz::output::SPILL as u64;
            ring.saturating_add(packed)
                .saturating_add(WORKER_READ_BUF as u64)
        }
        // Spec A's window is a fixed 64 KiB whatever the member declares.
        Codec::Rar15 => 64 * 1024,
        Codec::Rar20 { dictionary } | Codec::Rar3 { dictionary } => u64::from(*dictionary),
    }
}

/// The window `member` can reach (member-sized outside a solid
/// archive, the declared dictionary inside one; 64 KiB for RAR 1.3), which
/// `MemoryPolicy::max_window` must admit or the member is refused
/// (promise 2.3). Zero for a stored member or a directory.
pub(crate) fn member_reach(
    member: &crate::MemberInfo<'_>,
    format: Format,
    solid_archive: bool,
) -> u64 {
    if member.is_directory {
        return 0;
    }
    let Method::Compressed { dictionary, .. } = member.method else {
        return 0;
    };
    match format {
        Format::Rar5 if !solid_archive => member
            .unpacked_size
            .map_or(dictionary, |n| n.min(dictionary)),
        Format::Rar13 => 64 * 1024,
        _ => dictionary,
    }
}

/// What reading `member` alone needs in working memory beyond the walk's own
/// fixed buffers (the one-member floor): the window it can reach
/// (member-sized outside a solid archive, the declared
/// dictionary inside one), priced as admission prices it
/// ([`window_of`]), and nothing for a stored member or a directory.
pub(crate) fn member_need(
    member: &crate::MemberInfo<'_>,
    format: Format,
    solid_archive: bool,
    ceiling: u64,
) -> u64 {
    if member.is_directory {
        return 0;
    }
    let Method::Compressed { dictionary, .. } = member.method else {
        return 0;
    };
    match format {
        Format::Rar5 => {
            let reach = if solid_archive {
                dictionary
            } else {
                member
                    .unpacked_size
                    .map_or(dictionary, |n| n.min(dictionary))
            };
            // ONE member alone, the account at a width of one: its ring
            // and the read window, and NOT the packed block buffer, which
            // is charged as it grows and held under the budget where it
            // grows (`Buffered::grow`; SPEC-API 8.4.1, the account's item
            // 7). A second member in flight is priced by [`window_of`],
            // which keeps that buffer in its price: two members grow
            // theirs at once, and neither sees the other's coming.
            #[cfg(feature = "parallel")]
            {
                let ring = crate::rar5_lz::ring_len(reach, ceiling).map_or(reach, |n| n as u64);
                ring.saturating_add(WORKER_READ_BUF as u64)
            }
            #[cfg(not(feature = "parallel"))]
            {
                let _ = ceiling;
                reach
            }
        }
        // Spec A's fixed 64 KiB window.
        Format::Rar13 => 64 * 1024,
        // The RAR 4 family's window is the declared dictionary.
        _ => dictionary,
    }
}

/// The decoder a member's method and unpack version select (spec F 3.3.5).
///
/// A method byte no decoder claims (the older containers only: every
/// RAR 5 method value is claimed), and an unpack version the table does
/// not name, are each that member's own refusal and no other member's.
/// An unknown version refuses only where a codec would run: a DIRECTORY
/// entry of any version opens, its version ignored, since nothing ever
/// decodes a directory's data area (spec F 3.2.6 and 3.3.5).
pub(crate) fn codec_of(file: &FileHdr, format: Format, solid_archive: bool) -> Codec {
    if matches!(file.method, Method::Stored) {
        return Codec::Stored;
    }
    let unknown = || {
        if file.is_directory {
            Codec::Stored
        } else {
            Codec::Missing(ErrorKind::Unsupported(Unsupported::Version(
                file.unpack_version,
            )))
        }
    };
    if matches!(format, Format::Rar5) {
        // The ALGORITHM the header walk read out of the compression
        // information: 0 or 1, bit 20 folded in (spec F 3.2.6.3). A
        // version this package does not know names no dictionary, and is
        // THIS member's refusal and no other's (spec F 3.2.6 and question
        // 9, decided 28 Sep 2026).
        let (Some(_), Ok(algorithm @ (0 | 1))) =
            (file.dictionary, u8::try_from(file.unpack_version))
        else {
            return unknown();
        };
        // Spec F 3.2.6 (restated 8 Oct 2026): the method field is three
        // bits, and every value but 0 is a COMPRESSED member handed to
        // this one decoder, 6 and 7 as 1 to 5. The value says how hard
        // the writer tried and chooses nothing here; the reference
        // decodes such a member as it decodes any other, so no RAR 5
        // method value is a refusal.
        // A compressed member of UNKNOWN SIZE is decoded to the end of its
        // packed stream (`UNTIL_ITS_END`). Genuine rar writes one: a
        // member read from standard input and split, whose leading
        // fragment headers carry the unknown size flag and whose last
        // header has the size (spec F 3.5.4 J5). One that is not split,
        // which no genuine writer was seen to make, is read the same way,
        // as the reference reads it (10 Oct 2026); it was refused here as
        // a damaged header.
        // The dictionary the header walk computed (spec F 3.2.6.3), which a
        // version 1 member may declare off the powers of two.
        let Method::Compressed {
            dictionary: window, ..
        } = file.method
        else {
            unreachable!("a stored member returned above")
        };
        // What the member can REACH (SPEC-API 8.1, erratum of 26 Sep 2026).
        // In a solid archive a later member may continue this
        // window, and the chain's cumulative output is not known here, so
        // the reach there is the dictionary itself: the chain's reach once
        // it exceeds the dictionary, and the conservative figure before.
        let reach = if solid_archive {
            window
        } else {
            file.unpacked_size.map_or(window, |n| n.min(window))
        };
        return Codec::Rar5 {
            window,
            reach,
            algorithm,
        };
    }
    if matches!(format, Format::Rar13) {
        // The oldest container declares unpack version 2 and a method of 1
        // to 5, and its members are the RAR 1.5 algorithm (spec F 3.4.2).
        return Codec::Rar15;
    }
    // The RAR 4 family's dictionary bits are 64 KiB shifted left by the
    // bit value (spec F 3.3.5), which the header walk has already turned
    // into the method's dictionary.
    let dictionary = match file.method {
        Method::Compressed { dictionary, .. } => u32::try_from(dictionary).unwrap_or(u32::MAX),
        Method::Stored => 64 * 1024,
    };
    match rar4::codec_for(file.unpack_version) {
        Some(rar4::Rar4Codec::Rar15) => Codec::Rar15,
        Some(rar4::Rar4Codec::Rar20) => Codec::Rar20 { dictionary },
        Some(rar4::Rar4Codec::Rar29) => Codec::Rar3 { dictionary },
        None => unknown(),
    }
}

/// The output a compressed member of UNKNOWN size is decoded against:
/// more than any member holds. A RAR 5 member's blocks then run to the
/// one flagged last and the decoder names the end `IncompleteMember`,
/// which `decode` hands to the member's checksum as it does any valid
/// short end (spec F 4.2). The older container's decoders are given the
/// same figure, so that a member whose header declares no size (spec F
/// 3.5.4 J6) is not cut at nothing; WHAT ENDS THEIR STREAMS is each
/// decoder's own statement. Genuine sets of unpack version 29 are read
/// this way to their stream's end mark (`tests/stdin_split_member_rar4.rs`,
/// `-m3` and `-m5` over three volumes); no genuine set of unpack version
/// 15 or 20 with a compressed member of no size has been read here.
/// A split member's size, the last header's, is compared with the bytes
/// delivered in `verdict` (spec F 3.5.4 J5); one that is not split
/// declares none anywhere. Half the range, so no sum with it can wrap.
const UNTIL_ITS_END: u64 = u64::MAX / 2;

/// Decode one member's packed bytes into its output.
///
/// Nothing here knows whether the packed bytes come from the walk or from a
/// worker's own read of the member's byte range, and nothing here knows
/// which thread it is on: that is what makes one decoder serve both drivers
/// and what keeps their output byte-identical.
#[allow(clippy::too_many_arguments)]
/// What the solid chain's lookahead needs to read the members in front of
/// the one being decoded, or `None` where there is no chain to read.
///
/// A type alias so the one decode entry point has the same arity in both
/// builds: without `parallel` there is no decode-ahead for any value of
/// it (SPEC-H2 7.3 item 10).
#[cfg(feature = "parallel")]
pub(crate) type AheadFeed<'a> = Option<&'a crate::read::ahead::Feed>;

/// The same, in a build with no decode-ahead to feed.
#[cfg(not(feature = "parallel"))]
pub(crate) type AheadFeed<'a> = Option<&'a ()>;

/// The pool's lane budget as [`copy`] is handed it, or `None` where the
/// member's width is not the budget's to grant. An alias so `copy` has the
/// same arity in both builds: without `parallel` there is no budget and
/// nothing wide.
#[cfg(feature = "parallel")]
pub(super) type Lanes<'a> = Option<&'a crate::read::lanes::LaneBudget>;

/// The same, in a build with no lanes to budget.
#[cfg(not(feature = "parallel"))]
pub(super) type Lanes<'a> = Option<&'a ()>;

#[allow(clippy::too_many_arguments)]
#[inline]
pub(crate) fn decode<R: PackedRead, W: std::io::Write, T: Tally>(
    stream: R,
    member: &mut Member<W>,
    blake: &mut Option<Box<Blake2sp>>,
    tally: &mut T,
    decryptor: Option<MemberDecryptor>,
    codec: Codec,
    decoders: &mut Decoders,
    scratch: &mut Scratch,
    policy: &crate::MemoryPolicy,
    solid: bool,
    ahead: AheadFeed<'_>,
) -> Result<()> {
    let _ = &ahead;
    // One member's packed bytes are about to be read: a test asserting
    // that a skipped member was never decoded counts exactly this
    // (spec F 3.6, 3.7.1).
    #[cfg(feature = "test-support")]
    crate::probe::note_decoded();
    // One member is decoding for as long as this lives, whichever thread
    // it is on: the walk's own decode counts against the ceiling exactly
    // as a dispatched member's does (SPEC-API 8.3).
    #[cfg(feature = "parallel")]
    let budget = decoders.budget.clone();
    #[cfg(feature = "parallel")]
    let _slot = budget.as_ref().map(|b| b.member_in());
    #[cfg(not(feature = "parallel"))]
    let budget: Option<std::sync::Arc<()>> = None;
    let packed = Packed::new(stream, decryptor);
    let outcome = match codec {
        Codec::Stored => copy(
            packed,
            member,
            blake,
            tally,
            &mut scratch.copy,
            &mut scratch.copy_pair,
            policy.read_ahead,
            decoders.decode_width,
            decoders.width_stated,
            budget.as_deref(),
        ),
        Codec::Rar5 {
            window,
            reach,
            algorithm,
        } => {
            let unpacked = member.unpacked_size.unwrap_or(UNTIL_ITS_END);
            // Only a RAR 5 member's fills read deep: it is the one
            // measured (S8, a Zen 4 rental).
            #[cfg(feature = "parallel")]
            let parts = crate::read::cursor::deep::parts(decoders.decode_width);
            #[cfg(not(feature = "parallel"))]
            let parts = 1;
            let mut source =
                Buffered::over(packed, std::mem::take(&mut scratch.packed), policy, parts);
            let outcome = (|| -> Result<()> {
                #[cfg(feature = "parallel")]
                let lz = decoders.rar5_chain(window, reach, solid, policy, ahead)?;
                #[cfg(not(feature = "parallel"))]
                let lz = decoders.rar5(window, reach, solid, policy)?;
                let mut sink = Decoded {
                    member,
                    blake,
                    tally,
                };
                // Only the reader knows whether the member carries a
                // checksum, and the decoder's answer to a filter span the
                // stream completes past the declared size turns on it
                // (spec H2 3.1).
                if !sink.member.carries_a_checksum() {
                    lz.next_member_is_unchecked();
                }
                lz.member(&mut source, unpacked, algorithm, &mut sink)
            })();
            // The buffer goes back whatever happened, so the next member
            // reuses it.
            scratch.packed = source.buf;
            outcome
        }
        Codec::Rar15 => {
            let target = member.unpacked_size.unwrap_or(UNTIL_ITS_END);
            let mut source = Buffered::over(packed, std::mem::take(&mut scratch.packed), policy, 1);
            let outcome = {
                let lz = decoders.rar15();
                let mut sink = Decoded {
                    member,
                    blake,
                    tally,
                };
                lz.member(&mut source, target, solid, &mut sink)
            };
            scratch.packed = source.buf;
            outcome
        }
        Codec::Rar3 { dictionary } => {
            let unpacked = member.unpacked_size.unwrap_or(UNTIL_ITS_END);
            let mut source = Buffered::over(packed, std::mem::take(&mut scratch.packed), policy, 1);
            let outcome = (|| -> Result<()> {
                let stream = decoders.rar3(dictionary, solid, policy)?;
                let mut bits = Rar3Bits::streaming(&mut source);
                // The member is ONE stream to the reader and its end is
                // the stream's; `usize::MAX` is the end it cannot know
                // until the pull stream stops, which `Bits::streaming`
                // explains.
                let span = MemberSpan {
                    packed: 0..usize::MAX,
                    unpacked,
                };
                let mut sink = Decoded {
                    member,
                    blake,
                    tally,
                };
                let outcome = stream.member(&mut bits, &span, &mut sink);
                // A failure by a filter span of the member's own is its
                // verdict even where it declares no bytes (spec J 3.8).
                sink.member.span_left_member = stream.span_left_member();
                // A pull stream's own failure is the true cause, whatever
                // the decode made of the zero bits that followed it.
                match bits.fault() {
                    Some(fault) => Err(fault),
                    None => outcome,
                }
            })();
            scratch.packed = source.buf;
            outcome
        }
        Codec::Rar20 { dictionary } => {
            let unpacked = member.unpacked_size.unwrap_or(UNTIL_ITS_END);
            let mut source = Buffered::over(packed, std::mem::take(&mut scratch.packed), policy, 1);
            let outcome = {
                let stream = decoders.rar20(dictionary, solid);
                let mut bits = SliceBits::streaming(&mut source);
                let mut sink = Decoded {
                    member,
                    blake,
                    tally,
                };
                let outcome = stream.member_from(&mut bits, unpacked, &mut sink);
                // A pull stream's own failure is the true cause, whatever
                // the decode made of the zero bits that followed it.
                match bits.fault() {
                    Some(fault) => Err(fault),
                    None => outcome,
                }
            };
            scratch.packed = source.buf;
            outcome
        }
        Codec::Missing(kind) => Err(Error::new(kind)),
    };
    // A decoder may grow what it holds INSIDE a member, the RAR 3 text
    // model's arena being the one that does, so the charge is brought up
    // to date after every member as well as whenever one is built.
    decoders.recharge();
    // Under a NAMED budget the scratch gives its high-water back after
    // every member, as the rings do (`Shrink::Tight`): a packed or copy
    // buffer grown to a few MiB by one member and kept for the next is
    // resident on every worker for the rest of the operation, and twenty
    // of them held more than a 71 MiB limit before any window was counted
    // (bin4g).
    // A later larger member grows it again, geometrically, as the first
    // one did.
    //
    // Except inside a SOLID CHAIN: a member that continues one keeps the
    // scratch for the next, and the chain gives it back where a member that
    // does not continue it ends (the chain's start, or the non-solid member
    // after it), or when the operation drops it. One thread decodes a
    // chain, so what it keeps is ONE scratch, at most `MAX_PACKED` and in
    // practice the tape path's 4 MiB request, charged below as before;
    // and its next member grows it straight back, so the per-member give
    // back lowered no peak and paid for the re-growth each time: on a 2
    // GiB `-s` text set of 1,342 members, 2.67 GB of zeroing and 655,000
    // page faults a run on the critical path (measured 30 Sep
    // 2026). What the residency rule protects, the sum of high-water
    // buffers across every decoding thread, is unchanged: pool and
    // look-ahead workers never continue a chain and still give back after
    // every member.
    if decoders.shrink != Shrink::Wide && !(solid && keeps_chain_scratch()) {
        #[cfg(feature = "test-support")]
        crate::probe::note_scratch_give_back();
        scratch.give_back();
    }
    decoders.scratch_charge.set(scratch.live_bytes());
    // A MEMBER THAT ENDS SHORT, BY A MARK VALID IN ITS CODING, IS JUDGED
    // BY ITS CHECKSUM when it carries one (spec F 4.2, restated 8 Oct
    // 2026): the bytes produced are delivered and `verdict` compares the
    // stored checksum with them, so the decoder's own name for the short
    // end is not a failure here. With no checksum nothing vouches for
    // the short file and the name stands, failing the member. One site
    // for every read path, since every one of them decodes through here.
    match outcome {
        Err(e) if member.carries_a_checksum() && ended_short(&e) => Ok(()),
        outcome => outcome,
    }
}

/// Whether `err` is a decoder's name for a member whose data came to a
/// VALID end before its declared size: in RAR 5, the block flagged last
/// ending with the member short (spec H2 3.1, `IncompleteMember`). The
/// RAR 3 family's decoders raise none and a stored member has none. Packed
/// data that RUNS OUT is `Truncated` and is not this, nor is a kept
/// filter span the stream never completed (`FilterRange`).
#[cold]
#[inline(never)]
fn ended_short(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Corrupt(Corruption::Rar5(crate::Rar5Fault::IncompleteMember))
    )
}

/// One RAR 2.0 stream: spec H3 part A's decoder and its window, driven by
/// the loop that specification leaves to this package (its
/// `internals_h3` says so in as many words). A member reads from the first
/// bit of its OWN packed bytes; what crosses a member boundary is the
/// decoder's state, not the bit stream.
pub(super) struct Rar20Stream {
    pub(super) decoder: Rar20Lz,
    pub(super) window: Rar20Window,
    /// What the header declared, kept as declared. It does not bound the
    /// window: see [`RAR20_WINDOW`].
    pub(super) dictionary: u32,
}

/// The RAR 2.0 window, always the format maximum (`65,536 << 4`) and not the
/// declared dictionary (spec H3 3.5: tolerate). A conformant
/// stream never reaches past its declared dictionary, so this costs no
/// output byte on one, and a stream that does is read as the reference reads
/// it. A distance past what the stream produced, or past this allocation,
/// is still refused.
pub(super) const RAR20_WINDOW: u32 = 1 << 20;

impl Rar20Stream {
    pub(super) fn new(dictionary: u32) -> Rar20Stream {
        Rar20Stream {
            decoder: Rar20Lz::new(),
            window: Rar20Window::new(RAR20_WINDOW),
            dictionary,
        }
    }

    /// Begin a new stream in the same allocations, re-allocating the
    /// window (always the format maximum, whatever the header declares).
    pub(super) fn begin_stream(&mut self, dictionary: u32) {
        self.decoder = Rar20Lz::new();
        if self.dictionary == dictionary {
            let held = self.window.held_bytes();
            self.window.take(held);
        }
        self.window = Rar20Window::new(RAR20_WINDOW);
        self.dictionary = dictionary;
    }

    /// What the stream holds: the allocation, not the declared dictionary.
    pub(super) fn held_bytes(&self) -> u64 {
        u64::from(RAR20_WINDOW)
    }

    /// Decode one member into `sink`, reading its packed bytes through
    /// `input` - which for `extract` is spec F's pull stream, so the
    /// member's packed size is never held (spec F 2.3).
    pub(super) fn member_from<W: std::io::Write, T: Tally>(
        &mut self,
        input: &mut SliceBits<'_>,
        unpacked: u64,
        sink: &mut Decoded<'_, W, T>,
    ) -> Result<()> {
        let mut produced = 0u64;
        let mut exhausted = false;
        while produced < unpacked {
            if !self.decoder.codes_stand() {
                // A block header is a step too, and it cannot begin on an
                // exhausted input (SPEC-H3 3.5).
                if input.available() == 0 {
                    self.decoder.no_header_left();
                    exhausted = true;
                    break;
                }
                // A header the end of the packed data cuts and that is
                // not taken ends the member here, short (SPEC-H3 3.5).
                if !self.decoder.begin_block_in_member(input)? {
                    exhausted = true;
                    break;
                }
            }
            let room = (unpacked - produced).min(self.window.room() as u64);
            let step = self.decoder.run(input, &mut self.window, room)?;
            let (first, second) = self.window.pending();
            let held = first.len() + second.len();
            if held == 0 && step == Lz20Step::Filled {
                // No progress, no block boundary and bits still left: the
                // stream cannot reach the size its header declares. An
                // input that simply RAN OUT is not this case any more - it
                // ends the member with a checksum failure -
                // so the test names `Filled` rather than excluding one
                // step kind.
                return Err(Error::new(ErrorKind::Truncated));
            }
            // The two halves of the ring, in order, each in one write and
            // straight out of the window: they were copied into two fresh
            // `Vec`s here, which for a 1 MiB dictionary is up to a
            // megabyte allocated and freed per step and is most of what
            // `tests/streaming_memory.rs` sees this path hold above the
            // window itself.
            sink.put(first)?;
            sink.put(second)?;
            produced += held as u64;
            let held = self.window.held_bytes();
            self.window.take(held);
            if step == Lz20Step::Exhausted {
                exhausted = true;
                break;
            }
        }
        if exhausted {
            // The packed input ran out before the declared size did. The
            // member is short and its checksum fails; this is not an
            // error (SPEC-A 6.1, SPEC-H3 3.5).
            //
            // Spec D part 2's trailing table switch runs at the member's
            // DECLARED end, so it does not run here. That is SPEC-D part
            // 2's own recommended reading of the one question left
            // open, and it is not answered yet.
            return Ok(());
        }
        // SPEC-H3 3.5: a match that passed the declared size enters the
        // stream whole. What is past the size is no member's output, so
        // it leaves the window undelivered, and the member fails after
        // its declared bytes.
        let past = self.decoder.match_past_the_size(&mut self.window)?;
        let held = self.window.held_bytes();
        self.window.take(held);
        // SPEC-D 2.2: the member's tail may carry the next member's
        // tables, and nothing the archive holds there fails this member.
        self.decoder.finish_member(input)?;
        match past {
            true => Err(crate::lz20::match_past_the_size()),
            false => Ok(()),
        }
    }
}
