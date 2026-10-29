//! What a format gives the drive (`Emit`), the table sets a solid run
//! carries, and a chain's deferred blocks written in order.

use super::*;

/// A format that can also write its tokens out.
pub(crate) trait Emit: Format {
    /// Whether [`Emit::emit_member`] ever carries a set. A
    /// format that does not is never handed a member to write late.
    const CARRIES: bool = false;

    /// Append the entropy blocks `cuts` names, in order. `last` says the
    /// member ends with these tokens. `records` are the filter records
    /// the first of them writes ahead of its first token (spec H3 section
    /// 6.6); a format with no filter records is never handed any.
    fn emit(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        last: bool,
        records: &[BlockRecord],
        out: &mut Vec<u8>,
    );

    /// [`Emit::emit`], where the parse has already counted the symbols of
    /// each entropy block: `counts` holds a table of [`Format::symbols`]
    /// counts for each of `cuts`, in order, the tokens' alone (no filter
    /// record's symbol), or is empty where it has not. `steady` asks for
    /// the format's writer with no branch on the bits it holds, where it
    /// has one, for tokens that are nearly all literals. The same bytes as
    /// [`Emit::emit`] either way; the default counts for itself.
    #[allow(clippy::too_many_arguments)]
    fn emit_counted(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        counts: &[u32],
        steady: bool,
        last: bool,
        records: &[BlockRecord],
        out: &mut Vec<u8>,
    ) {
        let _ = (counts, steady);
        self.emit(tokens, cuts, last, records, out);
    }

    /// Write one WHOLE member of a solid run, of fewer than
    /// [`CARRY_MEMBER_BYTES`] bytes, as [`Emit::emit`] would with `last`
    /// set, where spec H3 section 4 lets its first block
    /// decode under the table set the member before it left in force.
    ///
    /// `counts` are the member's symbol counts from [`Emit::add_counts`],
    /// taken on the thread that parsed it (empty for a member of several
    /// entropy blocks). `carried` is that set on entry, or `None` where no
    /// set a reader
    /// would hold is known here; `may_carry` is false where the member
    /// MUST open a fresh set (the envelope's every fifteenth member). The
    /// format decides between the two from this member's tokens and the
    /// carried set alone, and leaves in `carried` the set in force after
    /// the member, or `None` where it does not know it. The default opens
    /// a fresh set every time, which is always a valid archive.
    #[allow(clippy::too_many_arguments)]
    fn emit_member(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        records: &[BlockRecord],
        counts: &[u32],
        carried: &mut Option<CarriedSet>,
        may_carry: bool,
        out: &mut Vec<u8>,
    ) {
        let _ = (may_carry, counts);
        self.emit(tokens, cuts, true, records, out);
        *carried = None;
    }

    /// Add the symbol counts of a member [`Emit::emit_member`] would write
    /// under one set to `counts`, in the order of [`CarriedSet::counts`]:
    /// nothing for a member of several entropy blocks.
    fn add_counts(
        &self,
        tokens: &[Token],
        cuts: &[Range<usize>],
        records: &[BlockRecord],
        counts: &mut Vec<u32>,
    ) {
        let _ = (tokens, cuts, records, counts);
    }
}

/// The least declared size of a member that always opens a fresh table
/// set (spec H3 section 4): rar 7.23's envelope, which no
/// member rarkit writes may lean on a carried set past.
pub(crate) const CARRY_MEMBER_BYTES: usize = 32_768;

/// The most members that share one table set, the member that opened it
/// included ("a fresh set at least every 15 members").
pub(crate) const CARRY_MEMBERS_MOST: usize = 15;

/// How a chain is lent each member's output buffer: called with the
/// segment and what to write into it.
pub(super) type LendOut<'a> = dyn FnMut(usize, &mut dyn FnMut(&mut Vec<u8>)) + 'a;

impl ChainWork {
    /// Take every chain whose members are all parsed, in member order,
    /// stopping at the first that is not, and move the window past each.
    pub(super) fn take_ready(
        &mut self,
        cells: &[Mutex<Option<Deferred>>],
        missing: &[AtomicUsize],
    ) -> Vec<ChainJob> {
        let mut taken = Vec::new();
        while self.next < self.chains.len() && missing[self.next].load(Ordering::Acquire) == 0 {
            let number = self.next;
            self.next += 1;
            let chain = &self.chains[number];
            if chain.clear_window {
                self.window.clear();
            }
            let members: Vec<(usize, Deferred)> = (chain.start..chain.end)
                .map(|segment| {
                    let member = cells[segment]
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .take();
                    (segment, member.expect("parsed"))
                })
                .collect();
            let mut seed = None;
            if chain.carried.is_none() {
                if self.lookahead {
                    // The count's LOOKAHEAD arm: the opener's set from
                    // every member of its chain after it.
                    let mut counts: Vec<u32> = Vec::new();
                    for (_, member) in members.iter().skip(1) {
                        add_into(&mut counts, &member.counts);
                    }
                    seed = Some(counts);
                } else if self.window_on && !self.window.is_empty() {
                    let mut counts: Vec<u32> = Vec::new();
                    for member in &self.window {
                        add_into(&mut counts, member);
                    }
                    seed = Some(counts);
                }
            }
            if self.window_on {
                for (_, member) in &members {
                    if self.window.len() == CARRY_MEMBERS_MOST {
                        self.window.pop_front();
                    }
                    self.window.push_back(member.counts.clone());
                }
            }
            taken.push(ChainJob {
                chain: number,
                members,
                carried: chain.carried.clone(),
                on_set: chain.members,
                seed,
            });
        }
        taken
    }
}

/// `sum += more`, element by element, `sum` grown to fit.
pub(super) fn add_into(sum: &mut Vec<u32>, more: &[u32]) {
    if sum.len() < more.len() {
        sum.resize(more.len(), 0);
    }
    for (total, &count) in sum.iter_mut().zip(more) {
        *total = total.saturating_add(count);
    }
}

impl ChainJob {
    /// Write the chain's members in order, each into the buffer `out`
    /// lends for its segment, and answer the set in force after it and
    /// the members on it.
    pub(super) fn write<F: Emit>(
        self,
        format: &F,
        out: &mut LendOut<'_>,
    ) -> (Option<CarriedSet>, usize) {
        let mut carried = self.carried;
        let mut members = self.on_set;
        let mut seed = self.seed;
        for (segment, member) in self.members {
            let mut may_carry = carried.is_some() && members < CARRY_MEMBERS_MOST;
            if !may_carry {
                carried = None;
                members = 0;
            }
            if let Some(counts) = seed.take() {
                carried = Some(CarriedSet {
                    lengths: Vec::new(),
                    counts,
                    codes: Vec::new(),
                });
                may_carry = true;
            }
            out(segment, &mut |buffer| {
                format.emit_member(
                    &member.tokens,
                    &member.cuts,
                    &member.records,
                    &member.counts,
                    &mut carried,
                    may_carry,
                    buffer,
                );
            });
            members += 1;
        }
        (carried, members)
    }
}
