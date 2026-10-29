//! Building the prefix codes both encoders emit (spec H3 section 6.3).
//!
//! Two requirements that are not obvious from the read side, and that this
//! module exists to hold in one place:
//!
//! 1. **A table sent for an alphabet in use fills the code space
//!    exactly.** A symbol of length `n` takes one part in `2^n` of the
//!    codes there can be, and the parts of a table's symbols must add up
//!    to 1. A reader would accept less; a writer owes it all the same,
//!    because what is left over is bits that are no symbol's code. The
//!    case that arises by itself is a block that uses ONE symbol of an
//!    alphabet: its least cost code is length 1, one half. Such a table
//!    goes out with length 1 on that symbol and length 1 on one other
//!    symbol of the alphabet, which the block never sends.
//! 2. **A code length may not exceed 15.** When the plain code for the
//!    frequencies is deeper than that, the OPTIMAL code of depth 15 is
//!    built rather than falling back to a flat one. The flat fallback
//!    costs real ratio: on a 256 MiB mixed corpus it fired on about one
//!    main table in ten at a 32 MiB dictionary and cost 0.2% to 0.5% of
//!    the archive.
//!
//! The optimal depth limited code comes from the package merge algorithm,
//! which is what makes requirement 2 cheap enough to run unconditionally:
//! it is `O(symbols * depth)` and it runs once per block, never on the
//! per token path (section 8.3, structural requirement 5).

use super::bits::Code;

/// The deepest code either format can name, since every code length goes
/// out through a four bit field.
pub(crate) const MAX_CODE_LEN: u8 = 15;

/// Code lengths for `frequency`, each at most [`MAX_CODE_LEN`], forming a
/// complete prefix code whenever any symbol is used.
///
/// `lengths` is overwritten and must be the same length as `frequency`, so
/// that a block reuses the caller's buffers. The package merge's own lists
/// live in a per thread [`Merge`], so a table allocates nothing once its
/// thread has built one of that size.
pub(crate) fn code_lengths(frequency: &[u32], lengths: &mut [u8]) {
    debug_assert_eq!(frequency.len(), lengths.len());
    MERGE.with_borrow_mut(|merge| merge.lengths(frequency, lengths));
}

/// [`code_lengths`] for a table where (nearly) every symbol is used, as a
/// carried table set's is: the plain Huffman code, built in
/// `O(symbols log symbols)` from the frequencies sorted once, where its
/// depth is at most [`MAX_CODE_LEN`]; the package merge only where it is
/// deeper. A plain Huffman code of that depth is an optimal code, so the
/// result costs exactly the bits the package merge's does; which of the
/// equally optimal lengths it names can differ, which is why the encoders'
/// own blocks keep [`code_lengths`] and only a carried set uses this.
pub(crate) fn code_lengths_dense(frequency: &[u32], lengths: &mut [u8]) {
    debug_assert_eq!(frequency.len(), lengths.len());
    lengths.fill(0);
    let mut order: Vec<(u32, u32)> = frequency
        .iter()
        .enumerate()
        .filter(|&(_, &count)| count > 0)
        .map(|(symbol, &count)| (count, symbol as u32))
        .collect();
    if order.len() < 2 {
        return code_lengths(frequency, lengths);
    }
    order.sort_unstable();
    let leaves = order.len();
    // Two queues: the leaves in order, and the internal nodes as they are
    // made, whose weights never fall. Node `i` of the tree is leaf `i`
    // below `leaves`, internal node `i - leaves` above; `parent` links
    // every node to the internal node that took it.
    let mut weight: Vec<u64> = order.iter().map(|&(count, _)| u64::from(count)).collect();
    weight.reserve(leaves - 1);
    let mut parent = vec![0u32; 2 * leaves - 1];
    let (mut leaf, mut inner) = (0usize, leaves);
    let take = |weight: &[u64], leaf: &mut usize, inner: &mut usize| -> usize {
        // The lighter front, a leaf on a tie, so the build is one order.
        if *leaf < leaves && (*inner >= weight.len() || weight[*leaf] <= weight[*inner]) {
            *leaf += 1;
            *leaf - 1
        } else {
            *inner += 1;
            *inner - 1
        }
    };
    for made in leaves..2 * leaves - 1 {
        let a = take(&weight, &mut leaf, &mut inner);
        let b = take(&weight, &mut leaf, &mut inner);
        weight.push(weight[a] + weight[b]);
        parent[a] = made as u32;
        parent[b] = made as u32;
    }
    // Depths from the root down: every parent is made after its children.
    let mut depth = vec![0u8; 2 * leaves - 1];
    for node in (0..2 * leaves - 2).rev() {
        depth[node] = depth[parent[node] as usize].saturating_add(1);
    }
    if depth[..leaves].iter().any(|&d| d > MAX_CODE_LEN) {
        return code_lengths(frequency, lengths);
    }
    for (index, &(_, symbol)) in order.iter().enumerate() {
        lengths[symbol as usize] = depth[index];
    }
}

/// The canonical codes for `lengths`: shorter lengths first, and within a
/// length by increasing symbol number, each code one more than the last,
/// shifted left by one at each length step. This is the assignment every
/// decoder in the project reads back.
pub(crate) fn canonical(lengths: &[u8], codes: &mut [Code]) {
    debug_assert_eq!(lengths.len(), codes.len());
    codes.fill(Code::default());
    let mut counts = [0u32; MAX_CODE_LEN as usize + 1];
    for &length in lengths {
        debug_assert!(length <= MAX_CODE_LEN);
        counts[length as usize] += 1;
    }
    counts[0] = 0;
    let mut next = [0u32; MAX_CODE_LEN as usize + 1];
    let mut code = 0u32;
    for length in 1..=MAX_CODE_LEN as usize {
        next[length] = code;
        code = (code + counts[length]) << 1;
    }
    for (symbol, &length) in lengths.iter().enumerate() {
        if length == 0 {
            continue;
        }
        codes[symbol] = Code {
            bits: next[length as usize],
            len: length,
        };
        next[length as usize] += 1;
    }
}

/// Whether `lengths` is a complete prefix code, which every table this
/// crate emits must be when any symbol is used.
// Live in the `cfg(test)` build only: this package's own tests are its
// one caller.
#[allow(dead_code)]
pub(crate) fn is_complete(lengths: &[u8]) -> bool {
    let mut kraft: u64 = 0;
    let mut any = false;
    for &length in lengths {
        if length > 0 {
            any = true;
            kraft += 1u64 << (MAX_CODE_LEN - length);
        }
    }
    !any || kraft == 1u64 << MAX_CODE_LEN
}

thread_local! {
    /// The package merge's working lists for this thread. A non-solid set
    /// of small members builds five tables for every member, and building
    /// them from fresh vectors each time was about a tenth of that set's
    /// `-m1` time, most of it the allocator.
    static MERGE: std::cell::RefCell<Merge> = std::cell::RefCell::default();
}

/// Symbol numbers fit below this many bits of a sort key: the largest
/// alphabet either format has is RAR 5's main one, 306 symbols.
const SYMBOL_BITS: u32 = 16;

/// The package merge algorithm's lists, reused from table to table.
///
/// Coins of denomination `2^-L` are minted for every symbol at every
/// level. The cheapest `2n - 2` of them buy the whole code space, and a
/// symbol's depth is how many levels it was bought at. Because the coins
/// of a level are in weight order, the ones a level contributes are always
/// a PREFIX of that order, so a level is recorded as one count rather than
/// as a set: that is what keeps this `O(symbols * depth)` in both time and
/// memory, and off the per token path it would otherwise crawl on.
///
/// An item is one `u64`: its weight shifted up one bit, and a low bit that
/// is set for a package. Ordering items by that word puts a coin before a
/// package of equal weight, which keeps the shallowest of the equally good
/// codes, and no two items compare equal unless both are coins of equal
/// weight, whose order the coins' own sort fixed.
#[derive(Default)]
struct Merge {
    /// The used symbols in weight order, ties by symbol number: each is
    /// `frequency << 32 | symbol`, so one plain sort gives that order.
    order: Vec<u64>,
    /// The coins, lightest first, then a sentinel.
    coins: Vec<u64>,
    /// One level's packages, lightest first, then a sentinel.
    packs: Vec<u64>,
    /// Every level's merged list, deepest first, end to end.
    items: Vec<u64>,
    /// Where each level's list sits in `items`.
    levels: [std::ops::Range<usize>; MAX_CODE_LEN as usize],
    /// How many levels each used symbol was bought at, by rank.
    depth: Vec<u8>,
}

impl Merge {
    fn lengths(&mut self, frequency: &[u32], lengths: &mut [u8]) {
        debug_assert!(frequency.len() < 1 << SYMBOL_BITS);
        lengths.fill(0);
        self.order.clear();
        for (symbol, &count) in frequency.iter().enumerate() {
            if count > 0 {
                self.order.push(u64::from(count) << 32 | symbol as u64);
            }
        }
        match self.order.len() {
            0 => {}
            1 => {
                // Item 1 of section 6.3: one used symbol at length 1 takes one
                // half of the code space, so a symbol the block never sends takes
                // the other half at length 1. The block's own bits do not change.
                let only = (self.order[0] & 0xffff_ffff) as usize;
                let unsent = usize::from(only == 0);
                lengths[only] = 1;
                if unsent < lengths.len() {
                    lengths[unsent] = 1;
                }
            }
            _ => {
                self.merge();
                for (rank, &key) in self.order.iter().enumerate() {
                    // Every used symbol is bought at least once: the
                    // lightest coins of the deepest level are always among
                    // the cheapest chosen.
                    lengths[(key & 0xffff_ffff) as usize] = self.depth[rank].max(1);
                }
            }
        }
    }

    /// The optimal prefix code whose deepest code is [`MAX_CODE_LEN`], as
    /// a depth for each entry of `order`.
    fn merge(&mut self) {
        // Every key is distinct, so the unstable sort's order is the only
        // order there is.
        self.order.sort_unstable();
        let n = self.order.len();
        // The coins and each level's packages are read from lists of their
        // own, each ended by a sentinel heavier than any item, so the merge
        // below takes one item a step with no end test and no branch on
        // which list gave it: which list gives it is data, and a branch on
        // data mispredicted on most steps of a table this small.
        let coins = &mut self.coins;
        coins.clear();
        coins.extend(self.order.iter().map(|&key| (key >> 32) << 1));
        coins.push(u64::MAX);
        let items = &mut self.items;
        items.clear();
        items.extend_from_slice(&coins[..n]);
        self.levels[0] = 0..n;
        let packs = &mut self.packs;
        let mut level = 1;
        while level < MAX_CODE_LEN as usize {
            let last = self.levels[level - 1].clone();
            // Package: pair the list up, dropping an odd tail, which can
            // never be part of an optimal solution.
            packs.clear();
            packs.extend(
                items[last.clone()]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| (((pair[0] >> 1) + (pair[1] >> 1)) << 1) | 1),
            );
            let packages = packs.len();
            packs.push(u64::MAX);
            let start = items.len();
            items.resize(start + n + packages, 0);
            let (mut coin, mut package) = (0, 0);
            for slot in &mut items[start..] {
                let (c, p) = (coins[coin], packs[package]);
                let take_coin = c < p;
                *slot = if take_coin { c } else { p };
                coin += usize::from(take_coin);
                package += usize::from(!take_coin);
            }
            if items[start..] == items[last.clone()] {
                // A level equal to the one below it is packaged into the
                // same list again, so every level from here up is this
                // one: stop building and point them all at it.
                items.truncate(start);
                for above in &mut self.levels[level..] {
                    *above = last.clone();
                }
                break;
            }
            self.levels[level] = start..items.len();
            level += 1;
        }

        // Walk back up: the top level spends `2n - 2` items, and every
        // package among them spends two items of the level below.
        self.depth.clear();
        self.depth.resize(n, 0);
        let mut spend = 2 * n - 2;
        for range in self.levels.iter().rev() {
            let list = &items[range.clone()];
            let taken = spend.min(list.len());
            let used_coins = list[..taken].iter().filter(|&&item| item & 1 == 0).count();
            for slot in &mut self.depth[..used_coins] {
                *slot += 1;
            }
            spend = 2 * (taken - used_coins);
            if spend == 0 {
                break;
            }
        }
    }
}

/// The package merge as it was first written, one fresh list per level:
/// the reference the reused form above is tested against, table for table.
#[cfg(test)]
pub(crate) fn code_lengths_reference(frequency: &[u32], lengths: &mut [u8]) {
    #[derive(Clone, Copy)]
    struct Item {
        weight: u64,
        coin: bool,
    }
    lengths.fill(0);
    let used: Vec<usize> = (0..frequency.len()).filter(|&s| frequency[s] > 0).collect();
    if used.len() < 2 {
        if let Some(&only) = used.first() {
            let unsent = usize::from(only == 0);
            lengths[only] = 1;
            if unsent < lengths.len() {
                lengths[unsent] = 1;
            }
        }
        return;
    }
    let mut order: Vec<usize> = used.clone();
    order.sort_by_key(|&symbol| (frequency[symbol], symbol));
    let coins: Vec<Item> = order
        .iter()
        .map(|&symbol| Item {
            weight: u64::from(frequency[symbol]),
            coin: true,
        })
        .collect();
    let mut levels: Vec<Vec<Item>> = vec![coins.clone()];
    for _ in 1..MAX_CODE_LEN {
        let last = levels.last().expect("a level");
        let packaged = last.as_chunks::<2>().0.iter().map(|pair| Item {
            weight: pair[0].weight + pair[1].weight,
            coin: false,
        });
        let mut merged = Vec::new();
        let mut coin = coins.iter().copied().peekable();
        let mut package = packaged.peekable();
        loop {
            let take_coin = match (coin.peek(), package.peek()) {
                (Some(c), Some(p)) => c.weight <= p.weight,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            merged.push(if take_coin {
                coin.next().expect("a coin")
            } else {
                package.next().expect("a package")
            });
        }
        levels.push(merged);
    }
    let mut depth = vec![0u8; order.len()];
    let mut spend = 2 * order.len() - 2;
    for level in levels.iter().rev() {
        let taken = spend.min(level.len());
        let used_coins = level.iter().take(taken).filter(|item| item.coin).count();
        for slot in depth.iter_mut().take(used_coins) {
            *slot += 1;
        }
        spend = 2 * (taken - used_coins);
        if spend == 0 {
            break;
        }
    }
    for (rank, &symbol) in order.iter().enumerate() {
        lengths[symbol] = depth[rank].max(1);
    }
}
