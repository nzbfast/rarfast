//! Advice to the kernel about how a large buffer's pages are backed.
//!
//! **Why this exists.** A decode writes its whole window once, from the
//! front, and the first write to each page faults it in. On Linux with
//! 4 KiB pages that fault is the whole of a short run's fixed cost: on a
//! Zen 4 box (kernel 6.8, THP in `madvise` mode, Ubuntu's default) a fresh
//! 32 MiB costs 11.5 ms to touch, 8,195 faults at 1.40 us each with the
//! memory cgroup's accounting in them, against 1.5 ms when the range is
//! advised `MADV_HUGEPAGE` (18 faults of 2 MiB). A 64 MiB long-match
//! member that decodes in about 9 ms spent 20 ms in all. 2 MiB pages also
//! take the ring's random back-reference reads off the dTLB, which is why
//! the large rows gain as well (measured 28 Sep 2026).
//!
//! **Where it applies.** The huge page advice is Linux only (the
//! ring release below is Linux and macOS): Darwin
//! on arm64 has no transparent huge pages and its 16 KiB first touch costs
//! 1.6 ms per 32 MiB, so every other target compiles [`advise_huge`] to
//! nothing. The advice changes no byte: a page is zero on first touch
//! whichever size backs it, and the kernel may ignore the advice outright
//! (THP `never`), which leaves exactly the behaviour before it.
//!
//! **The encoder's tables (1 Oct 2026).** A create's match finder reads
//! its links, heads and history at random, and at a 2 MiB dictionary those
//! already outrun a second-level TLB in 4 KiB pages: counted on a Zen 4
//! box, a level 3 create of 1 GiB of binaries took 261 M page walks and
//! 19 M with its blocks advised, the same instructions in 7 to 19 percent
//! fewer cycles (1 Oct 2026). So the chains'
//! heads and links, each builder's own heads, the tree's slots and hints
//! and the carried history ask too, through [`advise_huge_of`], each
//! before its first write.
//!
//! **The knob.** `RARKIT_HUGE_PAGES` in the environment, read once: `0`
//! turns every advice off for the process, `ring` keeps the decode ring's
//! and turns the encoder's off (what every build before 1 Oct 2026 did),
//! anything else or nothing leaves both on. One binary can so be measured
//! against itself.

/// `len` zero bytes, or `None` when the allocator refuses them.
///
/// What `vec![0u8; len]` asks the allocator for, the same zeroed request
/// of the same layout, so a large one is still a fresh anonymous mapping
/// the kernel already guarantees is zero and nothing is memset. The
/// difference is the answer to a refusal: `vec!` ABORTS the process, and
/// a window the host cannot map (a finite `RLIMIT_AS` spent on other
/// threads' stacks and arenas) must be reported instead, as SPEC-API 8.1
/// term 4's `LimitExceeded { AddressSpace }` (`memory::host_refused`).
#[allow(unsafe_code)]
pub(crate) fn zeroed(len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let layout = std::alloc::Layout::array::<u8>(len).ok()?;
    // SAFETY: `layout` has a non-zero size, checked above.
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` was allocated by the global allocator with exactly
    // the layout `Vec<u8>` uses for a capacity of `len` (size `len`,
    // alignment 1), and all `len` bytes are initialised, to zero.
    Some(unsafe { Vec::from_raw_parts(ptr, len, len) })
}

/// The transparent huge page size on every Linux target that has one
/// here (x86-64 and 4 KiB-page aarch64). Only whole, aligned 2 MiB spans
/// inside a buffer can be backed by a huge page, so only those are
/// advised, which also keeps the range page-aligned on any page size up
/// to 2 MiB.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HUGE: usize = 2 << 20;

/// What asks, by `RARKIT_HUGE_PAGES` (the module notes). Read once.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// `0`: nothing asks.
    Off,
    /// `ring`: the decode ring only.
    Ring,
    /// Unset, or anything else: the ring and the encoder's tables.
    All,
}

#[cfg(target_os = "linux")]
fn scope() -> Scope {
    static SCOPE: std::sync::OnceLock<Scope> = std::sync::OnceLock::new();
    *SCOPE.get_or_init(|| scope_of(crate::knob::reader_var_os("RARKIT_HUGE_PAGES").as_deref()))
}

/// The scope a value of `RARKIT_HUGE_PAGES` names.
#[cfg(target_os = "linux")]
fn scope_of(value: Option<&std::ffi::OsStr>) -> Scope {
    match value {
        Some(v) if v == "0" => Scope::Off,
        Some(v) if v == "ring" => Scope::Ring,
        _ => Scope::All,
    }
}

/// The aligned 2 MiB span inside `start..start + len`, as an offset from
/// `start` and a length, or `None` when no whole huge page fits.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn huge_span(start: usize, len: usize) -> Option<(usize, usize)> {
    let first = start.checked_next_multiple_of(HUGE)?;
    let end = (start.checked_add(len)?) / HUGE * HUGE;
    (end > first).then(|| (first - start, end - first))
}

#[cfg(test)]
thread_local! {
    /// How many requests THIS THREAD has made, the ring's first and the
    /// encoder's second, for the tests that pin which allocations ask and
    /// on which targets.
    pub(crate) static ASKED: std::cell::Cell<[usize; 2]> = const { std::cell::Cell::new([0; 2]) };
}

/// Count one request of `kind` (0 the ring's, 1 the encoder's).
#[cfg(all(test, target_os = "linux"))]
fn asked(kind: usize) {
    ASKED.with(|cell| {
        let mut counts = cell.get();
        counts[kind] += 1;
        cell.set(counts);
    });
}

/// Advise the aligned 2 MiB spans of `buf`'s own bytes, whatever `T` is.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn advise_span<T>(buf: &mut [T]) -> bool {
    let bytes = std::mem::size_of_val(buf);
    let start = buf.as_mut_ptr().cast::<u8>();
    let Some((offset, len)) = huge_span(start as usize, bytes) else {
        return false;
    };
    // SAFETY: `offset + len <= bytes`, so the span lies wholly inside
    // `buf`, a live allocation this call borrows mutably, and no other
    // reference can observe it meanwhile; its start is 2 MiB aligned and
    // its length a multiple of 2 MiB, which is page aligned on every page
    // size up to 2 MiB. Nothing is read or written through the pointer,
    // so `T` may be anything, uninitialised memory included.
    // `MADV_HUGEPAGE` is advisory: it changes how pages are backed and
    // never their contents (a first touch is zero either way, a touched
    // page keeps its bytes), and a refusal (THP compiled out, `never`, an
    // old kernel) is ignored, leaving the buffer as it was.
    let _ = unsafe {
        libc::madvise(
            start.add(offset).cast::<libc::c_void>(),
            len,
            libc::MADV_HUGEPAGE,
        )
    };
    true
}

/// Ask the kernel to back `buf`'s aligned 2 MiB spans with huge pages.
/// Call it on a buffer before its first write; a buffer too small to hold
/// one aligned huge page is left alone, and a refusal is ignored.
#[cfg(target_os = "linux")]
pub(crate) fn advise_huge(buf: &mut [u8]) {
    if scope() != Scope::Off && advise_span(buf) {
        #[cfg(test)]
        asked(0);
    }
}

/// Every other target: nothing to advise (see the module notes).
#[cfg(not(target_os = "linux"))]
#[inline(always)]
pub(crate) fn advise_huge(_buf: &mut [u8]) {}

/// [`advise_huge`] for one of the ENCODER's tables or its history: the
/// same advice over the buffer's own bytes, whatever its slots are (a
/// `Vec`'s spare capacity included, which is how a table that is filled
/// rather than zeroed asks before its fill). `RARKIT_HUGE_PAGES=ring`
/// turns these off and leaves the ring's.
#[cfg(target_os = "linux")]
pub(crate) fn advise_huge_of<T>(buf: &mut [T]) {
    if scope() == Scope::All && advise_span(buf) {
        #[cfg(test)]
        asked(1);
    }
}

/// Every other target: nothing to advise (see the module notes), and no
/// caller either: each call site is compiled for Linux alone, so that
/// every other target's code is what it was before the tables asked.
/// Kept for the tests, which run the same on every target.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
#[inline(always)]
pub(crate) fn advise_huge_of<T>(_buf: &mut [T]) {}

/// Whether [`release`] is on for this process: yes, unless
/// `RARKIT_RING_RELEASE` is `0`. Read once.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn release_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| crate::knob::reader_var_os("RARKIT_RING_RELEASE").is_none_or(|v| v != "0"))
}

/// Give a decode ring's pages back to the kernel IMMEDIATELY BEFORE the
/// ring is dropped or replaced (on Linux, and extended to macOS).
///
/// **Why.** A worker that meets a member needing a far smaller ring drops
/// its large one (`read::extract`, `Decoders::rar5`), and the sequential
/// look-ahead's workers drop every ring they replace (`Shrink::Tight`).
/// Neither allocator gives such a block's memory back by itself:
///
/// - glibc answers the first free of a large mapped block by raising its
///   mmap threshold, so every later ring comes from the thread's heap and a
///   freed one stays resident there: on a Zen 5 rental, `t` of a 4 GiB
///   non-solid archive of small members held 581 MiB with member-sized
///   rings and 258 to 262 MiB once the threshold was pinned.
/// - macOS's malloc keeps freed large blocks, pages and all, in its large
///   cache: on the M5 laptop `p` of bin4g held 106 to 191 MiB of freed
///   rings there (13 empty regions of 3 to 32 MiB at four look-ahead
///   workers), 179 to 473 MiB in all against 73 to 282 MiB with the cache
///   off.
///
/// Releasing the pages first keeps the allocator's address space and gives
/// its memory back, whatever the allocator does next. Linux advises
/// `MADV_DONTNEED` on the ring's whole aligned 2 MiB spans;
/// macOS advises `MADV_FREE_REUSABLE` on its whole 16 KiB pages,
/// the unit the kernel accounts a process's footprint in there, so a ring
/// of 3 MiB gives back all of itself but its two end pages rather than a
/// single 2 MiB span. Rings of 2 MiB and more only; a smaller ring is left
/// to the allocator. `RARKIT_RING_RELEASE=0` turns it off.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
pub(crate) fn release(buf: &mut [u8]) {
    if buf.len() < HUGE || !release_enabled() {
        return;
    }
    let Some((offset, len)) = release_span(buf.as_ptr() as usize, buf.len()) else {
        return;
    };
    let span = &mut buf[offset..offset + len];
    // SAFETY: `span` lies wholly inside `buf`, a live allocation this call
    // borrows mutably, so it is exclusively owned here and no other
    // reference into it exists; its start and length are multiples of
    // `RELEASE_GRAIN` (2 MiB on Linux, 16 KiB on macOS), so page aligned on
    // every page size the target has (4 KiB or 16 KiB). Nothing is read or
    // written through the pointer. On private anonymous memory
    // `MADV_DONTNEED` drops the pages, and a later read of them is zero;
    // `MADV_FREE_REUSABLE` lets the kernel take them, and a later read is
    // zero or the old byte. Either way the caller drops or replaces the
    // ring straight after, so no byte of it is read again, and an
    // allocator that hands the block out afresh gives no promise about its
    // contents (a zeroed allocation zeroes it itself). A refusal is
    // ignored, leaving the pages resident as before.
    let _ = unsafe {
        libc::madvise(
            span.as_mut_ptr().cast::<libc::c_void>(),
            span.len(),
            RELEASE_ADVICE,
        )
    };
}

/// The advice [`release`] gives: Linux drops the pages outright.
#[cfg(target_os = "linux")]
const RELEASE_ADVICE: libc::c_int = libc::MADV_DONTNEED;
/// The advice [`release`] gives: macOS marks them reusable, which takes
/// them out of the process's footprint at once.
#[cfg(target_os = "macos")]
const RELEASE_ADVICE: libc::c_int = libc::MADV_FREE_REUSABLE;

/// The span [`release`] advises is whole multiples of this, aligned to it:
/// Linux keeps whole 2 MiB spans, macOS takes its 16 KiB
/// pages (a multiple of 4 KiB, so aligned on an x86-64 Mac too).
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
const RELEASE_GRAIN: usize = if cfg!(target_os = "macos") {
    16 << 10
} else {
    HUGE
};

/// The whole, aligned `RELEASE_GRAIN` units inside `start..start + len`,
/// as an offset from `start` and a length, or `None` when none fits.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn release_span(start: usize, len: usize) -> Option<(usize, usize)> {
    let first = start.checked_next_multiple_of(RELEASE_GRAIN)?;
    let end = (start.checked_add(len)?) / RELEASE_GRAIN * RELEASE_GRAIN;
    (end > first).then(|| (first - start, end - first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_span_is_the_aligned_huge_pages_inside_the_buffer() {
        // Too small, or straddling one boundary: nothing.
        assert_eq!(huge_span(0, HUGE - 1), None);
        assert_eq!(huge_span(HUGE - 16, HUGE), None);
        // Exactly one page, aligned.
        assert_eq!(huge_span(HUGE, HUGE), Some((0, HUGE)));
        // An unaligned 32 MiB buffer holds fifteen whole pages.
        let start = 3 * HUGE + 16;
        let (off, len) = huge_span(start, 16 * HUGE).unwrap();
        assert_eq!((start + off) % HUGE, 0);
        assert_eq!(len, 15 * HUGE);
        assert!(off + len <= 16 * HUGE);
        // No overflow at the top of the address space.
        assert_eq!(huge_span(usize::MAX - HUGE, HUGE), None);
    }

    #[test]
    fn advice_changes_no_byte() {
        // Zeroed as the ring is, advised, then written: the bytes are the
        // bytes written, and the untouched ones still read zero.
        let mut buf = vec![0u8; 5 * HUGE + 123];
        advise_huge(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        for (i, b) in buf.iter_mut().enumerate().step_by(4093) {
            *b = (i % 251) as u8 | 1;
        }
        advise_huge(&mut buf);
        for (i, &b) in buf.iter().enumerate() {
            let want = if i % 4093 == 0 {
                (i % 251) as u8 | 1
            } else {
                0
            };
            assert_eq!(b, want, "byte {i}");
        }
        // A buffer too small for a huge page is left alone.
        let mut small = vec![7u8; 4096];
        advise_huge(&mut small);
        assert!(small.iter().all(|&b| b == 7));
    }

    #[test]
    fn the_release_span_is_whole_aligned_grains_inside_the_buffer() {
        assert_eq!(release_span(0, RELEASE_GRAIN - 1), None);
        assert_eq!(
            release_span(RELEASE_GRAIN, RELEASE_GRAIN),
            Some((0, RELEASE_GRAIN))
        );
        let start = 3 * RELEASE_GRAIN + 16;
        let (off, len) = release_span(start, 16 * RELEASE_GRAIN).unwrap();
        assert_eq!((start + off) % RELEASE_GRAIN, 0);
        assert_eq!(len, 15 * RELEASE_GRAIN);
        assert_eq!(
            release_span(usize::MAX - RELEASE_GRAIN, RELEASE_GRAIN),
            None
        );
        // Linux keeps the huge span exactly.
        if cfg!(target_os = "linux") {
            assert_eq!(release_span(start, 5 * HUGE), huge_span(start, 5 * HUGE));
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn release_leaves_a_small_ring_alone_and_only_zeroes_what_it_drops() {
        // Under 2 MiB: never touched, on any target.
        let mut small = vec![9u8; HUGE - 1];
        release(&mut small);
        assert!(small.iter().all(|&b| b == 9));
        // A larger ring: every byte either keeps its value (outside the
        // aligned span, or with the knob off) or reads zero (inside it).
        // Nothing else is possible.
        // (macOS's advice lets the kernel take a page when it wants, so a
        // released byte there reads zero or its old value.)
        let mut ring = vec![5u8; 5 * HUGE + 123];
        let span = release_span(ring.as_ptr() as usize, ring.len());
        release(&mut ring);
        for (i, &b) in ring.iter().enumerate() {
            let inside = span.is_some_and(|(o, l)| i >= o && i < o + l);
            if inside && release_enabled() {
                if cfg!(target_os = "macos") {
                    assert!(b == 0 || b == 5, "byte {i}");
                } else {
                    assert_eq!(b, 0, "byte {i}");
                }
            } else {
                assert_eq!(b, 5, "byte {i}");
            }
        }
    }
}

/// Which allocations ask for huge pages, and on which targets: the decode
/// ring and the encoder's tables on Linux, nothing anywhere else.
#[cfg(test)]
pub(crate) mod asking_tests {
    use super::{ASKED, HUGE};

    /// The requests this thread makes while `build` runs: the ring's,
    /// then the encoder's.
    pub(crate) fn asked_by(build: impl FnOnce()) -> [usize; 2] {
        let before = ASKED.with(std::cell::Cell::get);
        build();
        let after = ASKED.with(std::cell::Cell::get);
        [after[0] - before[0], after[1] - before[1]]
    }

    /// What `linux` requests read as here: themselves on Linux with the
    /// knob unset, and none on every other target. `None` where the
    /// environment sets the knob, which a test cannot undo once read.
    pub(crate) fn here(linux: [usize; 2]) -> Option<[usize; 2]> {
        if std::env::var_os("RARKIT_HUGE_PAGES").is_some() {
            return None;
        }
        Some(if cfg!(target_os = "linux") {
            linux
        } else {
            [0; 2]
        })
    }

    #[test]
    fn the_ring_and_the_finders_tables_ask_on_linux_and_nowhere_else() {
        use crate::carry::h_ours::codec::rar50::tree::BucketTrees;
        use crate::encode::chain::{Chains, KEY_SHORT};
        use crate::rar5_lz::output::Window;

        // The chains at the default dictionary over a long span: 4 MiB of
        // heads and 64 MiB of links, one request each.
        let made = asked_by(|| drop(Chains::new(2 << 20, 64 << 20, usize::MAX, KEY_SHORT)));
        if let Some(want) = here([0, 2]) {
            assert_eq!(made, want, "the chains' heads and links");
        }
        // Over a span whose links hold no whole huge page: the heads alone.
        let made = asked_by(|| drop(Chains::new(2 << 20, 64 << 10, usize::MAX, KEY_SHORT)));
        if let Some(want) = here([0, 1]) {
            assert_eq!(made, want, "the heads, and links too small to ask");
        }
        // The tree at the same dictionary: its slot pairs and its heads.
        let made = asked_by(|| drop(BucketTrees::new(2 << 20)));
        if let Some(want) = here([0, 2]) {
            assert_eq!(made, want, "the tree's slots and heads");
        }
        // The decode ring, as before: one request, and not the encoder's.
        let made = asked_by(|| drop(Window::new(32 << 20, u64::MAX)));
        if let Some(want) = here([1, 0]) {
            assert_eq!(made, want, "the ring");
        }
    }

    #[test]
    fn a_table_filled_after_it_asks_holds_what_the_fill_wrote() {
        // The tree's slots ask over spare capacity and are filled after;
        // the advice reaches no slot.
        let mut slots: Vec<u32> = Vec::with_capacity(3 * HUGE / 4 + 5);
        super::advise_huge_of(slots.spare_capacity_mut());
        slots.resize_with(3 * HUGE / 4 + 5, || 7);
        super::advise_huge_of(&mut slots[..]);
        assert!(slots.iter().all(|&slot| slot == 7));
        // A zeroed table reads zero after it asks, and keeps a store.
        let mut zeros = vec![0u32; 2 * HUGE / 4];
        super::advise_huge_of(&mut zeros[..]);
        zeros[HUGE / 4] = 9;
        assert_eq!(zeros.iter().filter(|&&slot| slot != 0).count(), 1);
        assert_eq!(zeros[HUGE / 4], 9);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn the_knob_names_what_asks() {
        use super::{scope_of, Scope};
        use std::ffi::OsStr;
        assert!(scope_of(None) == Scope::All);
        assert!(scope_of(Some(OsStr::new("1"))) == Scope::All);
        assert!(scope_of(Some(OsStr::new("0"))) == Scope::Off);
        assert!(scope_of(Some(OsStr::new("ring"))) == Scope::Ring);
    }
}

/// A ring the host will not map is REPORTED as the host's refusal, SPEC-API
/// 8.1 term 4's `LimitExceeded { resource: AddressSpace, needed, limit }`,
/// never an abort, never `Window`, and never quoting `u64::MAX` (the
/// `ulimit -v` rows measured on 30 Sep 2026 printed "Window
/// wanted 33554496 bytes and the policy allows 18446744073709551615").
#[cfg(test)]
mod host_refusal_tests {
    /// 64 PiB: more than any user address space here holds (47 or 48 bits),
    /// and small enough that the test build's counting allocator can add
    /// it to its byte count without overflowing. A `u64`, the type a
    /// declared window has: the figure does not fit a 32-bit `usize`, and
    /// as a `usize` constant it stopped the test target compiling there.
    const TOO_MUCH: u64 = 1 << 56;

    #[test]
    fn zeroed_answers_a_refusal_rather_than_aborting() {
        // On a 64-bit target this is TOO_MUCH itself. On a 32-bit one the
        // most a `usize` states is asked for instead, which is likewise
        // more than the address space holds.
        let too_much = usize::try_from(TOO_MUCH).unwrap_or(usize::MAX);
        assert!(super::zeroed(too_much).is_none());
        assert_eq!(super::zeroed(0), Some(Vec::new()));
        let got = super::zeroed(3 << 20).expect("3 MiB");
        assert_eq!(got.len(), 3 << 20);
        assert!(got.iter().all(|&b| b == 0));
    }

    /// SPEC-API 8.1 term 4: `needed` the bytes asked for, `limit` the
    /// finite `RLIMIT_AS` where one is set, else the policy's own figure.
    ///
    /// 64-bit only. This is a test of what the HOST refuses, and on a
    /// 32-bit target no declared size is both one a `usize` can state and
    /// one the host is sure to refuse. The figure below never reaches the
    /// host there: run on armv7 under qemu-arm on 4 Oct 2026 it was
    /// refused earlier, as `Window` with a limit of 4294967295.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn a_ring_the_host_refuses_is_address_space_with_its_true_figures() {
        use crate::rar5_lz::output::Window;
        use crate::{ErrorKind, Resource};
        let declared = TOO_MUCH / 2;
        for ceiling in [u64::MAX, TOO_MUCH] {
            let err = match Window::new(declared, ceiling) {
                Ok(_) => panic!("the host mapped {declared} bytes"),
                Err(err) => err,
            };
            let ErrorKind::LimitExceeded {
                resource: Resource::AddressSpace,
                needed,
                limit,
            } = *err.kind()
            else {
                panic!("not an AddressSpace refusal: {:?}", err.kind());
            };
            assert!(
                needed >= declared,
                "the ring's own size, not less: {needed}"
            );
            // This test runs with no `ulimit -v`, so the limit is the
            // policy's figure, or the request where none was set.
            let policy = if ceiling == u64::MAX { needed } else { ceiling };
            assert_eq!(limit, policy);
            let text = err.to_string();
            assert!(text.contains("refused"), "{text}");
            assert!(!text.contains(&u64::MAX.to_string()), "{text}");
        }
    }
}
