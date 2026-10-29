# Every window in this crate, its write invariant, and its guard

Written 19 Sep 2026 by a sweep of the window write guards,
a follow-up across the decoding packages and the encoders. It exists so
the closing audit and the next reader can find, in one place, what each
window promises about its own writes, which of the three sound mechanisms
keeps that promise, and HOW THE GUARD WAS SHOWN TO FAIL. A guard that has only
ever been seen to pass is not evidence.

## The class this is about

The window edge defect, 19 Sep 2026. A short match's
sixteen byte stride copy wrote up to fifteen bytes PAST the match's end. In a
ring of exactly the dictionary those slots hold the OLDEST LIVE BYTES, which is
what a later match at a distance at or just under the dictionary reads: wrong
output, no error, no checksum failure at this level. The helper was carried
correctly from a buffer that SLIDES, where the bytes past the write point are
unwritten slack; nothing in the type system, the name or the doc comment
noticed the buffer shape changing under it.

Four points, from that file's "general rule" section:

1. a copy that writes more than it was asked to is free only where the bytes
   past the write point are DEAD. In a ring none of them are: they are the
   oldest history, so a rounded up copy lands exactly on what the LONGEST legal
   references read. A wide copy is safest where the reference is shortest and
   most dangerous where the format stretches furthest, which is the opposite of
   the intuition that makes it look harmless;
2. the thing to hunt is a copy helper that MOVED BETWEEN BUFFER SHAPES;
3. three repairs are legitimate: make the write EXACT, give the ring a MARGIN
   past what any distance may name, or BRACKET the copy by saving what it will
   overrun and putting it back. Prefer the margin where the copy is hot;
4. **guard the WRITE, not the output.** A spill that the stream's own next
   bytes overwrite before anything reads it back changes no output at all, so
   whether it is ever VISIBLE is a property of the ARCHIVE and not of the
   decoder. Output tests structurally cannot see this class. H2's proof: the
   committed vector `h5_far_small_md` had been spilling onto a readable slot,
   exactly one dictionary back, in every run of the project's checks since that package landed,
   and every test passed.

And the lesson about guards themselves, learned the same day: H2's first guard
watched 64 slots on a ring whose margin was exactly 64, so every watched slot
was unreachable BY CONSTRUCTION and the guard would have passed whatever the
copy did. **A write side guard on a buffer with a margin must watch WIDER than
the margin or it is vacuous.**

## The guard

`src/window_guard.rs`, `#[cfg(debug_assertions)]` entire, so a release build
carries no snapshot, no compare and no branch.

`SpillWatch::take` snapshots the `WATCH` slots past `[at, at + length)`
immediately before a copy; `SpillWatch::check` runs immediately after and fails
on any slot that CHANGED and that a legal distance can still name. The whole of
the arithmetic: after the copy the write point is at `at + length`, so the slot
`i` further on is `ring_len - i` BACK from it, and it is nameable when
`ring_len - i <= limit` and `ring_len - i <= produced`. Both `limit` and
`produced` are the caller's own, taken from that decoder's existing distance
range check, so the guard is written against the INVARIANT and not against any
one ring's geometry.

`WATCH` is 128. Every ring below has a margin of ZERO, so once the stream has
lapped, EVERY watched slot is reachable and any spill at all fails: on these
four, any width would bite. The width is what stops the guard going quiet if
one of them is ever given a margin.

**It was 64, and this guard's own test suite caught that as vacuous.** At 64,
pointed at a ring carrying H2's 64 slot margin, the 64 watched slots were
EXACTLY the margin - every one unreachable by construction - so
`a_spill_one_byte_past_the_margin_fails` did not fail. That is the same
mistake H2's first guard made, arrived at independently here from the same
reasoning, and it was caught only because the suite requires every guard to be
shown to FAIL as well as pass. A guard that had only been checked in the
passing direction would have shipped vacuous for the second time in one day.

So the rule is not "wider than the widest block copied". It is **wider than
the widest MARGIN this guard could ever be pointed at, plus the widest block**:
128 is twice H2's `SPILL` and four times the RAR 1.5 family's `WILD`.

That rule is now a COMPILE TIME assertion rather than a test, because a
vacuous guard should not be buildable:

    const _: () = assert!(WATCH > WIDEST_BLOCK);
    const _: () = assert!(WATCH > WIDEST_MARGIN);

Falsified the same way as everything else here. With `WATCH` put back to 64,
`cargo check -p rarkit` fails outright:

    error[E0080]: evaluation panicked: assertion failed: WATCH > WIDEST_MARGIN
     const _: () = assert!(WATCH > WIDEST_MARGIN);

If a future ring is given a margin wider than 64, those two lines are what
stops the guard going quiet: raise `WIDEST_MARGIN` to match it and the build
tells you `WATCH` has to grow too.

H2's ring keeps its own guard (`Window::spill_watch` /
`Window::assert_no_reachable_spill` in `src/rar5_lz/output.rs`) because its
geometry differs: it is the only ring with a margin, and its watch is sized
`STRIDE_MAX + SPILL` against that margin. Geometries are not forced into one
type.

## The windows

### 1. RAR 3 (package H1) - `src/rar3_lz/window.rs`

| | |
|---|---|
| shape | ring of EXACTLY the declared dictionary, `65,536 << n` for `n` in 0 to 6, held down to `MAX_DISTANCE` |
| margin | **none** |
| longest distance admitted | `ring.len()` |
| mechanism | **exact**, on all three paths: every `run` in the general loop is `left.min(step).min(size - from).min(size - to)`, the `distance == 1` arm is an exact `fill`, and the fast path added 20 Sep 2026 writes `[head, head + length)` as a PAIR of overlapping fixed width copies (8 and 8, or 4 and 4) that covers the match and nothing else |
| guard | `Window::copy`, all three paths, one `SpillWatch` around the whole call |
| other writers | `put` (one byte); `free_run`/`commit`, where the literal burst of SPEC-H1 7.3 item 5 writes into a slice bounded by the ring's own end and commits only what it counted |

Package **I**, the PPMd decoder, writes into this same window and needs no
guard of its own: `StreamWindow for Window` forwards to `Window::put` and
`Window::copy` (spec I section 2), so the LZ hand-over is inside this
invariant already. Package **J**, the RAR 3 filters, never writes it at all:
`Window::slices` lends `&[u8]` and `Window::copy_out` copies into the caller's
staging, which is what SPEC-H1 3.9 and spec J 3.6 require - the window keeps
the UNFILTERED bytes.

### 2. RAR 2.0 (package H3 part A) - `src/lz20/window.rs`

| | |
|---|---|
| shape | ring of EXACTLY the declared dictionary (spec H3 3.5, whose rules are SPEC-H1 3.6's) |
| margin | **none** |
| longest distance admitted | `capacity` |
| mechanism | **exact**: the fast arm is `copy_within(read..read + length, write)`, a copy of the range itself and not of a rounded up block; the slow arm is one byte at a time |
| guard | `Window::copy`, both arms |
| other writers | `put` (one byte); `run` + `commit`, which lend the multimedia block a CONTIGUOUS RUN at the write point and then count what it filled. `pending` lends `&[u8]`, so the caller drains by reading |

The run is exact for a reason the type system carries rather than a guard:
`run` answers a slice that ends at the ring's end at the latest, so a write
past the ring is not expressible, and `commit` advances the write point by
what the caller FILLED and never by the run's length. Both halves are shown
to fail as well as pass by
`a_multimedia_block_wraps_the_ring_and_produces_the_same_bytes`, which puts
eight bytes through a four byte ring with the write point off zero: a `run`
that ignores the ring's end panics there on the slice, and a `commit` off by
one loses a byte of the output.

### 3. RAR 1.5 / 1.3 (spec A) - `src/rar1x.rs`

Brought to the present module on 7 Oct 2026. The decoder this section
first described, `src/rar15_lz.rs`, was replaced on 6 Oct 2026 by the one
written from spec A alone, and its ring is a different shape.

| | |
|---|---|
| shape | ring of `RING` = 131,072 bytes, a power of two, twice the reach and more; the write point `Pen::at` is always under `RING` |
| margin | **the ring's other half.** The longest distance is 65,535, so at least 65,537 slots ahead of the write point are ones no legal distance names |
| longest distance admitted | `REACH` = 65,535, and below the first lap `at`; a distance that names no byte gives zeros (spec A 4.8) |
| mechanism | **wide inside the margin.** `Pen::copy` at a distance of 8 or more, with both runs at least 8 short of the ring's end, copies eight bytes at a time and DOES write up to seven slots past the match. Those slots are `RING - i` back from the new write point, `i` under 8, which is over `REACH`, and they are written again before they come within it. A distance under 8 is copied a byte at a time, lowest first, and a run that comes near the ring's end goes through `Pen::push` |
| guard | `Pen::copy`, both arms that copy in place, through the module's own `Watch` of the two blocks (16 slots) past the copy's end: the wide copy may change the `BLOCK - 1` slots past its match and nothing further, the byte at a time copy nothing at all. A compile time assertion, `RING - (BLOCK - 1) > REACH`, says those slots are ones no distance names |
| other writers | `Pen::push` (one byte, and the point where the ring's end delivers to the sink) |

The mechanism is the RAR 5 window's (a margin the overrun lands in) and not
the bracketing the earlier module used, so the sentence that used to stand
here, that the invariant is broken in the middle of a call and restored by
a paired statement, no longer describes anything in the tree. What the
margin depends on is one inequality, `RING - 7 > REACH`, and an edit that
shrank the ring to the reach or widened the block past the difference would,
unguarded, break it silently: output tests below one lap cannot see it. What holds it
today is the guard, added 7 Oct 2026, and it is not `SpillWatch`, nor its
question. Asked whether a copy touched a slot a legal distance still names,
a watch on this ring could never fail: every slot near the write point
lies in the margin. So the guard is asked what CAN fail, whether the copy
wrote past the slots it is allowed, and the compile time assertion carries
the other half, that the allowed slots are out of every distance's reach. A
ring shrunk to the reach or a block widened past the difference does not
build; a copy that writes one slot further than its block fails in a debug
build.

**The watch is 16 slots and not 128, on purpose.** Its first form borrowed
`SpillWatch` and its 128, and `fuzz:rar1x_member` fell from 1,635 runs a
second to 161 (7 Oct 2026, an M5 Max Mac, one job): a snapshot and a
compare of 128 slots round every copy in place. The watch is sized from
the widest write the copy loop can make instead. A step writes one block;
a wrong copy is a step wider than its block or one step too many, and
either lands inside the block after the allowed overrun. Two blocks hold
every slot one faulty step can reach.

Shown to fail as well as pass, with the 16 slot watch: with the block's
copy widened by ONE byte and nothing else changed, six of the module's
eighteen unit tests fail at the guard (`rar1x, the wide copy: a copy that
ends at 1285 changed slot 1292`); restored, all eighteen pass.
`rar1x::tests::spec_a_4_8_the_wide_copy_may_touch_its_last_block_and_nothing_past_it`
keeps both directions without a mutation, for every watched slot and
where the watch goes round the ring's end, and
`spec_a_4_8_copies_of_every_shape_agree_with_the_plain_reading_round_the_ring`
compares every copy shape with a plain byte at a time reading for five laps.

### 4. The carried RAR 1.5 model's writer - removed

`src/carry/h_ours/codec/rar13/` is no longer in the tree: the present
decoder keeps its own state (`rar1x::Model`) and its own ring (window 3
above), and imports nothing from `src/carry`. There is no second RAR 1.x
window.

The sections further down that name `Run::check_spill`, `block_copy`,
`WILD` and `WINDOW` (the mutation table under "How each guard was shown to
FAIL", and the notes under "Fuzz") are the dated record of the module of
19 to 21 Sep 2026 and are left as they were written.

### 5. RAR 5 (package H2) - `src/rar5_lz/output.rs`

Done and guarded on 19 Sep 2026, before this sweep; left alone by it. Ring of
the declared dictionary plus `SPILL` (64), the only **margin** in the crate;
its own guard, watch `STRIDE_MAX + SPILL`.

`Window::drain` was asked about by name. **It only ever READS the ring.** The
ring-served loop added on 19 Sep takes `ring_slices`, which lends `&[u8]`, into
`self.filtered`, and the filter transform runs over that scratch: section 3.6
requires the ring to keep the UNFILTERED bytes, so the transform cannot run in
place. `emit_range` likewise reads. No write, and so nothing to guard.

## What is NOT a window, checked and cleared

- **The RAR 5 filter path** and **the RAR 3 filter path**: both copy the span
  out of the ring before transforming it, for the same reason - the ring must
  keep the unfiltered bytes. Neither writes a ring.
- **The carried delta and address filters (spec C)**,
  `src/carry/h_ours/codec/address_filters.rs` and
  `src/carry/c_lz/codec/filters.rs`: their in-place passes run over a
  `&mut [u8]` SCRATCH span, never over a ring, and each is bounded by the slice
  itself - `chunks_exact_mut(4)` and `chunks_exact_mut(16)` yield only whole
  chunks and leave the trailing bytes out, and `ia64_pass` narrows to
  `get_mut(..count * 16)` first. Nothing can write past the span.
- **The encoders**, `src/encode/`. There is no byte ring on the encode side at
  all. `Engine::history` is a FLAT `Vec<u8>`, extended by `extend_from_slice`
  and slid by `drain(..stale)`; the parse and the match finder read it as
  `&[u8]`; `Chains` holds `u32` positions, not bytes. So the hazard the sweep
  was sent to look for - an encoder reading a slot a wide copy scribbled, and
  writing a legal but worse stream, or with solid state a wrong one - cannot
  arise from inside the encoder, and the encoders never read a decoder's
  window. No guard is added there, and that is a finding rather than an
  omission.
- `MatchIndex::insert`'s `entries.copy_within(capacity.., 0)` and the PPMd
  arena's `copy_within`s: exact copies over index and arena structures, not
  over output history.

## How each guard was shown to FAIL

Two directions for every guard, because a guard seen only to pass is not
evidence.

### Direction 1: green on the tree as it stands

The guards were added FIRST and the whole suite run before any copy was
touched, on purpose: if a guard fires there, that
package already has the defect and the failure names the archive.

**Nothing fired.** `cargo test -p rarkit` is green on every target - 272 lib
tests and every integration suite, including `legacy_genuine` over the 81
genuine legacy archives, `corpus_differential`, `rar15_codec`, `rar20`,
`rar20_oracle` and `rar3_lz`. So none of the RAR 3, RAR 2.0 or RAR 1.5 windows
carries this defect, and each one's mechanism - exact, exact, bracketing - is
now enforced rather than argued.

That is a real result and not a null one: H2's guard, run against the code
before its fix, failed two PLAIN VECTOR TESTS that had always passed. These
three did not.

### Direction 2: each guard made to fail, on a genuine archive

One mutation per window, each in the shape the defect would really arrive in,
applied to the shipped code and then reverted. Every one was caught, and every
one was caught on a GENUINE archive from `fixtures/legacy/` rather than only on
a test written for it:

| window | mutation | first archive it fails on | message |
|---|---|---|---|
| RAR 3 (H1) | the copied run rounded up to a whole 8 byte block | `r420_md` (`legacy_genuine`), and the in-crate `window_copy_equals_the_byte_at_a_time_result` | `a copy of 7 bytes at 0 wrote slot 7, which is 65536 back and READABLE: the window is 65536 bytes, the longest distance it admits is 65536, and the stream has produced 65543` |
| RAR 3 (H1), the 20 Sep 2026 fast path | the second of the two fixed width copies moved one byte on, so the pair writes one byte past the match | `legacy_genuine`; the in-crate `rar3_lz` tests PASS it | `a copy of 6 bytes at 256 wrote slot 262, which is 65536 back and READABLE: the window is 65536 bytes, the longest distance it admits is 65536, and the stream has produced 65798. A copy may write only [256, 262).` |
| RAR 2.0 (H3 part A) | the fast arm's `copy_within` rounded up to a whole 8 byte block | `d250_m1` (`legacy_genuine`) | `block arm: a copy of 4 bytes at 2 wrote slot 6, which is 65536 back and READABLE ... the stream has produced 65542` |
| RAR 1.5 (spec A) | the restore that pairs with `block_copy`'s save deleted, leaving the wide block in place | `d140_m1` (`legacy_genuine`), and the in-crate `a_dribbling_source_decodes_the_same_member` | `block_copy: a copy of 4 bytes at 2 wrote slot 6, which is 65536 back and READABLE ... the stream has produced 65536` |

Three things are worth reading off that table.

**The RAR 1.5 mutation is the realistic one.** It does not invent a wide copy;
the wide copy is already there and is sound. It deletes ONE LINE, the restore
twenty lines below the save it pairs with. That is how a bracketed copy loses
its bracket in real life, and the guard catches it on the second archive in the
corpus.

**Every mutation fired at a distance of exactly 65,536**, one full lap back, on
a member that had just passed its first lap - `produced` of 65,536 to 65,543
against a 65,536 byte window. That is the same signature H2 recorded for
`h5_far_small_md`, which spilled at exactly one dictionary back within 450
bytes of its first lap. The class has one shape and these rings show it.

**The in-crate tests are the weaker screen, exactly as H2 found, and the
20 Sep 2026 row is the third instance.** A one byte spill in the RAR 3 fast
path passes all 26 in-crate `rar3_lz` tests, including
`window_copy_equals_the_byte_at_a_time_result`, and is caught by
`legacy_genuine` on a genuine archive. The same mutation widened to 16
bytes is caught earlier still, by `copy_within`'s own bounds check rather
than by the guard, which is worth knowing when reading a falsification:
"dest is out of bounds" means the mutation never reached the guard, so it
is not evidence the guard works. The RAR 2.0
mutation passes all 23 in-crate `lz20` tests and is caught only by a genuine
archive, for H2's own item 1 reason: a test that seeds a few kilobytes into a
64 KiB window never laps it, so every slot ahead of the write point is a byte
the stream never produced and the over copy is writing on dead memory.

### Direction 2b: the guard's own predicate

`src/window_guard.rs`'s test module, which ships and runs in every run of the project's checks:
four `#[should_panic]` tests (a spill onto a reachable slot, one at the far
edge of the watch, one that wraps the ring's end, and one a byte past a
margin), and four that must NOT fire (writing inside the copy's own range, a
spill the stream has not reached yet, a spill onto a margin the decoder
refuses, and a ring shorter than the watch). The last pair is what stops the
guard being loosened later: it encodes WHY an unreachable slot is unreachable
instead of skipping it.

`a_spill_one_byte_past_the_margin_fails` is the one that earned its place. It
failed to panic on the first run, which is how `WATCH` was found to be vacuous
at 64 against a 64 slot margin. See "The guard" above.

## What the guards cost

### Release: NOTHING, and it is shown rather than argued

Every line added is inside `#[cfg(debug_assertions)]`, so a release build
cannot contain it. Two checks rather than the assertion alone:

- `nm` finds **9 guard symbols in the debug rlib and 0 in the release rlib**;
- and the stronger one: the release **MACHINE CODE IS BYTE IDENTICAL** with
  and without the guards. Building `librarkit.rlib` at this branch and with
  this branch's `crates/rarkit/src` diff reversed, and hashing the `__text`
  section of every object in the archive, gives
  `9aeb57feb68a37428863acea88073c1699b2ba5a999b68818f147a79e8577271` both
  times. (The rlib as a whole DOES differ, because it carries metadata: doc
  comments, spans and the module list. That is why the comparison is on
  `__text` and not on the file.)

No bench leg is quoted for this. A timed leg would be weaker evidence than
identical machine code, not stronger, and the box was at a one minute load of
6.7 to 23 throughout this work with several fuzz runs beside it; a figure
taken there would have been INDICATIVE at best and would have told us less
than the hash does. There is also nothing architecture specific to owe: the
release artifact is unchanged, so there is no x86-64 half of a performance
claim to take.

### Debug: about 6% of the test suite

Measured back to back in the same minutes, same box, aarch64, one minute load
6.73 falling to 7.48 across the pair:

| `cargo test -p rarkit --lib` | wall | user CPU | tests |
|---|---|---|---|
| with the guards | 171.21 s | 296.26 s | 271 |
| with this branch's `src` diff reversed | 161.24 s | 287.33 s | 263 |
| cost | **+6.2%** | **+3.1%** | +8 (the guard's own) |

A snapshot and a compare of 128 bytes per match, on three windows, in test
builds only. For comparison, H2's own guard took its package's suite from
about 35 s to about 190 s; that guard is present in BOTH rows above, so the
6.2% here is this sweep's addition on top of it.

## Fuzz

`cargo +nightly fuzz run --debug-assertions`, 600 s each, on this branch with
the guards in. The pinned stable toolchain cannot build a fuzz target
(`-Zsanitizer` is nightly only), which is worth knowing before the next
reader spends ten minutes finding it.

| target | window it reaches | runs | exec/s | peak RSS | crashes |
|---|---|---|---|---|---|
| `rar20_member` | RAR 2.0 (window 2) | 4,002,696 | 6,660 | 225 MB | 0 |
| `rar20_tables` | RAR 2.0 tables, reaches the window | 9,025,864 | 15,018 | 408 MB | 0 |

No artifact was written by either.

**The RAR 3 and RAR 1.5 windows got no fuzz coverage from that run**, and
the reason given for it was wrong; see "The note that was wrong, and why"
below. `rar3_filter_record` does not close the gap either way:
`rar3_record_stream` hands the transform a synthetic `zeros` buffer as
`SpanBytes::Window` and never constructs the real `Window` at all.

### 19 Sep 2026, later the same day: the windows that had none

Same method, `cargo +nightly fuzz run --debug-assertions`, 600 s each, on
`fuzz/h1-and-spec-a-targets`. LOAD IS QUOTED because it is not a quiet box:
several other fuzz runs and builds were going throughout, so the exec/s
column is INDICATIVE and the run counts are a floor rather than a figure to
compare against another run.

| target | tree | window it reaches | laps it | runs | exec/s | peak RSS | crashes |
|---|---|---|---|---|---|---|---|
| `rar3_lz_window_edge` | `fuzz` | RAR 3 (window 1) | **3.0x** | 7,062 | 11 | 370 MB | 0 |
| `rar15_window_edge` | `fuzz` | RAR 1.5 (window 3) | **3.0x** | 8,613 | 14 | 397 MB | 0 |
| `rar3_lz_member` | `crates/rarkit/fuzz` | RAR 3 (window 1) | 1.0x | 784,403 | 1,305 | 152 MB | 0 |
| `rar3_lz_tables` | `crates/rarkit/fuzz` | RAR 3 tables | never | 8,507,707 | 14,155 | 414 MB | 0 |
| `rar3_lz_solid_chain` | `crates/rarkit/fuzz` | RAR 3 (window 1) | 1.0x | 608,598 | 1,012 | 165 MB | 0 |

No artifact was written by any of them. The bottom three are a SECOND run
of targets the fuzz inventory had already run the same day;
they are here for the `laps it` column,
which is the one that matters and which no target list carries.

**The `laps it` column is the point of this table.** A target that never laps
cannot see this class at all, and two of the five cannot: `rar3_lz_tables`
never reaches the window, and `fuzz_member` declares `1 << 16` bytes into a
`1 << 16` dictionary so it arrives at the end of its first lap and stops.
`fuzz_solid_chain` declares `1 << 14` across four members, one lap exactly if
every member runs to its declared size. Thirty minutes of those three is
thirty minutes in which the guard has almost nothing live to catch a spill on.

**And the 3.0x in the top two rows was 1.077x when they were first run.** That
is recorded below under "The target that was itself nearly blind", because it
is the same mistake in a third place and it was caught only by running the
thing.

**The two window edge targets are the ones that matter, and why is this**: a target that never LAPS its ring is structurally incapable
of seeing this class, because below one lap every slot ahead of the write
point holds a byte the stream never produced and a copy that overruns is
writing on dead memory. That is not hypothetical for the three H1 targets
above: `fuzz_member` declares `1 << 16` bytes into a `1 << 16` dictionary, so
it reaches the end of its first lap and no further, and `fuzz_solid_chain`
declares `1 << 14` per member across four members, which is one lap exactly if
every member runs to its declared size. Thirty minutes of those three is thirty
minutes in which the guard has almost nothing live to catch a spill on.

So `rar3_lz_window_edge` builds its member instead of hoping for one: the
smallest dictionary SPEC-H1 3.6 declares, a member that laps it three times,
and lead-then-edge match pairs chosen by the fuzz bytes, written by this
crate's own RAR 2.9 encoder and read back byte for byte.

`rar15_window_edge` cannot do that, because there is no RAR 1.5 ENCODER in
this crate. What it forces is the lap alone: the seed is TILED to 256 KiB of
packed bytes and the member is asked for three laps of the 65,536 byte ring.
Past the first lap `Run::check_spill`'s `produced` is `WINDOW`, so every
watched slot is reachable and any spill at all fails - and the guard is then
the verdict rather than the output, which is what point 4 of the class asks
for anyway. `tests/window_edge_targets.rs` is the proof the lap really
happens, held to the same standard as the guards themselves: all 64 seeds of
4 KiB lap, and the furthest reaches the full 196,608 bytes. Used UNTILED a
4 KiB seed is about 3,600 RAR 1.5 literals and stops at a twentieth of one
lap, which would have made the target exactly the vacuous exercise item 4
describes.

### The target that was itself nearly blind

Recorded because it is the third time in two days this file has had to write
down a check that could not see the thing it was checking, and the first two
are already above: H2's guard watching exactly its own margin, and this
guard's `WATCH` vacuous at 64.

`rar3_lz_window_edge` ran its first ten minutes, found no crash, and was
nearly useless. The log's own `lim:` column says why:

    #413   NEW  cov: 1556 ft: 1556 ... lim: 8
    #25324 DONE cov: 2069 ft: 5562 ... lim: 25

libFuzzer never grew its inputs past TWENTY FIVE BYTES, because one exec
encodes and decodes a fifth of a megabyte and costs about 24 ms. The first
construction built one lap of base and then appended one lead-then-edge pair
per three seed bytes, so the LAP COUNT WAS A FUNCTION OF THE SEED LENGTH. At a
25 byte seed the seed yields six whole chunks, and six pairs of at most
64 + 23 + 70 bytes on a 69,632 byte base is at most 70,574 bytes: **1.077
laps**, against the three the doc comment claimed. Only about 660 bytes of the
member sat past the lap, which is the only place a `SpillWatch` can bite,
because below one lap every slot ahead of the write point holds a byte the
stream never produced.

The pairs now CYCLE over the seed until the member is three laps, so coverage
still comes from the seed - every lead length, every gap, every distance - but
the lap count does not. Held to it by
`tests/window_edge_targets.rs`, at the seed lengths that OCCUR rather than
comfortable ones: 8, 9, 16, 25, 64, 512 and 4096 bytes. The old shape fails
that test at every seed up to 512 bytes.

What the fix bought, same box, same 600 s, both under `--debug-assertions`:

| | runs | exec/s | cov | ft |
|---|---|---|---|---|
| seed length sets the laps (1.077x) | 25,324 | 42 | 2,069 | 5,562 |
| construction sets the laps (3.0x) | 7,062 | 11 | **2,171** | **8,099** |

28% of the execs, 46% more features. Fewer, longer execs that actually reach
past the lap are worth more than many short ones that cannot.

`rar15_window_edge` never had the defect, because its seed is TILED to a fixed
256 KiB whatever its length, and its own ten minute run shows why that
mattered: `lim:` stayed at **8 bytes** for all 8,613 execs. Its test checks 1,
2, 8, 9, 16, 25, 64, 512 and 4096 byte seeds; every one laps, and the shortest
member any of them builds is 131,072 bytes, two full laps.

The general rule, for the next target of this kind: **make the lap a property
of the CONSTRUCTION, never of the seed length**, because a target whose every
exec is expensive is a target whose seeds stay tiny, and tiny seeds are
exactly where a seed-length-driven construction stops lapping.

**And `rar5_window_edge` has the same shape, unfixed.** It was the model these
two were built on, and its base is `window + 4096` with its pairs appended one
per three SEED bytes, so at the seed lengths that occur it laps about 1.03
times rather than the "twice" its own doc comment claims. H2's ring is the one
ring in the crate WITH a margin, and its guard watches `STRIDE_MAX + SPILL`
against it, so the target is thin rather than blind. It is package H2's and
this sweep did not touch it: see "Still to do" below.

### The note that was wrong, and why

The bullet that stood in "Still to do" until this run said that the H1 results'
section 7 reports 11 minute runs of `rar3_lz_member`, `rar3_lz_tables` and
`rar3_lz_solid_chain`, that none of the three was in `fuzz/fuzz_targets` or
`fuzz/Cargo.toml`, and that `git log -S` over `fuzz/` found no commit that
added or removed them. Every one of those statements is true, and the
conclusion drawn from them is false.

**There are TWO fuzz trees in this repository.** The root `fuzz/` holds the
RAR 5, RAR 2.0, writer and crypto targets. `crates/rarkit/fuzz/` holds the F,
I, J, L and H1 targets, with its own `Cargo.toml` and its own `Cargo.lock`.
All three H1 targets are in the SECOND one and always have been: they landed
with the H1 package itself, and section 7 names the path in its
own first line - "Three targets in `crates/rarkit/fuzz`". The search that
produced that bullet was run against the root tree alone, which is also
why `git log -S` over `fuzz/` was silent.

Worth keeping rather than quietly deleting, for two reasons. It is the same
shape of mistake as the vacuous guard recorded above - a check that cannot see
the thing it is checking, reported as evidence that the thing is absent - and
it is the second time in one day this file has had to record one. And the
repair is structural, and it landed the same day:
a fuzz inventory check holds BOTH trees to one expected list
and runs with the project's checks, so a one tree search can no longer be mistaken
for the whole repository. That file also now carries, in its header, WHICH
TARGETS LAP THE WINDOW THEY DRIVE, because that is the property this class
turns on and a target list cannot show it.

What was genuinely missing, and is now done, was never the three H1 targets. It
was the window EDGE coverage for these two windows, which no target in either
tree had.

## Still to do

- **The RAR 3 and RAR 1.5 window edge targets: DONE**, 19 Sep 2026, in the
  table above. The bullet that used to stand here said the three SPEC-H1 6.3
  targets did not exist; they do, and it was WRONG in a way worth keeping on
  the record. See "The note that was wrong, and why" above.
- **`fuzz/fuzz_targets/rar5_window_edge.rs` needs the same fix**, and it is
  package H2's, not this sweep's. Its member laps about 1.03 times at the seed
  lengths libFuzzer reaches, because its base is `window + 4096` and its pairs
  are one per three seed bytes. The repair is the one applied to
  `rar3_lz_window_edge`: cycle the seed's pairs until the member is a fixed
  number of laps, and hold it there with a test over the seed lengths that
  occur. Still to do.
- **An oracle adapter that decodes ONE RAR 1.5 member's packed bytes**, which
  is not written yet. `rarkit-oracle` is reachable from here
  through whole archives only, so `rar15_window_edge` has no output arm and
  rests on the write side guard alone. That is what point 4 of this class asks
  for and it is sound, but an output comparison would be worth having beside
  it.
- **Nothing on performance**, for the reason in "Release" above.
