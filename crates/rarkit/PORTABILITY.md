# Portability: pointer width, and the targets no box here builds

Written 19 Sep 2026, from the specifications alone.

Every development box carrying this project is aarch64 and 64-bit. Until
this sweep nothing here had ever linted, type-checked or run:

- the `not(target_arch = "aarch64")` arms,
- a 32-bit `usize`,
- Windows, for any target at all.

`make x86` (18 Sep) proved the x86-64 arms COMPILE. It did not lint them,
it never looked at a 32-bit target, and it never looked at Windows. That
gap is what `make cross` now closes, and it is a gate rather than advice.

The shipped targets are the ones the consuming application ships: x86-64
and aarch64 Linux gnu and musl, `armv7-unknown-linux-musleabihf`, Windows
gnu and msvc on x86-64 and aarch64 msvc, iOS, Android and both Apple
triples, with and without default features.

## 1. The rule this crate follows

A value that a specification allows past 4 GiB - a member's unpacked or
packed size, an offset into one, a volume size, a RAR 5 dictionary, a
recovery payload - is one of exactly three things, and never a bare
narrowing cast:

1. **kept `u64`**, which is the answer wherever the value is a count
   rather than an index into memory this process holds;
2. **converted with `usize::try_from`**, refused with the error kind the
   specification gives for an unsupported or over-limit size, where it
   sizes an allocation;
3. **provably under 4 GiB, with the reason written at the site**, where a
   bound already holds it there - a `u16` header field, a policy check
   that ran first, an invariant the surrounding code asserts.

Nothing on a 64-bit target changes: every conversion added here is exact
on a 64-bit `usize`, and `u64::try_from`/`usize::try_from` cannot fail
where `usize` is 64 bits wide.

## 2. The census

`crates/rarkit/src` holds about 446 `as usize` casts. They fall into
five classes, and only the first and the last could ever have been wrong:

| Class | Where | Treatment |
|---|---|---|
| A `u64` that a specification allows past 4 GiB | the sites in section 3 | fixed: `u64` end to end, or `try_from`, or a saturating `min` |
| A `u64` a check has ALREADY bounded | comment sizes (`max_comment`), encode dictionaries (`max_dictionary`), header lengths (`max_header`), RAR 4 and RAR 1.3 header sizes (a `u16` field) | provable; the bound is the line above the cast, or is named in a comment |
| A `u32`, `u16` or `u8` | the whole PPMd arena (`ppmd/arena.rs` is `u32` throughout), the RAR 3 and RAR 2.0 window capacities, every table index, every symbol | exact on a 32-bit `usize` too: `u32 as usize` never narrows on a 32-bit target |
| An index into a buffer this process already holds | `write/engine.rs`'s packed buffer, `read/cursor.rs`'s window, `rar3_lz/window.rs::slices` | provable: the length it indexes is itself a `usize` |
| A `u64` CLAMPED AFTER being narrowed | the five sites of 3.6 | the worst of them, because it looks bounded: fixed by clamping in `u64` first |

`usize::try_from` guards: 21 before this sweep, and the sweep adds the
ones section 3 names. `target_pointer_width` sites: ZERO before this
sweep; `memory.rs` is now the only one that changes a value, and the
tests state both arms.

The classification above was done twice and by two different means,
because the first was not enough. A hand audit found sections 3.1 to 3.5
and 3.7. It MISSED the whole of section 3.6, five sites in three
packages, because each of them looks bounded: the cast is wrapped in a
`min`. The compiler found them:

    cargo clippy -p rarkit --target armv7-unknown-linux-musleabihf \
        -- -W clippy::cast_possible_truncation

reports every cast whose width depends on the pointer - 104 of them - and
reading all 104 is what the second pass did. That command is worth
re-running whenever this crate grows a new size calculation; it is not in
`make cross` because it cannot be driven to zero (see 3.6).

## 3. What was wrong, and what it would have done

### 3.1 The RAR 5 window's member counter (silent wrong output)

`rar5_lz/output.rs`, `Window::produced()` returned
`(stream_produced() - member_base) as usize` from two `u64` fields, and
every call site cast it straight back to `u64`. A RAR 5 member's declared
unpacked size is a 64 bit field (SPEC-H2 section 3.1) and members over
4 GiB are ordinary traffic.

On a 32-bit target the count truncated INSIDE the accessor, so:

- the decode loop's termination test, `produced() < unpacked`, compared a
  wrapped count against the true size. At 4 GiB + 30 produced against
  4 GiB + 20 declared the member reads as NOT done and over-produces;
- `room = (unpacked - produced()) as usize` wrapped as well. A remainder
  of exactly 4 GiB truncates to ZERO, every match clamps to zero length,
  and the loop produces nothing per iteration and never ends.

Neither raises an error. This is wrong output, silently.

Fixed: `produced()` returns `u64`; `emitted`, `next_drain` and
`Span::start` are `u64`; `ring_slices` and `emit_range` take `u64`
offsets and narrow only the two figures a lap of the ring bounds, each
with the bound written at the site. The room left goes through
`rar5_lz::room`, which SATURATES at the pointer width and never wraps.
`Span::length` stays `usize`: section 3.6 bounds a filter block at
`MAX_FILTER_BLOCK_LENGTH`, far under 4 GiB. The RAR 3 side
(`rar3_lz/stream.rs`, `rar3_lz/window.rs`) already returned `u64` and is
unchanged.

**Could a 64-bit build ever have produced wrong output from this? NO.**
On a 64-bit target `usize` is 64 bits, so `(a - b) as usize` and the
`as u64` back are both the identity: every value round-trips unchanged
through the old accessor. The defect needs a narrower `usize` to exist at
all. Every figure this crate has measured or verified was measured on a
64-bit build and stands.

### 3.2 An allocation sized by an untrusted RAR 2.0 header

`lz20.rs`, `Stream::member`, did `Vec::with_capacity(unpacked as usize)`
where `unpacked: u64` comes from a RAR 2.0 member header. Spec F section
4.2 is explicit: a declared unpacked size is "never used to size a buffer;
it is a limit on output, checked as output is produced". On a 64-bit
target a header of a few bytes asked for the whole declared size at once;
on a 32-bit one a declared size at or over 4 GiB truncated and reserved
some small unrelated figure instead.

Fixed: `reserve_for` caps the up-front reservation at
`OUTPUT_RESERVE_MAX` (1 MiB) and the vector grows as output arrives. The
declared size is still the loop's termination test, which is what the
specification says it is for.

### 3.3 The extract path's room-left clamp

`read/extract.rs` computed `plain.len().min((n - written.min(n)) as usize)`
for a member's remaining room. On a 32-bit target a member above 4 GiB has
more room left than a `usize` holds, and truncating cuts a chunk short in
the middle of a member with no error. Now saturated through
`usize::try_from(..).unwrap_or(usize::MAX)`, which is exact on both widths
because `plain.len()` cannot exceed `usize::MAX` either.

### 3.4 The recovery payload accumulator

`rev5.rs`, `create`: the per-row accumulator is `payload` bytes, and
`payload` is derived from the largest DATA VOLUME in the set - an ordinary
file size, which may be well over 4 GiB. `vec![0u8; payload as usize]`
truncated on a 32-bit target and then folded parity into an accumulator of
the wrong size. Now `usize::try_from`, refused as
`LimitExceeded { resource: RepairWork }`. On a 64-bit target the
conversion cannot fail, so nothing changes.

### 3.5 An encode dictionary the target cannot address

`write/options.rs` checked the dictionary against
`MemoryPolicy::max_dictionary` but not against the pointer width, and each
encoder then took it through `options.dictionary as usize`. The format's
own maximum is 4 GiB, which on a 32-bit target IS the whole address space.
Now refused as `LimitExceeded { resource: Dictionary }`. `MemoryPolicy`'s
fields are public, so the clamp in section 4 is not on its own enough to
make this unreachable.

### 3.6 CAST BEFORE CLAMP, five times, in three packages

The one thing a hand audit did not find and the compiler did. The shape is

    let n = (big_u64 as usize).min(small);   // WRONG on a 32-bit target

and the right one is

    let n = big_u64.min(small as u64) as usize;   // exact on any width

Clamping AFTER narrowing is worse than a bare cast, because it looks
bounded. On a 32-bit target the narrowing wraps first and the `min` then
picks the wrapped figure, so the clamp that was supposed to make the
value safe is what hides the damage. A remainder of exactly 4 GiB narrows
to ZERO, and every one of these sites treats zero as "nothing left".

Found by `cargo clippy --target armv7-unknown-linux-musleabihf -W
clippy::cast_possible_truncation`, which reports 104 casts whose width
depends on the pointer, and reading every one of them:

| Site | What it is | What truncating did |
|---|---|---|
| `read/walk.rs`, `MemberReader::read_inner` | bytes left in a member fragment | `want == 0` returns `Ok(0)`: **end of data reported in the middle of a member** |
| `rar3_lz/mod.rs`, the literal burst | room left in the member | a burst cut short, or to nothing |
| `rar3_lz/bits.rs`, the stream reader's advance | how far the reader may skip | the reader advances by the wrong step, or not at all |
| `rar3_lz/bits.rs`, `tail_word` | the live byte count at the tail | zeros read in place of live bytes |
| `lz20/bits.rs`, `whole_bytes_left` | a stream-wide byte count | not even monotone in the bytes consumed |

All five are outside `src/carry/`. All five now clamp in `u64` first.

The census is NOT driven to zero and should not be: the lint fires on
every `u64 as usize` whether or not a bound makes it exact, so a zero
would mean `try_from` on hot paths that provably cannot fail. What the
census is for is to enumerate the 104, and every one has now been read
and classified. One was in `src/carry/`: `c_lz/codec/rar50.rs`, `MatchIndex::long_slot`,
class 3 of the rule in section 1 (provably under 4 GiB). DONE 19 Sep
2026: the shift leaves fewer than
`LONG_INDEX_MAX_ENTRIES` (2^20) values, and the reason is now written at
the site, with a test that drives spans either side of `u32::MAX`. The
other, `a_containers/source.rs`, no longer exists: the package was
deleted as dead code (at an earlier revision). The one `f64 as usize` in `carry/`
(`flat_slack_with`) saturates and is clamped by its ceiling; commented and
tested the same way. No carried line changed behaviour on 64-bit.

### 3.7 A repair stripe the target cannot address

`recovery/stripe.rs`, `Rebuild::stripe_len`, sized the stripe buffers from
`repair_limit / rows` alone, and `Rebuild::run` took the figure through
`stripe_len as usize`. `MemoryPolicy`'s fields are public, so a caller may
raise `repair_limit` past a 32-bit address space; a truncated stripe
length would then rebuild the wrong bytes rather than refuse. The figure
is now capped at `usize::MAX` as well as at the budget, which is the
identity on a 64-bit target.

`recovery/rr5.rs`, `Rr5Encoder::new`, narrows `plan.shard_len` too. Every
plan that reaches it is an `Rr5Plan::new` built from the length of a slice
this process already holds, never an `Rr5Plan::declared` parsed out of an
archive, so the narrowing is exact on any width. That is now written at
the constructor with a `debug_assert`, because the SAME struct can carry
an untrusted `shard_len` on the decode path and nothing in the type says
which kind a given plan is.

### 3.8 What was looked at and left alone

- `recovery/legacy.rs` allocates `record.data_len()` bytes for a RAR 4
  protect record. The parse forces `data_len` to equal a `u32` field and
  the record's data to lie inside the volume, so the narrowing is exact on
  a 32-bit `usize` as well. It is not bounded by `repair_limit`, though,
  so a valid header can still ask for a large allocation. That is a memory
  policy question rather than a pointer-width one, and it is LEFT OPEN rather
  than changed here: this document's remit is pointer width, and a bound needs
  spec L text to pick.
- The whole PPMd arena is `u32` throughout, so `u32 as usize` never
  narrows on a 32-bit target either. 20 casts, none of them in scope.
- Name arena offsets (`read/extract.rs`, `read/walk.rs`, `read/dump.rs`)
  are bounded by `max_member_table`, header spans by `max_header`, RAR 4
  and RAR 1.3 header sizes by a `u16` field, RAR 3 filter spans by
  `MAX_SPAN`, and `write/engine.rs`'s offsets index a buffer this process
  already holds. All provable, all left alone.

## 4. The memory policy's 32-bit arm

`memory.rs` clamped `max_window` and `repair_limit` to 4 GiB and
`max_dictionary` to 1 GiB. On a 32-bit target 4 GiB is the whole address
space of the process, shared with the packed buffer, the decoder tables,
the output path and the allocator's own fragmentation: a ceiling nothing
can ever map is not a ceiling.

`WINDOW_CEILING` and `DICTIONARY_CEILING` are now per pointer width:

| | 64-bit | 32-bit |
|---|---|---|
| `max_window`, `repair_limit` | 4 GiB | 512 MiB |
| `max_dictionary` | 1 GiB | 256 MiB |

The consuming application clamps its own budget to 1 GiB of address space
on a 32-bit target; rarkit takes half of that for a decode window and a
quarter for an encode dictionary, so a window at the ceiling still leaves
the rest of the process room to work in. At the DEFAULT budget every field
is far below both ceilings, so the default policy is the same figure on
either width and spec F section 4's table still describes it.

A dictionary above the clamp is refused as
`LimitExceeded { resource: Window }` before any allocation, which
`Rar5Lz::new` already did; the clamp is what makes that refusal reachable
rather than an allocation attempt.

**NOT YET SPECIFIED.** `SPEC-API-rarkit.md` section 8 and
`SPEC-F-rarkit-containers.md` section 4 say nothing about pointer width.
These two figures are a conservative choice made here, not a pinned
answer, and the spec text that pins them is not written yet.

## 5. Windows

The library and the CLI already compiled for every Windows target. The
DEV targets did not, and nothing had ever asked them to:

- `tests/writers.rs` used `std::os::unix::fs::MetadataExt` and
  `Metadata::mode()` with no gate. The test compares against reference
  `rar` output for a UNIX host, so off unix it now skips BY NAME rather
  than silently, and the site is gated so the file still type-checks.
- The gate bench used `libc::rusage`, `getrusage` and `RUSAGE_SELF`
  for CPU seconds and peak RSS. `libc` is a `cfg(unix)` dependency of the
  library and is now a `cfg(unix)` dev-dependency too.

Windows has no arm for either figure, and it reports **unavailable**
rather than zero. The Windows equivalents are `GetProcessTimes` (kernel32)
and `GetProcessMemoryInfo` (psapi), and NOTHING already in this workspace
binds them: there is no `windows-sys` and no `winapi`, and the `libc`
crate exposes neither there. Adding a dependency to print a bench figure
was not worth it; a zero in a results table would be a wrong number, which
is the class of defect this whole sweep is about. Not done yet: a real Windows
peak-working-set arm, if anyone ever benches there.

## 6. What is tested, and what is not

Tested ON THIS 64-BIT HOST, by driving the arithmetic rather than
producing it:

- `rar5_lz::tests::pointer_width` seeds the window's counters past 4 GiB
  (`Window::seed_counters_for_test`) and checks the member count, the
  termination test and a drain at those sizes. Each case also asserts
  that the TRUNCATING form gets it wrong, so a case that would prove
  nothing fails instead of passing.
- `rar5_lz::room_at_width` takes the pointer width as a PARAMETER, and
  `room` is defined in terms of it. Passing `u32::MAX` runs exactly the
  expression a 32-bit build runs.
- `lz20::tests::a_declared_size_never_sizes_the_output_buffer` drives
  `reserve_for` either side of 4 GiB and past it.
- `memory::tests::the_pointer_width_ceilings_bind_only_a_large_budget`
  states both arms.

Kept COMPILING and clippy-clean, by `make cross`:
`x86_64-unknown-linux-gnu`, `armv7-unknown-linux-musleabihf` and
`x86_64-pc-windows-gnu`, plus `--all-targets` for the Windows one and for
the x86-64 one.

**NOT DONE, for want of a box that has one: nothing here has RUN on
32-bit hardware or under a 32-bit target's test harness.** `cargo test
--target i686-unknown-linux-gnu` is not runnable on an Apple Mac. The tests
above are written so they need no 32-bit host, and `make cross` keeps the
32-bit target building and lint-clean, but a real
`cargo test --target i686-unknown-linux-gnu` or
`--target armv7-unknown-linux-musleabihf` run under qemu is still to do, and so
is a 32-bit fuzz run.
