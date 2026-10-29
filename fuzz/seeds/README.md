# Pinned fuzz seeds

`corpus/` and `artifacts/` are gitignored, so an input that cost a campaign
to find is lost the moment the box is cleaned. Anything worth keeping goes
here instead, named for what it is, and
`cargo fuzz run --fuzz-dir fuzz <target> seeds/<target>` replays the lot.

`crates/rarkit/fuzz/seeds/README.md` is the same file for the other tree,
and carries that tree's own sections.

## `rar20_member/empty-packed-declared19757`

The three bytes `2d 2d 4d`: dictionary selector 5, a declared unpacked size
of 19,757, and packed bytes that are EMPTY, the target's input being
everything from offset 3. Found in passing on 21 Sep 2026 by the par-src4k
work's campaign, on which `rar20_member` died at 0 s after 24 executions,
`fuzz_targets/rar20_member.rs:20`'s "a member is delivered whole".

It was never a decode defect. The decoder is right and the TARGET was
stale: the specification (SPEC-A 4.11 and 6.1, which says in terms "It reaches
RAR 2.0 too", with SPEC-H3 3.5 carrying the cross-reference) ends a member
at the step that BEGINS with the packed input already exhausted. An empty
packed input is the limiting case, so the member produces nothing though it
declared 19,757, and that is `Ok`: the shortfall is the caller's member
CHECKSUM to report (`MemberOutcome::checksum_ok == Some(false)`, SPEC-F
2.5). The target now asserts the bound SPEC-A section 6 does promise, that
no member delivers MORE than it declared, and the case is pinned as unit
tests at `lz20::tests::an_empty_input_ends_a_rar20_member_at_once`
and `lz20::tests::a_member_never_delivers_more_than_it_declared`.
Package A had such a pin already and package D had none, which is why the
fuzz target was the first thing to notice.

## `rar1x_member/<archive>__<MEMBER>`

Added 7 Oct 2026 with the target. These are SEEDS, not reproducers: ten
genuine members of the RAR 1.40.2 archives of `fixtures/legacy`, each in
the target's own input shape, which is three bytes of little endian
declared size, a zero flags byte, and the member's packed bytes exactly as
the DOS writer left them. They are every compressed member of
`d140_m5.rar` (seven, from a 300 byte text that packs to 194 up to
`AUDIO.RAW`, 36,000 bytes that pack to 34,697) and the three text members
of `d140_m1.rar`, whose packed bytes differ from their `-m5` forms. A run
that starts from them starts inside the grammar.

`crates/rarkit/tests/rar1x_member_seeds.rs` holds the directory to the
fixtures byte for byte, in both directions, and its `emit_seeds`
(`#[ignore]`, because it writes into the source tree) regenerates it.

## `edit_roundtrip/*` and `write_volumes/*`

Predate this README; see the commits that added them.

## `read_seam/*`

The four pinned inputs of `fuzz:read_seam` (SPEC-F 3.7.7, the one-member
seam). Each names a branch of that target's shape table, and three of the
four are cheap; the first is not, and is pinned precisely because a
campaign should not be left to find it by luck.

- `real-floor-16mib`: the input that takes the OPT-IN arm, a member with
  a decoder clearing the ENGINE'S OWN 16 MiB floor rather than a floor
  the harness forced. It runs that arm only under
  `RARKIT_SEAM_REAL_FLOOR`, and a campaign sets no environment: 25.2 s
  an execution with the variable set against 103 ms without it, on
  an M3 Mac under the address sanitizer. Taking the arm unconditionally
  at one input in 256 was MEASURED and abandoned, because libFuzzer
  keeps an input that reaches new branches and runs it again: a 600 s
  sweep managed 162 executions where `rar5_member` managed 2.53
  million.
- `encrypted-split-crc32`: the vector of a difference the target found
  on 22 Sep 2026: an encrypted member split across volumes with a CRC32
  record read back with the right bytes and a verdict of `Some(false)`,
  because the writer checksummed a leading fragment's plaintext where
  spec K 3.7.6 has the plain CRC32 of its ciphertext. The writer was
  fixed on 25 Sep 2026 and the target now holds this shape to a TRUE
  verdict like every other
  (`crates/rarkit/tests/encrypted_split_fragment_crc.rs`).
- `stored-blake2sp-by-hint`: a stored BLAKE2sp member engaged by
  `ReadOptions::sink_is_file: Some(true)`, which is the other way into
  the seam and the one that leaves the member's checksum on the SOURCE
  unit.
- `no-room-for-a-ring`: a read-ahead budget of 64 KiB, where
  `read/seam.rs::ring_plan` answers `None`, the member runs in sequence
  and SPEC-API 8.5 says that is never an error.

## `rar3_filter_record/*`, `rar3_filter_transforms/*` and `rar20_audio_lane/*`

Added 22 Sep 2026 by the x86-64 audio lane campaign, which found the
three filter targets starting from nothing at all. These are SEEDS, not
reproducers: no campaign paid to find them, and they exist so a run
starts inside the grammar rather than spending its first minutes
discovering that a record begins with a flags byte.

- `rar3_filter_record/<archive>` is one genuine archive's whole record
  stream, in the step-byte-then-record shape the target reads. The test
  that writes them builds each from the rows of
  `specs/vectors-J/genuine-records.tsv` through this crate's own
  `rar3_filters::builder`: every program, register set and span length
  is one a genuine rar 4.20 or 3.93 wrote. Regenerate with
  `cargo test -p rarkit --features repo-tests
  rar3_filters::tests::write_the_record_seeds -- --ignored`, which is
  `#[ignore]` because it writes into the source tree.
- `rar3_filter_transforms/<archive>__<kind>_a<a>_b<b>` is one seed per
  distinct transform and parameter pair those same traces carry, with the
  archive's own bytes as the span.
- `rar20_audio_lane/<alphabet>__c<channels>` is one seed per residual
  alphabet spec D part 1 names, at each of the four channel counts a
  multimedia block header can select: the unit ramp, the turn at the
  first adaptation, the weight ceiling, and the four values around `sx`'s
  extremes that section 1.4.2's bound is computed for.

The last two are written by a seed script, which is
deterministic: a regeneration that changes a byte is a change in the
vectors it reads.

## `rar5_member/` and `rar5_solid_chain/arms-disagree-truncated-against-incomplete-member`

REPRODUCERS, found on 8 Oct 2026 by the campaign of that day at main
46a1d5bd5 (item FUZZ-08OCT-1; `fuzz/findings-08oct/README.md`). Fourteen
bytes, `8b db 0a 00` and ten of `7b`, for `rar5_member`; four bytes,
`24 e3 b9 00`, for `rar5_solid_chain`. Each is a short member for which the
serial decode answers `Truncated` and the parallel decode answers
`Corrupt(Rar5(IncompleteMember))`, so the target's own assertion on the
error kind fails, in under a second from an empty corpus. While that
stands, both targets stop on these seeds at once: that is what they are
for. `crates/rarkit/tests/fuzz_08oct_rar5_arms_error_kind.rs` holds the
same fourteen bytes, ignored until the item is settled.

## `rar5_oracle_stream/zero-byte-member-with-filter-record`

A REPRODUCER from the same campaign (item FUZZ-08OCT-2, which is item
SWEEP2-08OCT-18 seen from this target). The eleven byte script
`2b 00 00 00 fd 00 f6 07 07 fd 00` frames one member that declares 0 bytes
and carries a filter record in its stream. Reference unrar 7.23 tests the
framed archive `All OK`; rarkit's serial arm fails it with
`Corrupt(Rar5(FilterRange))`, and the target's exemption for that kind does
not apply, so the target stops on this seed until that item is settled.

## `rar5_member/arms-disagree-bytes-before-the-error`

A REPRODUCER from the same campaign (item FUZZ-08OCT-3), 194 bytes. Both
arms fail with `Corrupt(Rar5(InvalidCode))`, the serial decode after
delivering all 262,144 declared bytes and the parallel decode after
delivering none, so the target's byte comparison fails. Reference unrar
7.23 extracts the framed member whole. It took 4.3 million executions to
find, on a copy of the target that did not compare the error kind, because
the seed above stops the true target first.
`crates/rarkit/tests/fuzz_08oct_rar5_arms_bytes_before_error.rs` holds the
same bytes, ignored until the item is settled.

## `write_members/` and `write_volumes/plain-member-with-symlink-attributes`

REPRODUCERS from the campaign of 8 Oct 2026 (item FUZZ-08OCT-4), seven and
nine bytes, seen at main 85cbb5ade and the same at 46a1d5bd5. Each plan
offers the writer an ordinary member whose Unix attributes carry the
symbolic link type; the writer returns Ok, and `rarkit::extract` then
refuses the archive as `Redirection(PosixSymlink)`, "outside this engine's
scope", so `plan.rs`'s read-back assertion fails. Whether the writer, the
reader or the target is the one to change is the item's question, not
answered here. `write_volumes` met it at execution 102, while still
reading the seeds already in its directory.

## `write_volumes/solid-rar4-empty-member-first-payload-1`

A REPRODUCER from the campaign of 8 Oct 2026 (item FUZZ-08OCT-5), 14 bytes,
the same at main 85cbb5ade and 46a1d5bd5. The plan is a solid RAR 4 archive
of a zero byte file and then a 2 byte file, with a volume payload budget of
1. The read-back delivers the 2 byte file first, so `plan.rs`'s "a member's
name changed" fails; `write_members` fails on the same bytes. The item
also records what this target cannot see: reference unrar 7.23 fails the
18 volume set the writer returned with a checksum error, where rarkit's
own test passes it.

## `write_volumes/solid-rar5-directory-first` and `write_members/solid-rar4-two-files`

REPRODUCERS from the same campaign, both under item FUZZ-08OCT-5 as added
to: 25 and 35 bytes. A solid RAR 5 plan of a directory then a file, and a
solid RAR 4 plan of a 409,615 byte file then a 3 byte file. Each is
written, and read back, in another order than the caller gave; reference
unrar 7.23 lists that order and tests both `All OK`; cleared of the solid
flag each keeps the caller's order. The targets' read-back holds the
caller's order, so they stop here until the item says whose the order is.

## `rar5_oracle_reframe/zero-byte-member-declaring-method-7`

A REPRODUCER from the same campaign (item FUZZ-08OCT-6), 72 bytes, found on
x86-64 Linux and the same on aarch64 macOS. Reframed, it is one RAR 5
member declaring 0 bytes and compression method 7. The old engine passes
it, rarkit refuses the method by name, and reference unrar 7.23 answers
"No files to extract", so the target's comparison with the old engine
fails on it. Method 6 does the same.

## `rar5_member/tables-cut-by-block-end-*` and `rar5_solid_chain/empty-last-block-with-table-bit`

Added 8 Oct 2026 (item FUZZ-08OCT-1). Reproducers, kept as seeds. On main
`46a1d5bd5` each failed its target's own assertion inside a second: the
serial decode answered `Truncated` and the tape path
`Corrupt(Rar5(IncompleteMember))` for the same member, so neither target
could be fuzzed at all.

- `rar5_member/tables-cut-by-block-end-not-last` (14 bytes, sha256
  `06a0c537...`): one block with a sound header, tables carried, not
  flagged last, whose 76 bits end inside the level table.
  `tables-cut-by-block-end-as-found` (22 bytes, `66090a22...`) is the
  input as libFuzzer first wrote it.
- `rar5_solid_chain/empty-last-block-with-table-bit` (4 bytes,
  `be13aeeb...`): a chain of one member whose one block carries the table
  bit, is flagged last and has an empty payload.

In both, every byte the block header declares is in hand: it is the
block's own bit count that ends inside its tables, before the member's
declared end. That is `IncompleteMember` on every arm (settled 8 Oct
2026; SPEC-H2 3.1 says it of a cut symbol and its sentence for a cut table
is still to be written). The difference dated from 28 Sep 2026 (`c252159f0`),
not from the block rewrites of 6 and 7 Oct. Pinned as unit tests in
`crates/rarkit/src/rar5_lz/unit_tests/short_member_kinds.rs`.

## `rar5_oracle_stream/zero-byte-member-completed-span-no-checksum`

Added 8 Oct 2026 (items SWEEP2-08OCT-18 and FUZZ-08OCT-2). A reproducer,
kept as a seed: the 11 byte script `2b 00 00 00 fd 00 f6 07 07 fd 00`
(sha256 `916727ef...`), which the target frames as one member declaring
ZERO bytes, with no checksum field, whose stream carries a delta record
for 8 bytes at offset 0 and then the bytes that complete its span. On
main `46a1d5bd5` the target failed on it at its 71st execution: the old
engine and the genuine `unrar` 7.23 pass the member, and rarkit failed it
`FilterRange`.

SPEC-H2 3.1 as restated that day: a kept span at or past the declared
size that the stream completes is `FilterRange` in a member that carries
a checksum and PASSES in one that carries none; the member's output is
its declared bytes either way, here none. The target's decoder arms now
tell the decoder that the members they frame carry no checksum, as the
reader tells it for an archive's. Pinned in
`crates/rarkit/tests/rar5_zero_byte_member_filter_record.rs` and
`crates/rarkit/src/rar5_lz/unit_tests/span_past_declared.rs`.

## `rar5_member/failing-symbol-past-the-declared-end`

Added 8 Oct 2026 (item FUZZ-08OCT-3). A reproducer, kept as a seed: the
194 byte member (sha256 `a1d1b9ce...`) whose blocks produce all 262,144
declared bytes and then hold a bit pattern that has no code. On main
`46a1d5bd5` both arms failed it `InvalidCode`, the serial decode having
delivered the whole member first and the tape path none of it, and the
target failed at its byte comparison; the genuine `unrar` 7.23 extracts
the member whole.

SPEC-H2 3.1 ("A symbol that FAILS past the declared end", added that
day): such a symbol ends its BLOCK, the member passes on its checksum
with every declared byte delivered, its next block is still decoded and
the set in force is kept, on every arm. Before the declared end the same
symbol fails the member under its own name. Pinned in
`crates/rarkit/src/rar5_lz/unit_tests/failing_symbol_past_end.rs`.

## `rar5_oracle_stream/unknown-type-record-past-the-declared-end`

Added 9 Oct 2026 (item READER-08OCT-1). A reproducer, kept as a seed:
the 113 byte script (sha256 `7e18d103...`) the target frames as eight
members with no checksum field, the first of 13,918 declared bytes
whose stream holds a filter record of a type no transform has, of
0xfdffffff bytes, read when the member's last declared byte is out. On
main `85cbb5ade` rarkit failed that member `FilterType` where the old
engine and the genuine `unrar` 7.23 pass it whole, and the target could
not run two minutes from its seeds.

SPEC-H2 3.6 ("A type of 4 or above", restated that day): the record is
read as any record is and its type is judged only if the length rule
and the order rule keep it; kept, with an empty span or one at or past
the declared size, it fails nothing and the block goes on; kept, with a
span that is not empty and starts inside the declared output, it is
`FilterType`, which is the one arm where rarkit does not follow the
genuine programs. Pinned in
`crates/rarkit/src/rar5_lz/unit_tests/unknown_filter_type.rs`.
