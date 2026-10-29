# Pinned seeds for `fuzz:edit_roundtrip`

`corpus/` is gitignored, so a target with nothing here starts every
campaign from the empty input. This one did: the whole roster campaign of
20 Sep 2026 measured `edit_roundtrip`'s last new basic block at execution
779 of 20,704,032, and a second campaign that fed it real archives from a
scratch directory reached coverage 4,887 against 104 unseeded. This
directory is that corpus, committed, so the next campaign starts where
the last one finished. `cargo +nightly fuzz run edit_roundtrip
seeds/edit_roundtrip` replays the lot.

## What a seed is

Three bytes of script and then an archive, which is the target's own
layout: byte 0 is the operation (`% 5`), byte 1 its argument, byte 2 its
length, and everything after them goes to `Archive::open`. Every seed is
named `<archive>__op<N>_a<argument>_l<length>`, so the operation a seed
drives is readable without a hex dump:

| op | what it drives | the seeds that carry it |
|---|---|---|
| 0 | `edit::set_comment`, cleared and set from the archive's own first 64 bytes | `__op0_a0_l0`, `__op0_a0_l64` |
| 1 | `edit::lock`, and the reopened archive reporting it | `__op1_a0_l0` |
| 2 | `edit::remove` of the first, the second and the last member | `__op2_a0_l0`, `__op2_a1_l0`, `__op2_a255_l0` |
| 3 | `edit::rename`, to a one letter name and to a thirteen letter one | `__op3_a0_l0`, `__op3_a1_l12` |
| 4 | `edit::set_recovery` at 3 per cent and at 100 | `__op4_a2_l0`, `__op4_a99_l0` |

## Where they came from, and what each family exercises

Every archive in the repository that `Archive::open` accepts and that is
under 40 KiB, behind each of the ten scripts above: 730 candidates, run
through `-merge=1`, which kept the 163 here. Each one therefore buys a
basic block no other seed in this directory buys.

**`r4_*` (`specs/vectors-G/archives`), the RAR 4 writer vectors.**
`r4_store`, `r4_m3` and `r4_solid` are the three member SHAPES a rewrite
copies: stored, compressed, and a solid chain whose members cannot be
reordered. `r4_cmt` and `r4_lock` start with the block `set_comment` and
`lock` rewrite, so those two arms see an archive that already has one.
`r4_rr` starts with a recovery record, which `set_recovery` must replace
rather than append. `r4_pw` and `r4_hpw` are an encrypted member and an
encrypted HEADER: the second is the case where the rewrite cannot read
the names it is copying. `r4_ts` carries high precision times, `r4_vol`
and `r4_volvn` a volume of a set, where a rewrite must refuse or keep the
set's own flags.

**`r5_*` (same directory), the RAR 5 writer vectors.** The same shapes in
the other container: `r5_store`, `r5_m3`, `r5_solid`, `r5_cmt`,
`r5_lock`, `r5_rr`, `r5_pw` and two volumes. RAR 5's service blocks sit
differently from RAR 4's, so the comment and recovery arms take a
different path here even though the API call is the same.

**`f01` to `f19` (`specs/vectors-F/archives`), spec F's container
corpus.** `f01_stored`, `f02_dirs` (directory entries, which have no data
to copy), `f03_m3`, `f04_solid`, `f05_blake` (a BLAKE2sp checksum rather
than a CRC32, which the listing assertion compares), `f06_comment`,
`f07_pw`, `f08_hp` (header encryption), `f09_rr`, `f10_qo` (quick open
records, which name the offsets a rewrite moves), `f11_svol` and
`f12_cvol` volumes, `f16_sfx_prefix` (an SFX stub ahead of the archive,
which every offset the rewrite writes has to carry), and the three
timestamp vectors `f17` to `f19`.

**`f13_truncated`, `f14_bad_header_crc`, `f15_bad_data_crc`.** The
damaged three. They are here because the target's contract starts at
`Archive::open`: what these cover is an archive that opens and then
cannot be rewritten, which is the path where a rewrite must return `Err`
rather than produce something that does not reopen.

**`D140_M5.RAR`, `D155_M5.RAR`, `D250_M5.RAR`, `r420_m5`, `r420_hp`.**
The legacy containers: RAR 1.5, 2.0 and 2.9 written by the genuine
archivers of 1994 to 2012. A rewrite COPIES a member's packed bytes
rather than decoding them, so what these test is the header walk over
containers this crate never writes.

**`create_*`.** The create path's own output, built with this
repository's CLI so that the seeds cover what rarkit ITSELF writes and
not only what it reads: `create_m0` (stored), `create_m1` and
`create_m5` (the method ends), `create_solid`, `create_rr` (a recovery
record to replace) and five parts of a seven volume set. Only RAR 5 is
here, because the CLI writes RAR 5 alone (`-ma4` is refused, as the
reference refuses it); the RAR 4 write side is covered by the `r4_*`
vectors above.

## `rename-picks-the-first-of-two-same-names`

The one input here that is a REPRODUCER rather than a fixture, found by
this target's first seeded campaign (20 Sep 2026, an M3 Mac, execution
814,282 of a 600 s sweep, 84 s in). Script `03 01 0c` - rename, argument
1 - in front of a mutated RAR 4 archive whose two members are BOTH
stored as `hello.txt`.

`edit::rename` and `edit::remove` take a NAME, and this archive gives
one name to two members, so the target's expectation - that the member
at the argument's index is the one that changes - was wrong and the
engine's answer, the FIRST of the two, was right. The target now
asserts what the API states and no more.

WHICH of two same-named members a rename or a removal should take is in
neither SPEC-G 3.15 (comment and lock only) nor SPEC-API 7.5, and
refusing the call outright is an equally good answer: that is an OPEN
question for the specification. `crates/rarkit/tests/edit_members.rs` pins the
behaviour either way in
`a_rename_touches_one_of_two_members_that_share_a_name` and its removal
sibling.

## Rebuilding it

    rarfast a -m<N> <archive> <files>          # the create path's share
    <the seed archive script> --archives <dir> --out <scratch> ...
    edit_roundtrip -merge=1 <scratch-out> <candidates>

The candidate set is every archive under `specs/vectors-G/archives`,
`specs/vectors-F/archives`, the legacy fixtures and the created ones,
crossed with the ten scripts in the table above.
