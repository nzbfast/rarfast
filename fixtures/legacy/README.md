# rarkit legacy fixture generator

> **This directory holds the archives as well as their generator.**
> `MANIFEST.tsv` is this tree's own run (section 0), `ARCHIVES.sha256`
> covers every file of it, and `archives/` holds the 109 files themselves.

A checked-in generator that turns the six genuine legacy RARLAB builds into
a deterministic corpus of **81 archives** covering every old on-disk format
the rarkit readers must accept. By design, old-format fixtures come from
RARLAB's own writers, never from another implementation's corpus.

No RARLAB binary or package is in this directory, and none ever will be.

## 0. The archives are committed, here

The 81 archives are committed in `rarkit`, under
`fixtures/legacy/archives/`: **109 files, 6,416,856 bytes (6.42 MB)**, being
the 81 first volumes plus their continuation and `.rev` files. They are
committed for three reasons - a re-run needs a container VM and six third-party packages, so a
corpus only such a box can produce is a corpus CI cannot have; the archives
embed times a re-run cannot promise to reproduce, so a test asserting
against a `MANIFEST.tsv` digest must be asserting against the archive that
was verified; and `specs/vectors-I`, `-J`, `-K` and `-L` already commit
their genuine-writer archives for the same reasons.

The project's fixtures check (run before its tests) holds the committed corpus to `MANIFEST.tsv` and
`ARCHIVES.sha256` and fails on a changed, missing or extra file, so the
corpus cannot drift under the tests that read it.

### What the committing run reproduced, and the eight rows it did not

The committed archives are a FULL re-run on an Apple Mac, 18 Sep 2026, from
the same six packages and the same `inputs.py`. `INPUTS.sha256` and
`REFUSED.tsv` came back byte-identical, and of `MANIFEST.tsv`'s 22 columns
**only `sha256` moved, on 8 of the 81 rows**. Every other column - the
header readings, the reference's entry counts, all 81 `unrar_7_23` verdicts
and all 21 `old_engine` DIFFERS - reproduced exactly. So section 5's warning
that the archives are not promised byte-identical is real, but it is now
narrowed to eight named rows with two identified causes:

| Rows | Bytes that move | Why |
|---|---|---|
| `r393_pw`, `r393_hp`, `r420_pw`, `r420_hp`, `r550_pw`, `r550_hp` | the whole ciphertext (68,145 of 68,896 in `r550_pw`) | RAR 3.x and later draw a **random salt** per archive, so no encrypted archive these writers produce is reproducible. The three DOS `-p` rows (`d140_pw`, `d155_pw`, `d250_pw`) are byte-stable: their ciphers take no salt. |
| `r550_rr`, `r550_cmt` | exactly **three**: a byte inside the block and the 2-byte header CRC that follows it | rar 5.5.0 stamps the recovery-record and comment sub-blocks it writes into a RAR 4 archive with the time of archiving. `r393_rr`, `r420_rr` and `r550`'s other rows do not move. |

Three independent runs on one machine (the 18 Sep original and two re-runs)
agree on the other 73 rows and disagree on these 8 every time. That is the
case for committing, made concrete: for 8 of 81 fixtures there is no such
thing as regenerating the same archive.

**The second legacy archive set.** Five more legacy archives -
`D250_M0.RAR`, `D250_M5.RAR`, `r393_m5.rar`, `r420_m5.rar` and
`r550ma4_m5.rar` - were made for spec H off a DIFFERENT input tree from
this generator's `inputs.py`. They now live in rarkit as
`specs/vectors-H/legacy/` and `crates/rarkit/tests/rar3_lz.rs` reads them.
Two sets from two input trees still stand, and a fixture whose input tree is
not the one a test hashes against is a trap. **Not done yet**: deciding
which tree is canonical and regenerating the other side. This
generator's rows each carry their `inputs_sha256`, so its side is
self-identifying; the vectors-H five are not.

## 1. Running it

```sh
colima start -p rarkitfx --cpu 4 --memory 8 --disk 30 --runtime containerd
OLD_ENGINE=<path to the previous engine's rarfast> \
  ./generate.sh <package dir> ~/.cache/rarkit-fixwork
```

Needs reference `unrar` 7.23 on PATH, python3, and a colima profile of its
OWN (never borrow a bench profile: a bench box may be mid-round). The work directory must be
under `$HOME`, because colima mounts only that, and it is mounted at its
real absolute path, because anything else sends every relative lookup
somewhere other than where the fixtures are.

`--only <prefix>` runs one writer or one row; `--stage write|verify` splits
the two halves, which is what to use when only the verification changed.
Measured 18 Sep 2026 on an Apple Mac (M5 Max, under its usual load): a
full run is **17.6 s** once the container images are cached, and `--stage
verify` alone is **2.1 s**. The FIRST run on a box pays for three image
pulls and the dosbox image build on top of that, which is minutes rather
than seconds and is the only part of any run that touches the network.

## 2. What is here

| File | What |
|---|---|
| `generate.sh` | the only entry point |
| `fixtures.tsv` | **the declarative set**: one row per archive, six fields, comments in the header |
| `build.py` | the engine `generate.sh` drives: packages, containers, header walk, round-trip, manifest |
| `inputs.py` | the seeded input trees; the only source of every byte archived |
| `INPUTS.sha256` | the digest of every input file. A run whose inputs do not match this REFUSES |
| `packages.sha256` | the six packages' hashes, sizes and source URLs. Never fetched, never committed |
| `Dockerfile.dosbox` | debian plus dosbox: the three 16-bit DOS builds' sandbox |
| `MANIFEST.tsv` | **the output**: one row per fixture, 22 columns (section 4) |
| `REFUSED.tsv` | rows `fixtures.tsv` asks for that did not become fixtures, with the reason (section 6) |
| `archives/` | **the fixtures**: 109 files, 6.42 MB, committed (section 0) |
| `ARCHIVES.sha256` | the digest of all 109, including the continuation and `.rev` volumes `MANIFEST.tsv` carries no digest for. the project's fixtures check holds the corpus to it and can rewrite it |

## 3. The licence boundary this keeps

The rules this generator enforces are:

1. **No RARLAB binary or package is ever committed to any repository.** The
   six are supplied by whoever runs the generator, out of a cache directory
   OUTSIDE every repository. `packages.sha256` carries their hashes and
   source URLs so a missing one can be asked for; the script never fetches.
2. **A new download needs the owner's explicit yes first.** When a package is
   absent the run refuses with exit 2 and prints the filename, size, source
   URL and SHA-256 to ask about. It does not proceed with a partial set.
3. **No self-extracting fixture is ever made.** An SFX archive embeds
   RARLAB's executable stub, so committing one would break rule 1. There is
   no `-sfx` row in `fixtures.tsv` and there must never be one.
4. **The legacy builds are never disassembled, traced or looked inside.**
   The two DOS self-extractors are UNPACKED by `unrar` and never executed as
   programs; only the `RAR.EXE` inside runs, inside dosbox, inside a
   container started with `--network none` whose single mount is the work
   directory. Only the writers' OUTPUT files are read.
5. Still to do, unchanged here: buy one RAR licence, since
   a generator re-run for years is not a 40-day evaluation; and find a
   second independent copy of `RAR155.EXE` and `RAR1_402.EXE` to compare
   hashes against, both having come from third-party CD mirrors with no
   published checksum.

## 4. The manifest

One row per fixture. The columns, and what each is evidence of:

| Column | From |
|---|---|
| `id` | the `fixtures.tsv` row |
| `format` | our own reading of the headers (`build.py: walk`) |
| `writer`, `writer_pkg_sha256` | which genuine build wrote it, and which package that build came out of |
| `command` | the exact command line, as that writer's platform spells it |
| `archive`, `volumes`, `bytes`, `sha256` | the output |
| `inputs_sha256` | the digest of the whole `INPUTS.sha256` list, so a row states which input tree it was made from |
| `password` | empty, or the password the archive needs |
| `signature`, `unpack_versions`, `methods`, `flags` | our own reading of the headers |
| `unrar_detail`, `entries`, `dir_entries`, `encrypted_entries` | reference `unrar 7.23`'s reading |
| `unrar_7_23` | **the verdict that matters**: exit code, files extracted, files differing from the input |
| `old_engine` | the same three, from the old engine, with `DIFFERS` when they are not identical |
| `covers` | the format ground the row is here for |

Two readings, kept apart on purpose. The header columns are ours and are
the self-check that a row produced the format it was written for: a row
whose headers say something its writer cannot write is REFUSED. The entry
counts are the reference's, from `unrar lta`, so that one source fills them
for every format.

**`not walked` is a real value and is not a zero.** Our parser walks the
RAR 1.5-to-4.x block layout that the public technote describes. RAR 1.3/1.4
lays its blocks out differently, and working that out is spec F's subject,
not this generator's - so for the nine `d140` rows those columns say `not
walked` rather than reporting zero entries, which would be a green line
over nothing. The three `-hp` rows say `headers encrypted` for the same
reason: nothing past the main header can be read without decrypting, which
is spec K's subject.

**Every archive in `MANIFEST.tsv` round-trips under reference unrar 7.23**:
exit 0, and the SHA-256 of every extracted file equal to its input's. A row
that does not is left OUT of the manifest and put in `REFUSED.tsv`. A
fixture the reference refuses is not a fixture.

## 5. Determinism, and what is NOT promised

The INPUTS are byte-for-byte deterministic: `inputs.py` uses
`random.Random` with an integer seed and only `getrandbits`, `randint`,
`random` and `choice`, so the same bytes come out on every box and every
Python from 3.6 on, and every file's mtime is set to one fixed instant. A
run whose inputs do not reproduce `INPUTS.sha256` refuses rather than
writing archives nobody can compare against.

The ARCHIVES are not promised byte-identical across re-runs on different
boxes. They embed file times, the DOS builds round those to two seconds,
and dosbox's own version is in the loop. **The committed archives are the
fixtures; the script is their provenance.** That is the whole argument for
section 0's decision.

Section 0 measures how far the promise actually reaches on ONE box: three
runs from the same packages and the same inputs agreed on 73 of the 81
rows, and disagreed on 8 every time - the six salted `-p`/`-hp` rows of the
RAR 3.x and later writers, and rar 5.5.0's `-rr` and `-z` rows, which carry
the time of archiving. For those eight there is no re-run that produces the
committed bytes, on this machine or any other. Everything above about DIFFERENT
boxes is still untested: this project has only aarch64 Macs, and a second
architecture would be the way to find out. That is **still to do**, on an
x86-64 box.

## 6. What the corpus covers, and what it found

81 fixtures: 9 RAR 1.3/1.4, 10 RAR 1.5, 18 RAR 2.0, 41 RAR 2.9, and 3 whose
format cannot be named without the password because their headers are
encrypted. Across them: methods 0x30 to 0x35 (stored and all five
compression levels) on all three DOS writers; solid and non-solid; solid
groups by extension; multi-volume in both the old `.r00` and the new
`.partN.rar` naming; recovery volumes (`.rev`); protect sectors at the
default and the DOS maximum of 8; archive comments; file data encrypted in
the RAR 1.3, 1.5, 2.0 and 2.9 ciphers; encrypted headers; a 64 KB
dictionary; the text model forced; the RAR 2.0 multimedia codec; each of
the five RAR 3 filters forced and two chosen automatically; a nested
directory tree, an EMPTY directory, a zero-length member and a one-byte
member in every `IN` archive; and a long name and a non-ASCII name.

### Differences the old engine shows, recorded so they are not rediscovered

`old_engine` is the previous engine's `rarfast` **built 4 Sep 2026**
and not rebuilt for this. 60 of the 81 rows agree with the
reference exactly. The 21 that do not fall into two groups, and the row
`REFUSED.tsv` holds is a third difference of a different kind - it is the
WRITER's, not an engine's. All three, as `MANIFEST.tsv` and `REFUSED.tsv`
record them:

| Rows | Format | Reference `unrar` 7.23 | The old engine | What it is |
|---|---|---|---|---|
| `d140_vol` | RAR 1.3/1.4 | `rc=0 files=9 mismatch=0` | `rc=3 files=1` | **Every multi-volume set, in every format** (11 rows). The old engine extracts nothing or almost nothing from a genuine volume set and exits 3. Spec I recorded this class against rar 4.2.0 sets and exit 0; here it is every writer and both naming schemes, at exit 3, so the exit-code half of that finding depends on the set's shape. |
| `d155_vol` | RAR 1.5 | `rc=0 files=9 mismatch=0` | `rc=3 files=2 mismatch=2` | as above, and the RAR 1.5 defect below on top of it |
| `d250_vol`, `d250_vrr` | RAR 2.0 | `rc=0 files=9 mismatch=0` | `rc=3 files=1` | as above; `d250_vrr` is the recovery-volume row |
| `r393_vol`, `r393_voln`, `r393_rv`, `r420_vol`, `r420_voln`, `r420_rv`, `r550_vol`, `r550_voln` | RAR 2.9 | `rc=0 files=9 mismatch=0` | `rc=3 files=0` | as above, across `.r00` and `.partN.rar` naming and the `.rev` rows |
| `d155_m0`, `d155_m1`, `d155_m2`, `d155_m3`, `d155_m4`, `d155_m5`, `d155_sol`, `d155_pw`, `d155_cmt`, `d155_vol` | RAR 1.5 | `rc=0 files=9 mismatch=0` | `rc=0`, **`mismatch=2`** | **Every RAR 1.5 archive** (10 rows): two extracted files differ. The defect - a genuine DOS RAR 1.55 directory is marked by its DOS attribute alone, and an engine that tests the flags word extracts it as an empty FILE. The same rows print `Total errors: 3` with exit code 0. |
| `r550_uni` | would be RAR 2.9 | **`rc=9`, 8 of 9 members, `Illegal byte sequence`** | not reached | **Not a fixture**: it is in `REFUSED.tsv`, not `MANIFEST.tsv`. rar 5.5.0 forced back with `-ma4` writes the member `naam-met-accenten-eeu-n.txt` in a way reference unrar 7.23 will not read; rar 3.9.3 and rar 4.2.0 write the same name into a RAR 4 header and the reference reads it back. See the end of this section. |

**The RAR 1.5 rows are expected to go green when the second arm is
rebuilt**: the defect is fixed in builds of that engine later than this
binary. The volume rows are not; nothing has fixed those. Re-measuring
the `old_engine` column against a current build is **not done yet**.

The two groups again, at length:

1. **Every multi-volume set, in every format** (11 rows: `d140_vol`,
   `d155_vol`, `d250_vol`, `d250_vrr`, and both volume rows plus the
   recovery-volume row of each Linux writer). The old engine extracts
   nothing or almost nothing from a genuine volume set and exits 3. This is
   the class spec I recorded against rar 4.2.0 volume sets, here shown to
   be every writer and every naming scheme, not one build. Note the exit
   code: spec I recorded exit 0, and these sets give exit 3, so the exit-code
   half of that finding depends on the set's shape.

   **This was nearly missed, and the near-miss is worth keeping.** An
   earlier run of this generator used `-v100k`, at which the whole input
   tree fits in ONE volume at `-m5`: every Linux volume row then "passed",
   because it exercised no volume continuation at all. `build.py` now
   REFUSES a `-v` row that produced fewer than two volume files.

2. **Every RAR 1.5 archive** (10 rows): two extracted files differ. A
   genuine DOS RAR 1.55 directory is marked by
   its DOS attribute alone, and an engine that tests the flags word extracts
   it as an empty FILE. It is FIXED in builds of that engine later than
   this binary, so these rows are expected
   to go green when the arm is rebuilt. The same rows also show the second
   half of that defect: `Total errors: 3` printed with exit code 0.

### A new finding: rar 5.5.0 `-ma4` and non-ASCII member names

`REFUSED.tsv` has one row. `r550_uni` asks rar 5.5.0, forced to RAR 4 with
`-ma4`, to archive the input tree including a member named
`naam-met-accenten-eeu-n.txt` (with the accents). It writes the archive, but
reference unrar 7.23 lists only eight of the nine members and fails with
`Illegal byte sequence`, exit 9. The SAME name written by rar 3.9.3 and rar
4.2.0 into a RAR 4 header (`r393_x`, `r420_x`) is read back correctly by the
reference. So a modern build forced back to the old format does not write
that name the way the old builds did.

Left as a finding, not chased: it is the writer's behaviour, and rarkit's
readers are not asked to read something the reference refuses. What the
corpus keeps instead is `r550_x`, the same row without that one member, so
rar 5.5.0 still contributes its long-name and filter coverage.

## 7. Where the fixtures go, and what may read the generator

The archives and this tooling live in `rarkit`, under `fixtures/legacy/`:
the generator, the manifest, the record AND (section 0),
`archives/` itself.

This generator read the old engine's output and ran it as the second arm.
It therefore adds tooling to `rarkit` and nothing under `crates/`. Anyone
writing a reader may use the archives and `MANIFEST.tsv` freely - they are
format artifacts from RARLAB's own writers, which is the whole point -
but must not read `build.py`'s old-engine arm as a statement
about how any reader is built.
