# vectors-G: test vectors for SPEC-G (the RAR 5 and RAR 4 writers)

Read `specs/SPEC-G-rarkit-writers.md` section 5 first; this
file only lists what is here. No RARLAB binary is in this directory, and
none is committed anywhere in this repository.

| File | What |
|---|---|
| `refmodel.py` | an executable statement of SPEC-G section 3.6: builds a RAR 5 stored archive in the reference layout from a member list |
| `refcheck.py` | builds the same members with `rar` 7.23 and compares byte for byte, over 30 shapes |
| `refcheck.txt` | its output on 18 Sep 2026: 24 shapes, 24 matches, 0 differences |
| `widthprobe.py`, `widths.tsv` | the size-field width rule of 3.6.4, bisected at all four crossings against the real binary, asserted over nineteen sizes |
| `archives/` | 23 archives: ten by `rar` 7.23, thirteen by genuine RARLAB `rar` 4.20 in a network-less container (the two encrypted split sets `r4_pwvol` and `r4_pwvolc` are for SPEC-G 3.10.2) |
| `MANIFEST.tsv` | per archive: size, SHA-256, writer, exact command line |
| `dumps/` | a block-by-block dump of every archive, from the two parsers below |
| `r5dump.py`, `r4dump.py` | block parsers for the two families; the tools to reach for when a differential test disagrees |
| `inputs.py`, `inputs.sha256` | the seeded input tree every archive was written from, and its hashes |
| `mk-r4.sh` | the command lines the RAR 4.20 build ran, inside the container |
| `verify-unrar.txt` | reference `unrar` 7.23 accepting all 23 archives |

## Probes and records of 6 Oct 2026

| File | What |
|---|---|
| `g5-census-probe.py` | `build` runs the reference rar over 60 switch combinations on a seeded tree; `census` parses every archive with a parser written from the specification and the public technote, and prints the tallies sections 3.2 to 3.4 and 3.9 to 3.12 quote |
| `g5-census/cases.tsv` | every command line, its exit status and output (rar 7.23 for x86-64 Linux) |
| `g5-census/census.txt` | the census |
| `g5-census/inputs.sha256` | the seeded tree's hashes |
| `g5-alter-probe.py` | takes archives of the census, changes one thing in each of 93 arms, and asks `unrar t`, `rar t`, `unrar lb` and `unrar lt` |
| `g5-solid-stored-history-probe.sh`, `g5-census/solid-stored-history.txt` | whether a member stored inside a solid archive enters the history (section 3.9), and rar 7.23's answer |
| `g5-census/refcheck-linux.txt`, `g5-census/widths-linux.tsv` | `refcheck.py` (30 shapes) and `widthprobe.py` run again under rar 7.23 for x86-64 Linux |
| `g5-locator-width-probe.py`, `g5-locator-width-bisect.py`, `g5-census/locator-width*.txt` | the locator's reserved width (section 3.6.3): the lines that show a simpler rule wrong, and the bisection that measured the rule |
| `g5-rewrite-probe.py`, `g5-census/rewrite.txt` | what rar writes into member headers when it rewrites an archive (`k`, `c`, `d`), section 3.6.5 |
| `g4-kept-census.py`, `g4-kept-census.txt` | every block of the 22 kept rar 4.20 archive files, read from the bytes (section 3.14) |
| `g5-alter/answers.tsv` | their answers (rar and unrar 7.23 for x86-64 Linux) |
| `g5-repair-probe.py`, `g5-repair/answers.tsv` | what `rar r` needs of the recovery flag, the locator and the percentage record (52 rows), and what `rar rc` makes of the same changes (8 rows); section 3.11 |
| `g4-alter-probe.py`, `g4-alter/answers.tsv`, `g4-alter/answers-macos.tsv` | 69 arms: a kept rar 4.20 archive with one thing changed, put to rar and unrar 7.23 for x86-64 Linux and again for macOS arm64, with the same answers; sections 3.14.4, 3.14.8, 3.14.9 and 3.14.10 |
| `g5-store-verdict-probe.sh`, `g5-census/store-verdict.txt` | whether rar 7.23 stores a member that will not compress, non-solid, solid and under `-ms`; section 3.8.3 |
| `g5-census/solid-order-and-default-fit-linux.txt` | `solid-order-and-default-fit.sh` run under rar 7.23 for x86-64 Linux; sections 3.8.1 and 3.9.1 |
| `filter-estimate-price.py` | the price of a window as section 3.8.2 states rarkit's rule for the detector's estimate; with no argument it prints that section's hand vectors |
| `g5-census/filter-types-elf-linux.txt` | `rar5-filter-types.py` on archives of three ELF x86-64 files; section 3.8.2 |

The run of 19 Sep 2026 that the header of `rar4-time-fraction.py` names,
for one and two fraction bytes, is NOT reproduced by the arms
`mtime-fraction-*` of `g4-alter-probe.py` on either system, and SPEC-G
3.14.4 follows those arms.

    python3 g5-repair-probe.py run D --rar /path/to/rar --unrar /path/to/unrar
    python3 g4-alter-probe.py run D --rar /path/to/rar --unrar /path/to/unrar

To run them again (about a minute; 20 MB of scratch, none of it kept here):

    python3 g5-census-probe.py build D --rar /path/to/rar
    python3 g5-census-probe.py census D > D/census.txt
    python3 g5-alter-probe.py run D --rar /path/to/rar --unrar /path/to/unrar

Encrypted archives draw fresh salts, and a recovery record carries a tag
that changes from run to run, so those archives differ between runs; the
tallies do not.

## Rebuilding

    python3 inputs.py in            # rewrites the seeded tree; compare with inputs.sha256
    python3 refcheck.py             # needs `rar` 7.23 on PATH
    python3 widthprobe.py           # needs `rar`; writes files up to 16 MiB in a temp dir
    python3 r5dump.py archives/r5_store.rar

The RAR 4 archives need a genuine RARLAB `rar` 4.x binary, which is not
committed. `fixtures/legacy/README.md` says
where the package comes from and how it is run; `mk-r4.sh` is the script
that ran inside the container, with the worktree mounted at its real
absolute path under `$HOME` (both conditions matter).

## Item FUZZ-08OCT-5 (9 Oct 2026)

`solid-order-as-given.sh` puts the item's three solid shapes to a genuine
rar and prints the order listed; `g5-census/solid-order-as-given-macos.txt`
is rar and unrar 7.23 for macOS. SPEC-G 3.9.1.

`g4-small-fragment-probe.py` cuts the data of members genuine rar 3.93,
4.20 and 5.50 wrote into volume pieces of chosen lengths and asks the
genuine readers to test each set. `g4-small-fragment/` holds
`answers-7.23-macos-arm64.tsv` (108 arms, unrar and rar 7.23) and
`survey-unrar-7.23-macos-arm64.tsv` (30 members, every piece length from 1
to 40). `g5-small-fragment-probe.py` is its RAR 5 twin over the members of
`../vectors-H/archives/`; `rar5-survey-unrar-7.23-macos-arm64.tsv` is its
answer (no member fails at any piece length). No archive is kept: the
probes rebuild each set byte for byte from archives this repository holds. SPEC-G 3.10.1, "the least piece of a
packed member in the RAR 4 family".


9 Oct 2026: `g4-small-fragment/*-linux-x86-64.tsv` and
`g5-census/solid-order-as-given-linux.txt` are the same probes under rar
and unrar 7.23 for x86-64 Linux; they agree with the macOS answers in
every column. The older genuine readers and writers are owed
(`../EVIDENCE-PASS-STATE.md`).

`g5-census/filter-types-elf-linux.txt` and the two `g4-small-fragment/rar5-survey-unrar-7.23-*.tsv` tables were made at the private commit be5c09422 by a tool not kept at the tip (a RAR 5 reader written from SPEC-H2's text, which their scripts load). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
