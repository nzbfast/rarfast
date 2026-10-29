# vectors-H: test vectors for SPEC-H1, H2 and H3 (the LZ codecs)

Read the specifications first; this file only lists what is here.

| Path | What |
|---|---|
| `archives/h5_*.rar` | 16 RAR 5 archives written by reference `rar` 7.23 from the seeded inputs. 21 members between them, 18 of them compressed (the rows of `CHECK-rar5.tsv`) and 3 stored. Each file header stores a name, a size, a modification time, a mode and a checksum, and no owner record. |
| `legacy/*.rar` | 5 archives written by RARLAB's own legacy builds through the recipe in `fixtures/legacy/README.md`: `D250_M0.RAR` and `D250_M5.RAR` by DOS RAR 2.50 (unpack version 20, spec H3 part A), `r393_m5.rar` by rar 3.9.3, `r420_m5.rar` by rar 4.2.0 and `r550ma4_m5.rar` by rar 5.5.0 `-ma4` (unpack version 29, spec H1). No RARLAB binary is in this directory. |
| `inputs.py`, `inputs.sha256` | the seeded generator for the RAR 5 inputs and the hashes every extracted file must match. Deterministic: one linear congruential generator, no system entropy, no dependency. |
| `mk-rar5.sh` | the command lines that rewrite `archives/` with a reference `rar` the caller supplies. |
| `h5-owner-record-diff.py` | a block by block comparison of two copies of the set. It was written when the archives were rewritten on 3 Oct 2026 without the owner record the first set carried (the writer reads `-ow-` as `-ow`): for all 16 it found that record, and the lengths and checksums the format ties to it, the only difference, and each member unpacks to the same bytes. |
| `CHECK-rar5.tsv` | a RAR 5 reader written from SPEC-H2's text, run over `archives/`: every one of the 18 members reproduced byte for byte, each SHA-256 equal to its seeded input's. The table was made at the private commit be5c09422 by a tool not kept at the tip. |
| `CHECK-rar3.tsv` | a RAR 3 reader written from SPEC-H1's text, run over `legacy/` and `../vectors-J/archives/`: every filter free member reproduced, the rest with their filter records framed. The one `FAIL` row is the checker's limit and is explained in SPEC-H1 section 5.1. The table was made at the private commit be5c09422 by a tool not kept at the tip. |
| `h3-incomplete-table.py`, `archives/h3_*_table.rar` | the probe that settles SPEC-H3 6.3 requirement 1 by OBSERVATION: two RAR 5 members differing only in whether the main alphabet's Kraft sum is one or a half, put to reference `unrar` and to `7zz`. It carries its own control and prints which tools on the box can judge at all. The two archives are what `--keep archives` wrote. |
| `h2-zero-byte-failing-symbol-probe.py` | the probe behind SPEC-H2 3.1's rule for a symbol that fails inside a block owned by a member that declares zero bytes: 57 arms put to reference `unrar`, built on `h2-member-end-surplus-probe.py`. It needs `rar` and `unrar` on the path and commits no archive. |
| `h1-ppm-join/` | 105 constructed RAR 3 archives that put a PPM block header in a member of zero bytes, in an LZ member's packed data after its declared size, and after a PPM member's end of block past its size; the probe, and the answers of reference `unrar` 7.23 for x86-64 Linux and for macOS. Its own README says how to make them again. SPEC-H1 3.8 (B4, B5) and SPEC-I 3.3 (E2, E7). |
| `h3-class-reading-probe.py`, `h3-class-reading/` | the six heads SPEC-H3 8.1 'LEVEL 5 BY CLASS' states readings for: six files of 1,048,576 bytes whose every byte the probe drew from the system's entropy source, and `readings.tsv`, what the section's words read on each (sum, stops, reading, long matches, class) with the figures under one excluded wording. The reading is rarkit's own rule: the probe calls no program. Run with no argument it checks the files against the table; `--draw` makes six NEW files and a new table, and the section's figures then change with them. |
| `h3-one-symbol-genuine-probe.py`, `h3-one-symbol-genuine/` | what genuine rar WRITES when the blocks under a table set send exactly one symbol of an alphabet (SPEC-H3 6.3 item 1): rar packs 21 simple inputs at five levels and the lengths of its tables are read back with the RAR 5 checker (not kept at the tip). 145 such table sets, each with two lengths of 1: the symbol sent and symbol 0, or symbol 1 when symbol 0 is the one sent. |
| `ladders.tsv` | every slot of every length and distance ladder in all three generations, generated from the specifications' own rules. |
| `distance-slot-edges.tsv` | two RAR 5 distance slots no ladder row places, each with what SPEC-H2 3.5 says the match answers: slots 66 to 79 under algorithm version 1 (32 to 38 extra bits) are read and give zero bytes (`zeros`); slot 64 under algorithm version 0, one past that version's alphabet of 64, is `DistanceSlot`, and no stream names it through the distance code. A row gives the slots it covers inclusive, the extra bits the pair rule would give them (`-` where the slot is past its alphabet and none are read), the answer and the section that decides it. No byte is copied from the window in either case. Written from the specification's text alone; `ladders.tsv` is unchanged. |

## Reproducing

    python3 inputs.py /path/to/work/IN > /path/to/work/inputs.sha256
    diff /path/to/work/inputs.sha256 inputs.sha256
    sh mk-rar5.sh /path/to/work/IN archives rar
    python3 h3-incomplete-table.py

The legacy archives are not regenerated by anything here: they come from the
5.0b recipe, which needs the RARLAB packages that recipe names and a
network less container. They are committed for the reason SPEC-H1 question 5
and SPEC-H3 question 1 give: nothing else in the repository exercises these
two codecs against the output of a genuine writer.

## The two checkers are not here

The two tables `CHECK-rar5.tsv` and `CHECK-rar3.tsv` were made by scratch
checkers written from the specifications: no model for the
implementation, not fast, no encryption and no volumes, and the RAR 3
one with no PPM model at all. Neither checker is kept at the tip (both
stand in the private history at commit be5c09422), and neither is
written again: from now a table is checked by rarkit's shipped reader
against the genuine archives.

## RAR 3 prefix table shapes (6 Oct 2026)

`d3-prefix-table-shapes-probe.py` is the observation behind spec D section
3.2.1. With `--unrar <path>` it builds 18 RAR 4 family archives, each one
member whose LZ block has chosen code lengths and data bits (complete,
incomplete, oversubscribed and all zero lists, on the main, distance and
level alphabets), and reports whether the reference tests the member OK and
prints the predicted bytes. With `--census <archives>` it decodes genuine
archives with the RAR 3 checker (not kept at the tip) and prints the class and code lengths of every
table read. `d3-prefix-table-shapes/` holds the 18 archives, the answers of
unrar 7.23 for x86-64 Linux, and the census output. None of it is pinned in
a checksum file; the archives are rebuilt byte for byte by the probe.

## The RAR 5 block header (6 Oct 2026)

`h2-block-header-probe.py` is the observation behind spec H2 section 3.2.
`--make DIR` has reference rar write ten archives from generated inputs;
`--census` walks the block chain of every compressed member of the
archives given, decoding no symbol, and prints what each header field
holds; `--probe` builds 20 members with one header field altered each and
prints what reference unrar does. `h2-block-header/` holds the 20 probe
archives, unrar 7.23's answers on x86-64 Linux, the census of the ten
generated archives (not committed; `--make` rebuilds their inputs, and rar
stamps times into its output) and the census of `archives/h5_*.rar`.

## The end of a RAR 2.0 member (6 Oct 2026)

`d2-member-end-probe.py` is the observation behind spec D section 2.2.
`--unrar <path>` builds 80 archives of two members in one solid chain,
unpack version 20, each with a chosen tail after member 1's last symbol,
and prints which tables the reference decoded member 2 under. `--census`
decodes genuine archives' LZ members with a RAR 2.0 reader written from
SPEC-H3's text (not kept at the tip; private commit be5c09422) and prints what
each member's packed data holds past its last symbol. `d2-member-end/`
holds the 80 archives, unrar 7.23's answers on x86-64 Linux and the census
of the DOS RAR 2.50 archives.

## RAR 5 filter records waiting at once (6 Oct 2026)

`h2-pending-filters-probe.py` is the observation behind spec H2 section
4.2's bound on waiting filter records. `--probe` builds members in which N
delta records are read before the first span begins, for a ladder of N up
to 300,000, and prints how many of the N spans reference unrar transformed.
`--make DIR` has reference rar pack the executables of the system it runs
on and a generated sound file; `--census` prints the most records waiting
at once in each member, through the RAR 5 checker (not kept at the tip). `h2-pending-filters/` holds unrar
7.23's answers on x86-64 Linux, the census of what rar 7.23 wrote there,
and eight of the probe's archives (N of 1, 100, 8,192 and 8,193, both
shapes); the probe rebuilds the rest.

## A RAR 5 filter record of type 4 to 7 (9 Oct 2026)

`h2-unknown-type-record-probe.py` is the observation behind spec H2
section 3.6's rule for a filter record whose type field is 4 or above
(bug sweep item READER-08OCT-1): eighteen shapes of one member in a solid
stream of three, at seven declared sizes and three checksum fields, put
to genuine unrar and rar. `h2-unknown-type-record/` holds the 378
archives, the answers, and its own README.

`h2-far-distance-probe.py` is the measurement behind spec H2 section
3.5.1 (11 Oct 2026): what genuine unrar and rar do with a member that
holds one fresh match at a far distance slot after 300 bytes. It builds
its members with the member writer of `h2-symbols-probe.py` (no reader
is used: the genuine programs are the judge) and says in its first
comment what a row holds. `h2-far-distance/` holds the 85 archives,
their manifest and two tables of 170 rows, macOS (arm64) and Windows
(x64).

**Tables made through a tool that is not kept.** `CHECK-rar5.tsv`, `CHECK-rar3.tsv` and the kept tables of `h2-block-header/`, `h2-pending-filters/`, `d3-prefix-table-shapes/` and `d2-member-end/` (their census parts) were made at the private commit be5c09422 by a tool not kept at the tip: a reader written from the specification's own text. Their values are forced by the genuine archives and stand. No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
