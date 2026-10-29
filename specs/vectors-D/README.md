# Vectors and probe records for specification D

Read the specification first; this file only lists what is here and how
to run it again. Probes of 6 Oct 2026 behind sections 2.2 and 3.2.1 of the
same specification are kept under `../vectors-H/` (`d2-member-end-probe.py`,
`d3-prefix-table-shapes-probe.py` and their directories) and are described
in that directory's README.

Nothing here opens the source of any RAR reader. The scripts are scratch
checkers written from the specifications' text; they are not a model for
an implementation. No RARLAB binary is in this directory.

## The RAR 2.0 multimedia predictor (6 Oct 2026)

`d1-predictor-probe.py` is the observation behind spec D part 1. It holds
a reader of multimedia blocks and of LZ blocks of literals, and 55 VARIANT
readings, each the same reader with one statement of part 1 read another
way.

    python3 d1-predictor-probe.py --search WORK
    python3 d1-predictor-probe.py --judge WORK --unrar /path/to/unrar
    python3 d1-predictor-probe.py --versions WORK --unrar /path/to/unrar
    python3 d1-predictor-probe.py --vectors

`--search` is seeded and rebuilds the same 35 streams byte for byte: for
every variant it keeps streams on which the variant's bytes differ from
the stated reading's. `--judge` extracts each with the reference and says
whether every member came out as the stated reading says; where one does
not, it prints which variants give the reference's bytes instead.
`--versions` rewrites the unpack version byte of one stream to each value
from 15 to 29 and prints which the reference tests OK. `--vectors` prints
the stated reading's bytes for the fixed vectors of section 1.3.1.

`d1-predictor/` holds:

| File | What |
|---|---|
| `*.rar` | the 35 streams, each an archive of unpack version 20 members whose headers carry the CRC32 of the stated reading's bytes |
| `*.want` | the stated reading's bytes for each, every member joined |
| `streams.tsv` | per stream: member sizes, and the variants that differ on it |
| `search.txt` | per variant: how many kept streams it differs on; which ends of the weight range the kept streams reach |
| `unrar-7.23-linux-x86-64.txt`, `unrar-7.23-macos.txt` | `--judge` under each reference: all 35 streams as stated, every variant not followed |
| `versions-unrar-7.23-*.txt` | `--versions` under each reference |
| `vectors.txt` | `--vectors` |
| `genuine-census.txt` | the census below |

`d1-genuine-census.py` reads the multimedia blocks of genuine archives
with the same reader and prints what each member holds and whether its
bytes have the CRC32 its own header carries; with `--variants` it also
says which variant readings fail that CRC32. From the repository's root:

    python3 specs/vectors-D/d1-genuine-census.py --variants \
        fixtures/legacy/archives/d250_mm.rar

`d250_mm.rar` is the one archive of the seventeen written by DOS RAR 2.50
(`fixtures/legacy/archives/d250_*.rar`, `specs/vectors-H/legacy/D250_*.RAR`)
that holds multimedia blocks.

## A table read in a member's tail that does not complete (6 Oct 2026)

`d2-incomplete-tail-probe.py` is the observation behind spec D section
2.2's statement O7 and the note in section 2.1 on a member whose packed
data runs out. It imports `../vectors-H/d2-member-end-probe.py` and
`d1-predictor-probe.py`.

    python3 d2-incomplete-tail-probe.py --unrar /path/to/unrar --keep WORK

It builds 80 archives of two members in one solid chain whose first
member's tail holds a terminator and a header cut short, computes the
second member's bytes under several readings of what the cut read leaves,
and prints which reading the reference's bytes are; then 8 archives whose
first member is declared at more bytes than its packed data codes.
`d2-incomplete-tail/` holds the 88 archives (the probe rebuilds them byte
for byte) and the reference's answers on both systems.

## A RAR 3 code within 15 bits of the end of the data (6 Oct 2026)

`d3-end-of-data-probe.py` is the observation behind spec D section 3.2.4.
It imports `../vectors-H/d3-prefix-table-shapes-probe.py` and, for the
census, a RAR 3 reader written from SPEC-H1's text that is not kept at
the tip.

    python3 d3-end-of-data-probe.py --unrar /path/to/unrar --keep WORK
    python3 d3-end-of-data-probe.py --census <RAR 4 family archives>

`--unrar` builds 48 archives of one member whose packed data ends right
after, or inside, its last codeword, and prints whether the reference
reports each OK. `--census` prints, per member of genuine archives, how
few bits were left when a symbol was read. `d3-end-of-data/` holds the 48
archives, the reference's answers on both systems, and the census of the
RAR 4 family archives under `specs/vectors-F`, `-G`, `-H`, `-I` and `-J`
(the constructed archives of `vectors-H/d2-member-end` and
`vectors-H/d3-prefix-table-shapes` left out).

The census part of `d3-end-of-data/` was made at the private commit be5c09422 by a tool not kept at the tip (that RAR 3 reader). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
