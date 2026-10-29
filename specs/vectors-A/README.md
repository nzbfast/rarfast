# Vectors and probe records for specification A

Two probes, both of 6 Oct 2026. Neither runs any rarkit code: the judge of
every question is reference unrar 7.23, and the decoder they hold is
written from SPEC-A's text in Python.

## 1. Every section

Files: `a_model.py`, `a_containers.py`, `a_edges.py`,
`a-all-sections-probe.py`, and the records in `a-all-sections/`.

`a_model.py` is a decoder and a stream writer made from SPEC-A sections 2
to 5. For every statement of sections 3 and 4 that could be read another
way it also holds a VARIANT: the same decoder with that one statement
replaced (an update left out, an old value used where a new one is stated,
an edge moved by one in each direction, a first value changed, a quantity
carried or reset at a member boundary). `VARIANTS` in that file lists all
212 with the section each guards.

    python3 a-all-sections-probe.py --search  OUT_DIR
    python3 a-all-sections-probe.py --judge   OUT_DIR --unrar /path/to/unrar
    python3 a-all-sections-probe.py --census  ../../fixtures [--variants]
    python3 a-all-sections-probe.py --edges   SCRATCH_DIR --unrar /path/to/unrar

- `--search` is seeded and rebuilds the 108 archives of `a-all-sections/`
  byte for byte (about five minutes). It plans members, writes each as
  packed bits, and keeps for every variant archives on which the variant
  and the stated reading give different bytes. Some plans put one quantity
  exactly on an edge; some use every codeword of every table.
- `--judge` puts each archive to the reference, the header carrying the
  CRC32 of the STATED bytes, then puts the same members to it again in the
  RAR 1.4 container. A statement is SHOWN when, on an archive where its
  variant differs, the reference reports every member OK and prints the
  stated bytes.
- `--census` decodes the genuine RAR 1.40 and RAR 1.55 archives of
  `fixtures/legacy/archives` (`d140_*`, `d155_*`) and of
  `fixtures/large-rar15/archives` with the stated model, checks every
  member against the checksum its header carries, and counts what those
  archives hold and what they never hold. With `--variants` it counts, for
  every variant, the genuine archives that variant fails to reproduce.
- `--edges` asks the questions that are not "which reading": which header
  flag makes a member solid, what a last match past the declared size
  does, whether anything after a member's last step is read, where
  decoding stops when the packed bytes run out, and what a copy from before
  the start of the output gives. It keeps nothing but its text.

`a-all-sections/` holds:

| File | What |
|---|---|
| `a_NNN.rar` | an archive the search kept (RAR 1.5 container, unpack version 15) |
| `a_NNN.want` | the bytes the stated reading gives for its members, in order |
| `streams.tsv` | for each archive: the plan that made it and the variants that differ on it |
| `search.txt` | the search's own summary |
| `judge-unrar-7.23-linux-x86-64.txt` | the reference's answers, x86-64 Linux |
| `judge-unrar-7.23-macos-arm64.txt` | the same under unrar 7.23 for macOS |
| `edges-unrar-7.23-linux-x86-64.txt`, `edges-unrar-7.23-macos-arm64.txt` | the answers to the edge questions |
| `census.txt` | the census of genuine archives, with the variants |

The archives double as decoder vectors: a decoder written from SPEC-A must
give `a_NNN.want` for `a_NNN.rar`, and the reference does.

## 2. The long match alone (the first probe)

`a47-long-match-results-probe.py` is the earlier observation behind
section 4.7: 30 variants, 33 streams. `--search DIR` plans members, writes
each as a packed stream, and keeps the streams on which a variant reading
of one result gives different bytes from the stated results. `--judge DIR
--unrar <path>` wraps each kept stream as a RAR 1.5 format member and
prints what the reference does with it and which variants that settles.

`a47-long-match-results/` holds the 33 streams the search kept
(`*.packed`), the bytes the stated results give for each (`*.want`), the
archives put to the reference (`*.rar`), which variants differ on which
stream (`streams.tsv`), the search's own summary (`search.txt`) and the
answers of unrar 7.23 for x86-64 Linux. The search is seeded and rebuilds
the same streams. Probe 1 above repeats every one of its variants and adds
the other side of each edge.

## 3. The seven codes in two printed forms

`codes-4.2-forms.py` holds SPEC-A table 4.2 (counts by length) and table
4.2.1 (length and last value, the form rarkit holds), shows that each
gives the other and that every code fills its code space exactly, and
prints the first and last codeword of every used length, which are the
check vectors of 4.2. It reads no archive and runs no program:

    python3 codes-4.2-forms.py

It ends with the line `OK` and exit 0.
