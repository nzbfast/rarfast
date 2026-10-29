# Vectors for clean-room specification F (containers and the read path)

Companion to `specs/SPEC-F-rarkit-containers.md`, section 5.

- `archives/` the 30 archives. The `f*` ones were written here by reference
  `rar` 7.23 and are rebuilt by `generate.sh`; `f13` to `f16` are byte
  edits of `f01` and `f03` that the same script makes, and `f19` is one
  that `htime-record.py` makes. The four legacy
  archives (`D140_M5.RAR`, `D155_M5.RAR`, `D250_M5.RAR`, `r420_m5.rar`,
  `r420_hp.rar`) were written by genuine RARLAB legacy builds under the
  recipe in `fixtures/legacy/README.md` and
  are copied in; `generate.sh` does not rebuild them.
- `expected/<archive>.txt` the full block walk of each archive. A
  reader's own walk, printed in the format of specification F section
  5.2, must reproduce these files. They are the acceptance test for every
  header shape the package claims to read.
- `MANIFEST.tsv` per archive: size, SHA-256, writer, command, what it pins.
- `SHA256SUMS` over `archives/`.
- `htime-record.py` builds `f17` to `f19` and re-runs the read-side probes
  behind SPEC-F 3.2.6.1 (the RAR 5 file-header extra TIME record).
- `packed-bound.py` re-runs the probes behind SPEC-A 6.1: what reference
  `unrar` 7.23 does with a member whose packed data runs out before its
  declared unpacked size, in all four generations.
- `rar7-dictionary-field.py` reads and rewrites the RAR 5 compression
  information field, the probe behind SPEC-F 3.2.6.3 (the RAR 7 dictionary
  size and compression version 1). It builds no archive of its own; its
  docstring has the rar commands.
- `rar4-name-run-probe.py` hand-builds 33 RAR 4 archives (seven of them
  one per selector, the order of units, an unfinished selector byte, a
  surrogate pair and a 52,000 unit name; the records in `rar4-name-run/`
  are unrar 7.23's answers on x86-64 Linux and, from its `--census` arm,
  the census of this repository's genuine archives) whose member
  name is a two part Unicode name of an unusual shape and prints what
  reference `unrar` 7.23 lists for each, the probe behind SPEC-F 3.3.7
  (no ceiling on a name, runs that copy from the
  name field, a zero unit ending the name). It needs `unrar` only and
  commits no archive.

- `evidence-06oct/` holds the evidence of 6 Oct 2026 behind SPEC-F
  sections 3.1 to 3.5: censuses of every genuine archive kept in this
  repository, 54 RAR 5 archives freshly written by reference `rar`, and
  about 380 constructed archives with the reference's recorded answers.
  Its own README says how to run each part again.

No RARLAB binary or package is committed here, and none is fetched by
anything in this directory.

## Two measurements of 11 Oct 2026

- `named-version-edges-probe.py`, `named-version-edges/`: which decoder
  the reference gives the unpack versions 13, 14 and 26 of the older
  container (SPEC-F 3.3.5): genuine archives with every compressed
  member's version rewritten.
- `older-link-target-length-probe.py`, `older-link-target-length/`: how
  long a symbolic link's target the reference takes from a member of the
  older container (SPEC-F 3.3.12): one constructed link at 25 lengths.

## One measurement of 13 Oct 2026

- `clear-stored-order-probe.py`, `clear-stored-order/`: what an
  observer sees of a clear stored member's checksum and of the order
  its bytes reach a file and a pipe (SPEC-F 3.7.7 S14): a damaged
  member, a cut archive, a reader that closes the pipe, an interrupt, a
  file size limit, and a file read while it grows; rar and unrar 7.23,
  the encrypted twin beside it. No archive is kept.
