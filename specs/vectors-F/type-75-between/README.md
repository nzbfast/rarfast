# A block of type 0x75 standing between blocks (8 Oct 2026)

The archives and answers behind SPEC-F 3.3.3 B2.
`../type-75-between-probe.py --build DIR` writes the 35 archives kept
here (26 of 8 Oct; 9 added on 9 Oct 2026, `size-field-*` and
`40-bytes-bad-crc`, for rule 2 as restated that day) and `cases.tsv` (each SHA-256 and what the arm is); its docstring
says what the answers' columns mean. `outcomes-*.tsv` are rar 7.23 and
unrar 7.23 for macOS (SHA-256 `fd6c7db73c659a28` and `99720d63484b8db7`,
first 16), the same on every archive. Nothing a program printed is kept
but the member names `lb` listed.

Owed: the older genuine readers (the form is theirs) and the x86-64
Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
