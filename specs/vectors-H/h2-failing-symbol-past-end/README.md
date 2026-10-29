# A symbol that fails after the declared size of a RAR 5 member (8 Oct 2026)

The archives and answers behind SPEC-H2 3.1, "a symbol that fails past
the declared end". `../h2-failing-symbol-past-end-probe.py --keep DIR`
writes the 228 archives kept here and `cases.tsv`; its docstring says
what they hold and what the answers' columns mean. The answers are rar
7.23 and unrar 7.23 for macOS (SHA-256 `fd6c7db73c659a28` and
`99720d63484b8db7`, first 16), the same in every arm. Nothing a program
printed is kept.

Where C reads FAIL beside a reading other than ALL, that is the probe's
own artefact: C's checksum field is the ALL reading's, so a C that came
out as another reading fails it, and the reading named is the fact.

Owed: the x86-64 Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
