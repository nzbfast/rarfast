# Damaged headers and a lost tail in RAR 5, with and without a quick open record (8 Oct 2026)

The bases and answers behind SPEC-F 3.2.2 R5, 3.2.8, 3.2.9.1 and 4.6.
`../damaged-walk-probe.py --build DIR` has genuine rar 7.23 write the
four bases kept here (a second run gives other bytes, so these ARE the
vectors) and lists every arm's SHA-256 in `cases.tsv`; `--judge` makes
each arm from its base in memory. The probe's docstring names the arms
and the answers' columns. The answers are rar 7.23 and unrar 7.23 for
macOS (SHA-256 `fd6c7db73c659a28` and `99720d63484b8db7`, first 16), the
same on all 72 arms. Nothing a program printed is kept: two columns say
how many lines named a corrupt header and whether the program said the
archive ended.

Owed: the x86-64 Linux builds, and the same arms on a volume set.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
