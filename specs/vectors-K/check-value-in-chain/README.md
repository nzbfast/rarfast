# A refused password check value inside a solid RAR 5 chain (8 Oct 2026)

The archives and answers behind SPEC-K 3.7.3, "A refused member inside a
solid chain". `../check-value-in-chain-probe.py --build DIR` has genuine
rar 7.23 write the two base archives (password `PASS`) and makes the
arms; the salts are random, so the archives kept here ARE the vectors and
a second build gives other bytes (`cases.tsv` holds each SHA-256). Its
docstring says what the answers' columns mean. The answers are rar 7.23
and unrar 7.23 for macOS (SHA-256 `fd6c7db73c659a28` and
`99720d63484b8db7`, first 16), the same on every row. Nothing a program
printed is kept.

Owed: the x86-64 Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
