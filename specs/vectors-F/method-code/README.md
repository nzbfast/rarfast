# RAR 5 method values 6 and 7 in a solid chain (8 Oct 2026)

The archives and answers behind SPEC-F 3.2.6, "Method values 6 and 7 are
compressed". `../method-code-probe.py --build DIR` has genuine rar 7.23
write `base.rar` and makes the 60 arms; rar's output is not the same
bytes on a second run, so the archives kept here ARE the vectors
(`cases.tsv` holds each SHA-256 and the altered member's sizes). Its
docstring says what the answers' columns mean. The answers are rar 7.23
and unrar 7.23 for macOS (SHA-256 `fd6c7db73c659a28` and
`99720d63484b8db7`, first 16), the same on every arm. Nothing a program
printed is kept.

Owed: the x86-64 Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
