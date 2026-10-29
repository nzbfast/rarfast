# A member of the older container whose name comes to nothing (8 Oct 2026)

The archives and answers behind SPEC-F 3.3.7, N10.
`../empty-name-probe.py --build DIR` writes the 41 archives kept here and
`cases.tsv` (each SHA-256 and the name field in hex); its docstring says
what the answers' columns mean. The answers are rar 7.23 and unrar 7.23
for macOS (SHA-256 `fd6c7db73c659a28` and `99720d63484b8db7`, first 16)
under LC_ALL=C and under en_US.UTF-8; the two programs agree on every
archive, and the two locales differ only in how `lb` prints one name
that is valid UTF-8. Nothing a program printed is kept but the names
`lb` listed, in hex.

Owed: the same archives on the Linux and Windows builds (what they make
of a name byte that is not UTF-8), and on the older genuine readers,
whose form this is.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
