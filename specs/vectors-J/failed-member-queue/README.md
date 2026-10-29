# Filters waiting when a member of a RAR 3 solid chain fails (8 Oct 2026)

The answers behind SPEC-J 3.8, "A member that ends with filters
waiting".

    ../failed-member-queue-probe.py --keep DIR r420_f_mixed.rar r420_solid.rar r393_solid.rar

with the archives of `fixtures/legacy/archives/`. The 95 cut archives are
not kept: the probe makes them again from the tracked genuine ones and
`cases.tsv` holds each SHA-256. Its docstring says what the marks mean.
The answers are rar 7.23 and unrar 7.23 for macOS (SHA-256
`fd6c7db73c659a28` and `99720d63484b8db7`, first 16), the same in every
arm. Nothing a program printed is kept.

Owed: the older genuine readers (the form is theirs) and the x86-64
Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
