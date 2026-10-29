# A member that declares more bytes than its packed data yields (8 Oct 2026)

The answers behind SPEC-F 4.2, "A member that ends short".

    ../declared-long-probe.py --keep DIR archives/f01_stored.rar archives/f03_m3.rar \
        archives/f04_solid.rar archives/f05_blake.rar r420_m0.rar r420_m3.rar r420_m5.rar \
        r393_solid.rar r420_solid.rar d250_m3.rar d155_m3.rar d250_sol.rar

the last eight from `fixtures/legacy/archives/`. `cases.tsv` holds the
SHA-256 of all 154 altered archives; those under 4 KiB are kept here and
the probe makes the rest again from the tracked genuine ones. Its
docstring says what each column of an answers file means. The answers
are rar 7.23 and unrar 7.23 for macOS (SHA-256 `fd6c7db73c659a28` and
`99720d63484b8db7`, first 16), the same in every arm. Nothing a program
printed is kept.

Owed: the older genuine readers and the x86-64 Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
