# A RAR 5 filter span past the declared size (8 Oct 2026)

The archives and answers behind SPEC-H2 3.1, "a kept filter record whose
span is not wholly inside the member's declared output".

`../h2-span-past-declared-probe.py --keep DIR` writes the 280 archives
kept here and `cases.tsv` (each SHA-256); it rebuilds them byte for byte.
Its docstring says what each archive is and what each column of an
answers file means. The container is a genuine rar 7.23 header rewritten;
the blocks are written from SPEC-H2.

| File | Program | SHA-256 of the program, first 16 |
|---|---|---|
| `outcomes-unrar-7.23-macos-arm64.tsv` | unrar 7.23 for macOS | `99720d63484b8db7` |
| `outcomes-rar-7.23-macos-arm64.tsv` | rar 7.23 for macOS | `fd6c7db73c659a28` |

The two agree in every column of every archive. Nothing a program printed
is kept: a verdict is derived from whether a member's name stands on a
line that ends in OK or on one that says error.

Owed: the same archives put to the x86-64 Linux builds.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
