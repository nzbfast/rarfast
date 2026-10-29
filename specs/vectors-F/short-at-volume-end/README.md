# A member that ends short in a volume of a set (9 Oct 2026)

The answers behind SPEC-F 4.2, "A member that ends short", rule 6.

`../short-at-volume-end-probe.py --build DIR` writes 33 arms (three
containers: RAR 5, and the older container with unpack versions 29 and
20) and `cases.tsv`, each file's SHA-256. The sets are not kept: the
builder needs no genuine program and writes the same bytes each run, and
`cases.tsv` here is what it wrote. Its docstring says what each arm is
and what each column of an answers file means.

| File | Program | SHA-256 of the program, first 16 |
|---|---|---|
| `outcomes-unrar-7.23-macos-arm64.tsv` | unrar 7.23 for macOS | `99720d63484b8db7` |
| `outcomes-rar-7.23-macos-arm64.tsv` | rar 7.23 for macOS | `fd6c7db73c659a28` |
| `outcomes-unrar-7.23-linux-x86-64.tsv` | unrar 7.23 for x86-64 Linux | `926d3a00775ed96a` |
| `outcomes-rar-7.23-linux-x86-64.tsv` | rar 7.23 for x86-64 Linux | `56c3c4fd46faa7a9` |

The four agree in every column of every arm. The older genuine readers
are owed (`../../EVIDENCE-PASS-STATE.md`). Nothing a program printed is
kept: the marks are derived.
