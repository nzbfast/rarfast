# A member of the older container that declares fewer bytes than its stream holds (8 Oct 2026)

The answers behind SPEC-H1 3.8 B9, SPEC-F 3.6.3 item 4 and SPEC-J 3.8.

    ../h1-declared-short-probe.py --keep DIR r393_solid.rar r420_solid.rar r550_solid.rar \
        r420_f_audio.rar r420_f_delta.rar r420_f_x86.rar r420_m5.rar d250_sol.rar d155_sol.rar

with the archives of `fixtures/legacy/archives/`, in that order. The 576
altered archives are 40 MB and are NOT kept: the probe makes them again
from the tracked genuine ones, and `cases.tsv` holds each SHA-256. The
probe's docstring says what each column of an answers file means.

| File | Program | SHA-256 of the program, first 16 |
|---|---|---|
| `outcomes-unrar-7.23-macos-arm64.tsv` | unrar 7.23 for macOS | `99720d63484b8db7` |
| `outcomes-rar-7.23-macos-arm64.tsv` | rar 7.23 for macOS | `fd6c7db73c659a28` |

The two agree in every column of every arm. Nothing a program printed is
kept.

Owed: the same arms put to the older genuine readers (unrar 4.20 and
5.50) and to the x86-64 Linux builds of 7.23.
