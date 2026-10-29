# older-link-target-length: how long a link's target the reference takes

For SPEC-F 3.3.12. `unrar-7.23-macos-arm64.tsv` is the output of
`../older-link-target-length-probe.py` with unrar 7.23 for macOS arm64
on 11 Oct 2026: one constructed symbolic link member of the older
container at 25 target lengths, put to `unrar lt` and `unrar x`. The
probe's first comment says what a row holds. Nothing is random and no
archive is kept.

    python3 ../older-link-target-length-probe.py --unrar UNRAR --work DIR

NOT MEASURED: x86-64 Linux (the system's own limit on a link's target
differs there), older readers.
