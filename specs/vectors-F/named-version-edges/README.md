# named-version-edges: which decoder the reference gives unpack versions 13, 14 and 26

For SPEC-F 3.3.5. `unrar-7.23-macos-arm64.tsv` is the output of
`../named-version-edges-probe.py` with unrar 7.23 for macOS arm64 on 11
Oct 2026: four genuine archives of `fixtures/legacy/archives`, every
compressed member's header rewritten to another unpack version, and what
`unrar t` then says. The probe's first comment says what a row holds.

    python3 ../named-version-edges-probe.py --unrar UNRAR --fixtures ../../../fixtures/legacy/archives --work DIR

Nothing is random and no archive is kept: the probe rewrites the genuine
fixtures each time. NOT MEASURED: x86-64 Linux, older readers.
