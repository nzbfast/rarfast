# rar5-tag-clock: the tag a genuine writer stores in its recovery records

For SPEC-L 3.5.2, "The tag".

| File | What |
|---|---|
| `rar-7.23-macos-arm64.tsv` | 40 runs of rar 7.23 for macOS arm64 on 11 Oct 2026, a third of a second apart |
| `rar-7.23-linux-x86-64.tsv` | 40 runs of rar 7.23 for x86-64 Linux on 11 Oct 2026 |

A row is one run of the writer: the clock before and after it, and the
tag its archive holds (`../rar5-tag-clock-probe.py` says the rest). The
two tables were written by an earlier form of the probe that printed the
same nine columns under shorter headings and `True` for `yes`; the
headings and that word were brought to the probe's, and no value was
touched.

    python3 ../rar5-tag-clock-probe.py /path/to/rar WORK_DIR > rar-<version>-<system>.tsv

No two tables are alike, because the tag is of the clock: that is what
they show. Each archive here has one record; that all records of one
archive hold one tag is the census's finding (`../l-evidence/census.txt`),
on archives of many records.

NOT MEASURED: older writers.
