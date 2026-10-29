# h3-class-reading: six heads and what they read

For SPEC-H3 8.1, "LEVEL 5 BY CLASS" and "The second statistic".

| File | What |
|---|---|
| `a-one-byte.bin` to `f-blocks.bin` | six files of exactly 1,048,576 bytes. Every byte was drawn from the system's entropy source by `../h3-class-reading-probe.py --draw` on 11 Oct 2026; the probe's first comment says what kind of head each is. No recipe makes them again: the files are the vectors. |
| `readings.tsv` | one row a file: its size, its SHA-256, the four figures the section's words give on it (sum, stops, reading, long matches), the class those give, and the four figures under the one wording the section excludes (a table of most recent positions that follows the stops only). |

    python3 ../h3-class-reading-probe.py

checks the six files against the table and exits 0 when every row agrees.
The figures are integer arithmetic over the bytes, the same on every
machine, and no program is called: the reading is rarkit's own rule.

`--draw` writes six NEW files and a new table. Do that only together with
the section, whose figures are these rows.
