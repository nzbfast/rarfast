# h3-one-symbol-genuine: what rar writes when a table set sends one symbol of an alphabet

For SPEC-H3 6.3 item 1.

| File | What |
|---|---|
| `rar-7.23-macos-arm64.tsv` | the output of `../h3-one-symbol-genuine-probe.py`, run on 11 Oct 2026 with rar 7.23 for macOS arm64. Its first line is the program's banner. One row for every alphabet of every table set under which at most two different symbols are sent: the input, the switch, the set's number in the member, the alphabet, how many different symbols are sent, which, and every symbol the table gives a length to. A member rar stored has one row saying so. |
| `rar-7.23-linux-x86-64.tsv` | the same probe with rar 7.23 for x86-64 Linux, 11 Oct 2026. rar packs some inputs into other symbols there than on macOS (the rows differ from line 58 on); the rule the rows show is the same |

    python3 ../h3-one-symbol-genuine-probe.py WORK_DIR --rar /path/to/rar > rar-<version>-<system>.tsv

The probe makes its 21 inputs itself (no random source: the table can be
made again and compared), has the genuine rar pack each at `-m1` to
`-m5`, and reads the tables back with a RAR 5 reader written from
SPEC-H2's text, which is not kept at the tip. It checks that the reader gives each input
back before it prints a row. It removes its inputs and archives as it
goes; nothing but the table is kept.

NOT MEASURED: older writers.

The two tables here were made at the private commit be5c09422 by a tool not kept at the tip (that RAR 5 reader). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
