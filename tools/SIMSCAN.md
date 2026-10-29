# simscan: how to run the similarity check

`simscan.py` compares this repository's source with another source tree
and prints file names and scores only, never matched text. The project
runs it on every change, against the source its authors must not copy
from. You can run it against any tree you want to compare with: another
implementation of the format, an earlier version, a fork.

    python3 tools/simscan.py --subject crates/rarkit/src --reference <a directory of source> --label rarkit
    python3 tools/simscan.py --subject crates/rarkit-cli/src --reference <a directory of source> --label rarkit-cli

Each run ends with a `verdict` line and exits 0 on PASS, 1 on FAIL and 2
when it refuses (no subject files, an empty reference). The limits are in
`THRESHOLDS` near the top of the script; what each measure means is in
its opening comment.

`simscan-waivers.toml` lists the few files that score above a limit for a
reason that is not copying: constants a format or a public standard
dictates, such as CRC and BLAKE2 tables. Each row says what the source of
the numbers is and what the scores were when it was reviewed. A row whose
file has moved up past its recorded score fails the run.
`--no-waivers` judges every file on the limits alone.

    python3 tools/simscan.py --selftest

checks the tool against planted copies and needs no other tree.
