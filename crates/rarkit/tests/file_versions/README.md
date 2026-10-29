# solid-ver.rar

A SOLID archive of file versions, written by reference rar 7.23 (macOS
aarch64) on 6 Oct 2026 for `tests/file_versions.rs`: the solid chain runs
through members an extraction passes over by default.

Made by running, three times, with `v.txt` holding
`solid version N of the file, with enough text to compress. ` forty times
and a line end (N = 1, 2, 3) and `w.txt` holding `another member ` fifty
times and a line end:

    rar a -idq -ver -s -m3 solid-ver.rar v.txt w.txt

Its six members in archive order, as `unrar lt` names them: `v.txt;1`,
`w.txt;1`, `v.txt;2`, `w.txt;2`, `v.txt`, `w.txt`. `unrar t` tests
`v.txt` and `w.txt` and says "All OK"; `unrar t -ver` tests all six.
