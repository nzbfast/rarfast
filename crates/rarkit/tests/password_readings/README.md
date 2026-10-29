# The Linux-made twin of the Windows capture's long-password archive

`linux-long-password.rar` (140 bytes, sha256
`75b10faed90aabf0066bc76f02c09cda24ef85e69d1e64c3d98a3cf908b81057`) was
written on 6 Oct 2026 by the reference `rar` 7.23 for x86-64 Linux, under
`LANG=C.UTF-8`, with the command of the capture's own archive
(`specs/vectors-K/windows-06oct/long-password/t.rar`):

    printf 'hello\n' > hello.txt
    rar a -ma5 -m0 -p<125 x, U+1F511, y, z> twin.rar hello.txt

`rar` warned that the password exceeds 127 characters and would be cut.
The reference `unrar` 7.23 for Linux then answered, for the same file:

| Password given | Verdict |
|---|---|
| whole (128 characters, 129 UTF-16 units) | All OK |
| cut after `y` (127 characters, 128 units) | All OK |
| cut after U+1F511 (126 characters, 127 units) | Incorrect password, exit 11 |

So this writer kept 127 characters, where the Windows one kept 127 UTF-16
units (spec K 3.7.1). The salt is random, so a second run of the command
writes other bytes with the same verdicts.

`tests/password_readings.rs` reads both archives.
