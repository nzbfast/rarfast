# What extraction does to a file it writes (10 Oct 2026)

The tables behind SPEC-CLI section 9. `output-path-probe.py` makes
them with the genuine rar (to build the archives) and the genuine
unrar (the program measured), and says in its first comment what a
row holds. Both programs are called; neither is opened or traced. A
file is looked at from outside only, with lstat, before, during and
after a run.

    ./output-path-probe.py RAR UNRAR LABEL DIR

- `output-path-7.23-macos-arm64.tsv`: 121 arms, unrar 7.23 on macOS
  (arm64), run as an ordinary user.
- `output-path-7.23-linux-x86-64.tsv`: the same 121 arms, unrar 7.23
  on Linux (x86-64), run as the superuser and with hang-ups ignored:
  the arms that need a permission to be refused, and the `signal-hup`
  arms, say nothing there (SPEC-CLI section 9's head lists these).

The 56 signal arms of a table are eight runs of seven kinds, and on
macOS the count of runs that end each way differs from one run of the
probe to the next. A run needs about 400 MB of scratch and writes a
393 MB member about 70 times. The arms on a full volume mount a 2 MB
volume inside the scratch (hdiutil on macOS; a tmpfs on Linux, which
needs the superuser) and are left out where neither can be done.

Windows (11 Oct 2026): `output-path-windows-probe.py` is the probe's
Windows form and says in its first comment what a row holds and which
arms it leaves out and puts in.

    output-path-windows-probe.py RAR UNRAR LABEL DIR

- `output-path-7.23-windows-x64.tsv`: 95 arms, UnRAR.exe 7.23 on
  Windows 11 (x64), the archives made there by Rar.exe 7.23, an NTFS
  volume, a user who is an administrator. A name's bits are its
  attributes there. No full volume: that case is not measured on
  Windows. SPEC-CLI note 9.9 reads this table.

`failed-replace-probe.py` and `failed-replace-7.23-macos-arm64.tsv`
(36 rows; SPEC-CLI 9.6): what unrar, rar and 7-Zip leave of a file
that was already there when the extraction that replaces it fails (a
checksum that does not agree, an archive cut short, a full volume).
7-Zip is 26.02 as Homebrew builds it for macOS, which reads stored RAR
members only. `failed-replace-7.23-linux-x86-64.tsv` (28 rows, 11 Oct
2026): unrar and rar on x86-64 Linux.
`failed-replace-7zip-23.01-linux-x86-64.tsv` (16 rows, 11 Oct 2026):
7-Zip 23.01 of the Ubuntu 24.04 `7zip` package on x86-64 Linux, its
programs `7z` and `7za`; `7za` reads no RAR, so
its 8 rows show only that. That run used `kept:DIR`, an archive made
by genuine rar 7.23 beforehand.
`failed-replace-7.23-windows-x64.tsv` (26 rows, 11 Oct 2026):
UnRAR.exe 7.23, Rar.exe 7.23 and 7-Zip 26.03 (`7z.exe`) on Windows 11
(x64), the archive made there by Rar.exe; no full volume, so the 10
rows of that case are not there.
