# rarfast 0.9.0 (beta)

rarfast is a new, fast archiver for the RAR format, written in Rust: it
creates, lists, tests, extracts and repairs RAR archives and takes the
same commands as `rar` and `unrar`. It is not a product of RARLAB.

**0.9.0 is a beta.** Please do not trust it with your only copy of
anything yet: test every archive you make before deleting the originals.
We do not expect the beta to be long, because rarfast was tested
extensively before this release. On this release's code:

- 3,361 automated tests passed, 0 failed, on macOS (Apple silicon),
  and 905 more, 0 failed, in a check that the library's tests read no file outside the library's own folder.
  4,260 passed, 0 failed, on Linux x86-64;
- built from the public source alone, as cargo builds it by default,
  3,041 tests passed, 0 failed, on macOS and again on Linux;
- the Windows release build passed a 36-check first-use test on a
  second Windows machine that did not build it (create, test and
  extract at two levels, with and without passwords, and a volume set,
  each output checked byte for byte).

## Downloads

| System | File |
|---|---:|
| Windows 11, x86-64 (Windows 10 has not been tested) | `rarfast-0.9.0-windows-x86_64.zip` |
| macOS 11 (Big Sur) or newer, Apple silicon only | `rarfast-0.9.0-macos-arm64.zip` |
| Linux, x86-64, glibc 2.34 or newer (Ubuntu 22.04, Debian 12, RHEL 9, Fedora 35 or newer) | `rarfast-0.9.0-linux-x86_64.tar.gz` |

SHA-256 of each download (the same lines are in `SHA256SUMS`):

    5ca1d5dc00d16a12ce6974f43d8060b60aaecf0968c226acbc4d5530b43cafb4  rarfast-0.9.0-macos-arm64.zip
    68e4af86aaf6c36d8212ce0b10a28703282d3721391b8ed6394dacd2b806dd3c  rarfast-0.9.0-windows-x86_64.zip
    17f26463edc119d6d498d244c229b23ada6aada23e33cae298435f15f68dbe5b  rarfast-0.9.0-linux-x86_64.tar.gz

Each download holds the program, a README, the known issues, the licence
texts and a `SHA256SUMS` of the files inside it. `rarfast --version`
names the source each program was built from, `b5ec84e81213` on all
three: `rarfast 0.9.0 (b5ec84e81213, aarch64 macos)`, `rarfast 0.9.0
(b5ec84e81213, x86_64 linux)` and `rarfast 0.9.0 (b5ec84e81213, x86_64
windows)`.

## Source

The source is published with this release, under MIT OR Apache-2.0, in
this repository: https://github.com/nzbfast/rarfast.

## Before you run it

- **Windows:** the program is not code signed yet. rarfast has been
  approved for code signing by SignPath, and the certificate has not
  been issued yet; a signed build will follow. Unblock the zip
  before unpacking (Properties, Unblock) and expect a SmartScreen prompt
  on first run (More info, Run anyway). Extracting archives of very many
  files is slower than with unrar or 7-Zip while Defender checks
  rarfast's output (the known issues give the figures).
- **macOS:** the program is not notarized. Run
  `xattr -d com.apple.quarantine rarfast` once after unpacking, BEFORE
  the first run. If macOS has already blocked a copy, unpack the archive
  again and run the line first.
- **Linux:** the build needs glibc 2.34 or newer (the highest versioned
  glibc symbol the binary uses is `GLIBC_2.34`). It does not start on
  older systems (Ubuntu 20.04, Debian 11, RHEL 8) or on musl systems
  such as Alpine; the README gives what those print.

The README inside each download has the details, and `KNOWN-ISSUES.md`
lists what we already know about, with the commands and switches this
release refuses. The one to know first: rarfast creates new archives and
does not yet add files to an archive that already exists.

rarfast l -v and lt -v now list every member of every volume of a
multi-volume set, as unrar does.

## Speed on big files: the time you save

Big RAR5 archives in the two formats most Usenet uploaders use: RAR5
stored (`-m0`) and RAR5 compressed (`-m3`, rar's default), each split
into 100 MiB volumes. Each machine ran two sets: one big member (16 GiB
on Windows and Linux, 32 GiB on macOS), and ten members of 2 GiB, 20 GiB
in all; each platform's section gives the volume counts. In the tables,
"1 x 16 GiB" is one member of 16 GiB and "10 x 2 GiB" is ten members of
2 GiB. Every program ran at its own defaults
(threads included) on the same machine, against the released 0.9.0
binary, and each figure is a median unless marked. Times are in
seconds, with minutes past a minute. "rarfast faster than unrar 2.76x"
means unrar took 2.76 times as long as rarfast; below 1.00x the other
program was faster, and the table says so in words. Where two copies of rarfast differed by more than 2 percent, the row is
read by each program's fastest run, and is marked `*`.

### The time you save, in a few examples

- **Extracting ten 2 GiB members, RAR5 compressed, on Windows**
  (PC 1): 2.5 s with rarfast against 1 min 18.8 s with 7-Zip, so
  1 min 16.3 s saved.
- **Extracting ten 2 GiB members, RAR5 compressed, on Linux:** 6.0 s with rarfast
  against 1 min 29 s with 7-Zip, so 1 min 23 s saved.
- **Creating one 16 GiB member, RAR5 compressed, on Linux** (`-m3`): 43.3 s with
  rarfast against 6 min 16 s with rar, so 5 min 32 s saved.
- **Creating one 32 GiB member, RAR5 compressed, on macOS** (M1 Ultra, `-m3`):
  45.9 s with rarfast against 8 min 53.9 s with rar, so 8 min 8.1 s
  saved.
- **Creating one 32 GiB member, RAR5 compressed, on macOS** (M5
  MacBook Air, `-m5`): 1 min 41.0 s with rarfast against 12 min 12.4 s with rar, so
  10 min 31.4 s saved.

### Where rarfast is not ahead

- **Linux, one 16 GiB member, RAR5 stored, right after the set was
  read:** in a later count (AMD EPYC 4345P, Linux 6.8), unrar exits
  first, but with about 5.7 GiB of the file not yet on the drive;
  counted until the data is on the drive, rarfast is faster, 5.0 s
  against 6.5 s.
- **Archive size when creating, RAR5 compressed:** rar's archives are
  0.2 to 0.6 percent smaller, by machine and level (the size column of
  each create table). RAR5 stored, the two are the same size.
- **macOS (M5 MacBook Air), creating with the files already in
  memory:** the ten 2 GiB members, RAR5 stored, ran 0.95x to 1.10x,
  by which files the cache held.
- **Windows with Defender on, extracting many small files:** Defender
  spends far more CPU on rarfast's output while it is written, so
  20,000 small files, RAR5 compressed, took 6.2 s with rarfast against
  3.5 s with unrar and 4.5 s with 7-Zip (PC 1, the table below; the
  known issues give the figures).

### Windows

Two PCs of the same model: AMD Ryzen 7 9800X3D (8 cores, 16 threads),
61.6 GiB RAM, Windows 11 Pro 10.0.26200, a WD_BLACK SN8100 4 TB NVMe
drive. The sets: one member of 16 GiB (164 volumes RAR5 stored, 158
RAR5 compressed), and ten members of 2 GiB (205 volumes stored, 197
compressed). Before
each run the previous output was removed and the drive's pending writes
were allowed to finish. Each extract time is the median of 7 runs (9 for
the 16 GiB member, RAR5 stored, on PC 1); the stored create rows are the median of 6
runs and the compressed ones of 3. Every output was checked against the
input (sha256), and every archive rarfast created passed `rar t`.

This build is a plain release build, not profile optimised (the macOS
and Linux builds are). unar has no Windows command line build, so it is
not in these tables.

The Windows rows were measured on an earlier build of 0.9.0, whose
version line names `6fac1fc369bb`. The Windows build you download is a
plain build of `b5ec84e81213`, this release's final source. Its level
pair against the previous candidate's Windows build on PC 1 passed on
every row. Each build since the measured one was checked level against
the build before it.

The ten 2 GiB members, RAR5 stored, were extracted twice: once right
after the set was read, and once after 20 GiB of other data had been
written to the drive.

**PC 1**

| extract | rarfast | unrar 7.23 | rarfast faster than unrar | 7-Zip 26.03 | rarfast faster than 7-Zip |
|---|---:|---:|---:|---:|---:|
| 1 x 16 GiB, RAR5 stored | 2.2 s | 6.1 s | 2.76x | 10.7 s | 4.82x |
| 1 x 16 GiB, RAR5 compressed | 6.2 s | 20.0 s | 3.22x | 1 min 3.1 s | 10.15x |
| 10 x 2 GiB, RAR5 stored, after a read | 1.6 s | 7.1 s | 4.49x | 13.2 s | 8.30x |
| 10 x 2 GiB, RAR5 stored, after a write | 1.6 s | 7.7 s | 4.82x | 13.3 s | 8.33x |
| 10 x 2 GiB, RAR5 compressed | 2.5 s | 25.1 s | 10.00x | 1 min 18.8 s | 31.36x |

| create | rarfast | WinRAR 7.23 | rarfast faster than WinRAR | archive size, rarfast / WinRAR |
|---|---:|---:|---:|---|
| 1 x 16 GiB, RAR5 stored (`-m0`) | 2.4 s | 6.2 s | 2.59x | 16.00 / 16.00 GiB |
| 1 x 16 GiB, RAR5 compressed (`-m3`) | 26.9 s | 3 min 50.9 s | 8.59x | 15.40 / 15.36 GiB |
| 1 x 16 GiB, RAR5 compressed (`-m5`) | 35.2 s | 3 min 21.8 s | 5.74x | 15.40 / 15.36 GiB |
| 10 x 2 GiB, RAR5 stored (`-m0`) | 3.0 s | 7.7 s | 2.59x | 20.00 / 20.00 GiB |
| 10 x 2 GiB, RAR5 compressed (`-m3`) * | 33.0 s | 4 min 47.0 s | 8.69x | 19.26 / 19.20 GiB |
| 10 x 2 GiB, RAR5 compressed (`-m5`) | 43.0 s | 4 min 23.1 s | 6.12x | 19.26 / 19.20 GiB |

A later count on PC 1, of the 0.9.0 build you download, median of 3
runs:

| extract | rarfast | unrar 7.23 | rarfast faster than unrar | 7-Zip 26.03 | rarfast faster than 7-Zip |
|---|---:|---:|---:|---:|---:|
| 20,000 small files, RAR5 compressed | 6.2 s | 3.5 s | 0.57x | 4.5 s | 0.73x |

**PC 2**

| extract | rarfast | unrar 7.23 | rarfast faster than unrar | 7-Zip 26.03 | rarfast faster than 7-Zip |
|---|---:|---:|---:|---:|---:|
| 1 x 16 GiB, RAR5 stored | 2.1 s | 6.0 s | 2.89x | 10.6 s | 5.06x |
| 1 x 16 GiB, RAR5 compressed | 6.3 s | 20.3 s | 3.22x | 1 min 2.9 s | 9.98x |
| 10 x 2 GiB, RAR5 stored, after a read * | 1.6 s | 7.2 s | 4.60x | 12.8 s | 8.25x |
| 10 x 2 GiB, RAR5 stored, after a write | 1.6 s | 7.7 s | 4.88x | 13.3 s | 8.40x |
| 10 x 2 GiB, RAR5 compressed | 2.6 s | 25.2 s | 9.74x | 1 min 18.5 s | 30.31x |

| create | rarfast | WinRAR 7.23 | rarfast faster than WinRAR | archive size, rarfast / WinRAR |
|---|---:|---:|---:|---|
| 1 x 16 GiB, RAR5 stored (`-m0`) * | 2.3 s | 5.4 s | 2.34x | 16.00 / 16.00 GiB |
| 1 x 16 GiB, RAR5 compressed (`-m3`) * | 26.2 s | 3 min 55.7 s | 9.01x | 15.40 / 15.36 GiB |
| 1 x 16 GiB, RAR5 compressed (`-m5`) | 34.2 s | 4 min 54.3 s | 8.60x | 15.40 / 15.36 GiB |
| 10 x 2 GiB, RAR5 stored (`-m0`) | 3.2 s | 7.4 s | 2.31x | 20.00 / 20.00 GiB |
| 10 x 2 GiB, RAR5 compressed (`-m3`) | 32.7 s | 4 min 53.9 s | 8.98x | 19.26 / 19.20 GiB |
| 10 x 2 GiB, RAR5 compressed (`-m5`) | 43.1 s | 5 min 33.6 s | 7.74x | 19.25 / 19.20 GiB |

unrar here is WinRAR's `UnRAR.exe` 7.23, WinRAR is `Rar.exe` 7.23 (the
command line program that comes with WinRAR), and 7-Zip is `7z.exe`
26.03.

### Linux

AMD EPYC 4345P, 8 cores and 16 threads, 60 GiB RAM, NVMe, Ubuntu 24.04.5
LTS. The sets: one member of 16 GiB (164 volumes RAR5 stored, 158 RAR5
compressed), and ten members of 2 GiB (205 volumes stored, 197
compressed). Each
extract time is the median of 5 runs, each create time the median of 3.
Every program's output was checked against the input once per row
(sha256): identical for rarfast, unrar and 7-Zip on every row. Every
archive rarfast created passed `rar t`.

The stored rows were run twice: once right after the set was read, and
once right after 20 GiB of other data had been written to the disk.

| extract | rarfast | unrar 7.23 | rarfast faster than unrar | 7-Zip 23.01 | rarfast faster than 7-Zip |
|---|---:|---:|---:|---:|---:|
| 1 x 16 GiB, RAR5 stored, after a read | 4.8 s | 4.8 s | 1.01x (unrar exits with 5.2 GiB unwritten) | 11.5 s | 2.40x |
| 1 x 16 GiB, RAR5 stored, after a write | 7.1 s | 11.6 s | 1.64x | 15.0 s | 2.12x |
| 1 x 16 GiB, RAR5 compressed | 5.0 s | 18.3 s | 3.67x | 1 min 11 s | 14.26x |
| 10 x 2 GiB, RAR5 stored, after a read | 3.9 s | 5.9 s | 1.53x | 14.1 s | 3.66x |
| 10 x 2 GiB, RAR5 stored, after a write | 5.2 s | 11.5 s | 2.20x | 17.6 s | 3.36x |
| 10 x 2 GiB, RAR5 compressed | 6.0 s | 22.8 s | 3.77x | 1 min 29 s | 14.70x |

| create | rarfast | rar 7.23 | rarfast faster than rar | archive size, rarfast over rar |
|---|---:|---:|---:|---:|
| 1 x 16 GiB, RAR5 stored (`-m0`) | 4.9 s | 8.9 s | 1.81x | 1.000 |
| 1 x 16 GiB, RAR5 compressed (`-m3`) | 43.3 s | 6 min 16 s | 8.68x | 1.005 |
| 1 x 16 GiB, RAR5 compressed (`-m5`) | 53.9 s | 5 min 12 s | 5.78x | 1.006 |
| 10 x 2 GiB, RAR5 stored (`-m0`) | 6.1 s | 12.1 s | 1.97x | 1.000 |
| 10 x 2 GiB, RAR5 compressed (`-m3`) | 54.2 s | 7 min 47 s | 8.61x | 1.005 |
| 10 x 2 GiB, RAR5 compressed (`-m5`) | 1 min 7 s | 6 min 29 s | 5.81x | 1.006 |

The two stored (`-m0`) create rows ran right after the repeated 20 GiB
writes of the extract rows. An earlier run of the same rows on the same
machine, with no such writes before it, read 5.4 s for rarfast against
5.7 s for rar on the 16 GiB member, and 6.2 s against 8.1 s on the ten
2 GiB members. The
compressed create rows agree with that run within 2 percent.

7-Zip here is the official Linux build 23.01 from www.7-zip.org, the
newest Linux build listed there. Ubuntu's own `7zip` package
(23.01+dfsg-11) cannot extract a compressed RAR file at all: it is built
without a RAR decoder.

**unar did not extract these archives correctly, so it has no times.**
unar 1.10.1, from the Ubuntu package `unar 1.10.7+ds1+really1.10.1-3build1`:

- the one 16 GiB member: `lsar` lists the file as 0 bytes; unar exits 0 and
  writes an empty file;
- each of the ten 2 GiB members: `lsar` lists its size as -2147483648; unar
  exits 1 with `Failed! (Attempted to read more data than was
  available)` and writes nothing. The stored sets gave the same results.
- controls of one file each, archived by `rar a -ma5 -v100m`: a stored
  file of 2047 MiB extracts correctly and one of 2048 MiB fails, as
  above. Of two compressed files of 1 GiB, one extracts correctly and
  the other fails with the same message, 262,144 bytes short, on each of
  three runs; `unrar t` passes that archive and rarfast extracts it
  correctly.

### macOS

The macOS rows were measured on an earlier build of 0.9.0, whose
version line names `6fac1fc369bb`. The build you download is the
profile optimised build of `b5ec84e81213`. Its level pairs against the
previous candidate passed on the M5 MacBook Air.
Each build since the measured one was checked level against the build before it.

**Apple M5 MacBook Air**

The base model: 10 cores, no fan, 32 GiB RAM,
internal SSD, macOS 27.0.1. The sets: one member of 32 GiB (328 volumes
RAR5 stored, 312 RAR5 compressed), and ten members of 2 GiB (205 volumes
stored, 197 compressed). These sets do not fit in memory, so each was read once
just before its row. Each extract time is the median of 5 runs. The
create rows were timed from the drive with nothing of the files in
memory before each run (checked for every run), the median of 7 runs
stored and of 3 compressed. Every rarfast, unrar and 7-Zip output was
checked byte for byte (sha256), and every archive rarfast created passed
`rar t`.

The stored rows were run twice: once right after the set was read, and
once after 20 GiB of other data had been written to the disk.

| extract | rarfast | unrar 7.23 | rarfast faster than unrar | 7-Zip 26.04 | rarfast faster than 7-Zip |
|---|---:|---:|---:|---:|---:|
| 1 x 32 GiB, RAR5 stored, after a read | 11.8 s | 16.6 s | 1.41x | 17.5 s | 1.48x |
| 1 x 32 GiB, RAR5 stored, after a write * | 11.7 s | 16.2 s | 1.39x | 17.5 s | 1.50x |
| 1 x 32 GiB, RAR5 compressed | 12.5 s | 1 min 2.8 s | 5.02x | 2 min 12.5 s | 10.59x |
| 10 x 2 GiB, RAR5 stored, after a read * | 7.3 s | 10.2 s | 1.40x | 10.9 s | 1.50x |
| 10 x 2 GiB, RAR5 stored, after a write * | 7.3 s | 10.2 s | 1.40x | 11.0 s | 1.52x |
| 10 x 2 GiB, RAR5 compressed * | 8.1 s | 39.3 s | 4.85x | 1 min 23.3 s | 10.30x |

| create, from the drive | rarfast | rar 7.23 | rarfast faster than rar |
|---|---:|---:|---:|
| 1 x 32 GiB, RAR5 stored (`-m0`) | 16.3 s | 16.8 s | 1.03x |
| 1 x 32 GiB, RAR5 compressed (`-m3`) * | 1 min 17.9 s | 12 min 17.6 s | 9.47x |
| 1 x 32 GiB, RAR5 compressed (`-m5`) | 1 min 41.0 s | 12 min 12.4 s | 7.25x |
| 10 x 2 GiB, RAR5 stored (`-m0`) | 10.1 s | 10.4 s | 1.04x |
| 10 x 2 GiB, RAR5 compressed (`-m3`) | 55.4 s | 8 min 26.5 s | 9.14x |
| 10 x 2 GiB, RAR5 compressed (`-m5`) | 1 min 1.9 s | 7 min 37.2 s | 7.39x |

**Apple M1 Ultra**

20 cores (16 performance, 4 efficiency), 128 GiB RAM, internal SSD,
macOS 27.0. The sets: one member of 32 GiB (328 volumes RAR5 stored,
312 RAR5 compressed), and ten members of 2 GiB (205 volumes stored, 197
compressed). Here each set fits in memory; the ten 2 GiB members, RAR5
stored, were also extracted from a fresh copy that was not in memory ("not cached"). Each
extract time is the median of 5 runs, each create time the median of 3,
and each row waited for the machine to be quiet before it ran. Every
rarfast output was checked byte for byte (sha256), and every archive
rarfast created passed `rar t`.

| extract | rarfast | unrar 7.23 | rarfast faster than unrar | 7-Zip 26.04 | rarfast faster than 7-Zip |
|---|---:|---:|---:|---:|---:|
| 1 x 32 GiB, RAR5 stored, after a read * | 5.2 s | 11.8 s | 2.29x | 24.2 s | 4.70x |
| 1 x 32 GiB, RAR5 stored, after a write * | 4.9 s | 9.1 s | 1.86x | 14.1 s | 2.90x |
| 1 x 32 GiB, RAR5 compressed * | 15.1 s | 1 min 20.7 s | 5.36x | 5 min 33.4 s | 22.15x |
| 10 x 2 GiB, RAR5 stored, after a read | 3.2 s | 13.8 s | 4.31x | 23.4 s | 7.33x |
| 10 x 2 GiB, RAR5 stored, after a write * | 3.2 s | 6.8 s | 2.13x | 12.8 s | 3.98x |
| 10 x 2 GiB, RAR5 stored, not cached, after a read * | 6.6 s | 10.2 s | 1.54x | 16.4 s | 2.47x |
| 10 x 2 GiB, RAR5 stored, not cached, after a write * | 6.8 s | 10.4 s | 1.54x | 17.0 s | 2.51x |
| 10 x 2 GiB, RAR5 compressed * | 4.3 s | 1 min 47.9 s | 25.35x | 3 min 25.6 s | 48.31x |

| create | rarfast | rar 7.23 | rarfast faster than rar | archive size, rarfast / rar |
|---|---:|---:|---:|---|
| 1 x 32 GiB, RAR5 stored (`-m0`) * | 4.9 s | 8.9 s | 1.81x | 32.00 / 32.00 GiB |
| 1 x 32 GiB, RAR5 compressed (`-m3`) | 45.9 s | 8 min 53.9 s | 11.64x | 30.53 / 30.46 GiB |
| 1 x 32 GiB, RAR5 compressed (`-m5`) | 52.6 s | 8 min 48.7 s | 10.05x | 30.55 / 30.46 GiB |
| 10 x 2 GiB, RAR5 stored (`-m0`) | 3.0 s | 5.6 s | 1.85x | 20.00 / 20.00 GiB |
| 10 x 2 GiB, RAR5 compressed (`-m3`) | 28.5 s | 5 min 39.4 s | 11.93x | 19.23 / 19.18 GiB |
| 10 x 2 GiB, RAR5 compressed (`-m5`) | 32.5 s | 5 min 31.6 s | 10.22x | 19.25 / 19.18 GiB |

**On both Macs:** 7-Zip here is 7-Zip 26.04 for Apple silicon, from
7-zip.org. unar is not in these tables: its official command line build
is for Intel Macs only, and it was not run under Rosetta.

**The bsdtar that comes with macOS (3.5.3, libarchive 3.7.4) did not
extract these split archives correctly,** so it has no times. On the
first volume of each set it exited 0 and wrote a file that does not
match the original (on the ten 2 GiB members, one member of ten). From the same data
archived as a single volume, it extracted every set correctly.

### Not done for this release

- one planned check of the macOS and Linux profile-optimised builds, on
  an input of one big member, was not run;
- the Linux build's profile check ran on AMD processors only; Intel was
  not checked;
- a volume set whose next volume is not a RAR archive was tested on
  RAR 5 sets only, not on RAR 4 sets;
- the SmartScreen prompt on a double click in Explorer was not tested on
  this build; the SmartScreen note comes from earlier builds. The zip, marked as downloaded (ZoneId=3), was unpacked by
  Expand-Archive and by Explorer's extractor: each gave the right
  program, which ran, and created, tested and extracted archives byte
  for byte.

## Reporting bugs

Please open an issue at https://github.com/nzbfast/rarfast/issues, with
the output of `rarfast --version`, your system, the exact command and
what happened. Replies may be slow for the first week. A report of an
archive that fails its test, or an extracted file that differs from the
original, is the most valuable thing you can send.
