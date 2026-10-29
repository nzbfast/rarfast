# rarfast 0.9.0, first testers' release

rarfast is a new archiver for the RAR format. It creates, lists, tests,
extracts and repairs RAR archives, and it is built to be fast on many
cores. It is written in Rust. It is not a product of RARLAB.

**This is a test release. Please do not trust it with your only copy of
anything.** After you create an archive, test it (`rarfast t archive.rar`,
and with `unrar t archive.rar` if you have unrar) before you delete the
originals.

## Where is the source?

At https://github.com/nzbfast/rarfast, published with this release under
MIT OR Apache-2.0.

## Which file

| System | File |
|---|---|
| Windows 11, 64-bit Intel or AMD (Windows 10 has not been tested) | `rarfast-0.9.0-windows-x86_64.zip` |
| macOS 11 (Big Sur) or newer, Apple silicon only | `rarfast-0.9.0-macos-arm64.zip` |
| Linux, 64-bit Intel or AMD, glibc 2.34 or newer | `rarfast-0.9.0-linux-x86_64.tar.gz` |

All three are at https://github.com/nzbfast/rarfast/releases.
`SHA256SUMS` lists the checksum of every file. There is no 32-bit build,
no Intel Mac build and no ARM Linux build yet.

## First run

**Windows.** This build is not code signed yet. It needs nothing else
installed: the Microsoft C runtime is built into `rarfast.exe`.

1. Before unpacking, right-click the downloaded zip, choose Properties,
   tick Unblock, and press OK. (Or, in PowerShell:
   `Unblock-File rarfast-0.9.0-windows-x86_64.zip`.)
2. If Windows still says "Windows protected your PC" the first time you
   run it, choose More info, then Run anyway.
3. Check the program against `SHA256SUMS`: `Get-FileHash rarfast.exe`.

**Where to put it, and Windows Defender.** Unzip `rarfast.exe` anywhere;
there is no install step, and no folder is faster than another (we
measured Program Files against Downloads: no difference). While
rarfast writes its output, Defender spends far more CPU on it than on
the output of the other programs we counted, so extracting an archive
of many small files takes longer with rarfast than with UnRAR or 7-Zip
(the known issues give the figures). The extracted files are correct;
only the time changes. Why Defender treats rarfast's output this way is
being counted for 0.9.1. Testing an archive (`rarfast t`) and
extracting large media files are not affected. We do not know yet
whether Defender relaxes for a given `rarfast.exe` after some days on
one PC. Please do not turn Defender off or add an exclusion for this.

**macOS.** The program is not notarized by Apple. After unpacking, and
BEFORE you run rarfast for the first time, run this once in Terminal, in
the folder that holds it:

    xattr -d com.apple.quarantine rarfast

The order matters. If you already tried to run rarfast and macOS blocked
it, running the line afterwards may not free that copy: delete the
unpacked folder, unpack the archive again, and run the line first.

**Linux.** `chmod +x rarfast`. This build needs glibc 2.34 or newer: that
is Ubuntu 22.04, Debian 12, RHEL 9, Fedora 35, or anything newer
(`ldd --version` shows yours). It has been started and smoke tested on
Ubuntu 22.04 and 24.04, Debian 12, Fedora 35 and current, Rocky 9 and
AlmaLinux 9. On a system it does not support, this is what you see:

- On an older glibc (Ubuntu 20.04, Debian 11, RHEL 8) it does not start
  and prints lines of this form:

      ./rarfast: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./rarfast)

- On a musl system such as Alpine the shell prints only
  `sh: ./rarfast: not found`. That means the program loader is missing,
  not the file: the build needs glibc.

## Using it

rarfast takes the same commands and switches as `rar` and `unrar`:

    rarfast a -m5 backup.rar my-folder     create an archive
    rarfast t backup.rar                   test it
    rarfast x backup.rar out/              extract with paths
    rarfast l backup.rar                   list

A copy of the program named `unrar` (or a symbolic link with that name)
behaves as unrar, and one named `rar` behaves as rar, so it can stand in
for either in a script.

Sizes in switches follow rar: lower case `k`, `m`, `g`, `t` are powers of
1024 and upper case `K`, `M`, `G`, `T` are powers of 1000 (`-v100m` is
104,857,600 bytes, `-v100M` is 100,000,000). A switch rarfast does not
support yet is refused by name and nothing is done; `KNOWN-ISSUES.md`
lists them.

`rarfast --version` prints the version. Please include that line in
every report.

## Reporting a problem

Open an issue at https://github.com/nzbfast/rarfast/issues. Replies may
be slow for the first week. Please include:

- the output of `rarfast --version`;
- your system and processor;
- the exact command you ran;
- what you expected and what happened, with the program's output copied
  as text;
- if an archive is involved and you can share its listing, the output of
  `rarfast lt archive.rar`.

If rarfast ever writes an archive that fails its own test or unrar's, or
extracts a file that differs from the original, that is the most
important report you can send us. Please keep the archive.

`KNOWN-ISSUES.md` lists what we already know about.

## Licence

rarfast is licensed MIT OR Apache-2.0, at your option: see `LICENSE-MIT`
and `LICENSE-APACHE`. `THIRD-PARTY.txt` lists the open source libraries
inside the program and their licences. RAR is an archive format of
RARLAB; rarfast is independent of them.
