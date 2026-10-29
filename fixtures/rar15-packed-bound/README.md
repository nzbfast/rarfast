# RAR 1.5 members that declare far more than their packed input holds

Two inputs found by the second whole-roster fuzz campaign on 20 Sep 2026
(target `f_extract_any`, the SEQUENTIAL `Archive::extract`), copied here
so that they can be used without opening
any other repository. They are fuzzer output, not the work of any RAR
implementation.

- `declared-4gb-original.rar`, 13,802 bytes: as found.
- `declared-4gb-minimised.rar`, 11,548 bytes: minimised with
  `-minimize_crash=1`.

Each holds a RAR 1.5 member whose header declares about 4 GiB unpacked
over a few kilobytes of packed data. At an earlier revision of rarkit, built release
with no sanitizer and given 8 GB, the minimised input SUCCEEDS after
121.9 s with 4.32 GB peak RSS (an Apple M3 Mac), about 374,000 times its size.

What they are for: SPEC-A 6.1 as decided. The
decode ends when the packed input is exhausted and the member reports a
checksum failure, as reference `unrar` 7.23 does; and acceptance test 1
(no allocation proportional to the declared size) must hold, which it did
not. Expected after the fix: milliseconds, memory at the window plus the
copy buffer, `checksum_ok == Some(false)`, no panic.
