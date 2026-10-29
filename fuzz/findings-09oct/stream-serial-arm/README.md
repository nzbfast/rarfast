# rar5_oracle_stream: the stop after the filter type class, 9 October 2026

Found by running `rar5_oracle_stream` for four minutes from its
committed seeds, once the comparison of a filter type of 4 or above was
made a counted class (`oracle_support.rs`, `ORACLE_FILTER_TYPE`). It
stopped at execution 520, peak resident set 179 MB.

| | |
|---|---|
| input | `rar5_oracle_stream--crash-7585a5a6...hex`, 76 bytes, sha256 87d642dd8158f2aad5d4f34efbaf3cf10bf568b90dd319bfdd4751f266f872ab (`xxd -r -p` gives the bytes back) |
| the line | `rar5_oracle_stream.rs`, the serial arm against the oracle: "member 1: the decoder's serial arm 85 bytes, the oracle 85, first difference at Some(30)" |
| the archive the target frames from it | `framed-archive.rar.hex`, 347 bytes, sha256 ff35f60ac31f625906facac79da7f51c551f574779c42cf3c3c9b1ffb550a33d (three members in one solid chain: 42, 85 and 0 bytes; no checksum) |

## What was measured, and nothing more

- Reference unrar 7.23 (`unrar t`): All OK, three members.
- Member by member, sha256 of the bytes `unrar x` wrote against what
  `rarfast x` wrote (a plain build of main 3db18e7c5): 466d7a466636,
  fabdcdb9b9ac and the empty file, the SAME on both for all three.
- The decoder's serial arm for member 1, written by the replay aid
  (`RAR5O_DUMP`): fabdcdb9b9ac, the reference's bytes.
- The comparison engine's member 1: 94d79a79eb72. It differs from the
  reference in ONE place: at byte 30 it copies 24 bytes from the first
  byte of member 0, where the reference and rarkit copy the same count
  from member 0's fifth byte. Everything before and after is the same.
- Neither member's stream holds a filter record the order rule drops, or
  a long kept one (`filter_record_shape` answers false and false for all
  three).

So on this input rarkit's reader, rarkit's serial arm and the reference
agree, and the comparison engine alone is four bytes off in one match's
source. WHICH rule separates them is NOT established: no class is added
for it, and the target still stops on this input. Until a shape is
named for it the target cannot run an hour.
