# Bases for `tests/repair_remaining_arms.rs`

Seven archives written by REFERENCE rar 7.23, stored (`-m0 -ma5`). They
are byte copies of the kept bases of specification L's two probes,
`specs/vectors-L/own-records-probe.py` and
`specs/vectors-L/own-records-more-probe.py` (each one's `--build`),
copied here so that a test of the tool opens nothing outside its own
crate. `SHA256SUMS` pins them.

| File | The probe's command, run in a directory holding the members |
|---|---|
| `plain.rar` | `rar a -ma5 -m0 -idq a.rar payload.bin` gives the inner archive; under the name `inner.rar` it is stored with `small.bin`: `rar a -ma5 -m0 -idq a.rar inner.rar small.bin`. No recovery record in either. |
| `hp150.rar` | `rar a -ma5 -m0 -idq -hpwalk-own -rr150 a.rar payload.bin` |
| `hp20.rar` | `rar a -ma5 -m0 -idq -hpwalk-own -rr20 a.rar payload.bin` |
| `inner150.rar` | `rar a -ma5 -m0 -idq -rr150 inner.rar payload.bin` |
| `outer150w.rar` | with that archive beside it as `inner.rar`: `rar a -ma5 -m0 -idq -rr20 outer.rar inner.rar small.bin` |
| `innerA150.rar`, `outerA150w.rar` | the same two commands over a `payload.bin` that is the letter A 6,000 times |

`payload.bin` is 6,000 bytes and `small.bin` 700, both the probe's own
pinned bytes. rar's salts make an enciphered archive's bytes differ from
run to run, so a rebuild of the two enciphered ones is a new pair and `SHA256SUMS` is
cut again with it.

No damaged archive is kept. Each test makes its damaged input from one
of these in a scratch directory, by the change its own text names.
