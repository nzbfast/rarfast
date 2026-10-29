#!/usr/bin/env python3
"""Mechanical similarity scan of a SUBJECT source tree against a REFERENCE.

    simscan.py --subject <dir or files> --reference <dir> --label <name>
    simscan.py --subject <dir or files> --reference-set donor        # pass/fail
    simscan.py --subject <dir or files> --reference-index <file>     # pass/fail
    simscan.py --reference <dir> --save-index <file>
    simscan.py --selftest

WHY. The rarkit project ends
in a closing audit: the new crate scanned against RARLAB's UnRAR and against
the donor crate the old engine was forked from. The UnRAR half had a tool
(a record, not edited); the
donor half had none, and no "before" figure either. This is that tool. It
reuses the audit's three measures and adds the one a Rust-to-Rust comparison
needs: shared CODE TOKEN RUNS.

MEASURES, per subject file:
  runs    code is tokenised (identifiers, keywords, literals, punctuation;
          comments and whitespace dropped). A token is COVERED at N when it
          lies inside any run of N consecutive tokens that also occurs in one
          reference file. N is 8, 12, 16, 24, 32 and 48. Counted two ways: RAW, and
          NORMALISED, where every identifier that is not a keyword or a
          primitive type becomes one placeholder and every literal another,
          so a rename does not hide a copied function.
  n48d    the normalised count at N=48 again, counting only windows that hold
          at least DISTINCT different token values. Normalisation maps every
          literal to one placeholder, so a constant table becomes `L , L , L`
          and matches any other table in the reference: norm48 saturates on
          table-driven code whoever wrote it. n48d is the same measure with
          that artefact removed, and it is what each FILE is judged on.
  ids     identifiers shared after normalisation (lower case, underscores
          removed, 5 or more characters, not a keyword, not a dictionary
          word when /usr/share/dict/words exists).
  grams   8-word runs shared between comments plus string literals.
  ints    array-literal runs of 8 or more integers with an 8-window that
          occurs in a reference array literal.

THE HARD RULE: THIS TOOL PRINTS NAMES AND COUNTS, NEVER MATCHED TEXT. The
engine's authors run it over their own new files against a reference they
must not read, and a tool that echoes a matched run hands them the forbidden
body. Three things hold that:
  1. the reference is reduced to 64-bit hashes as it is read, and nothing
     else of it is kept, so there is no reference text to print;
  2. every output line goes through emit(), which refuses a line carrying an
     identifier the reference has and the subject's own paths do not;
  3. --selftest builds a reference with marker tokens, copies some into a
     subject, runs every output mode and fails if any line carries a run of
     reference tokens - and proves the detector by catching a leaky line.
The reference index (--save-index) is hashes only, so a box that runs
the scan needs no donor tree at all. It is large (tens of MB): keep it OUT of git.

PASS/FAIL. The WHOLE SUBJECT is judged on raw24 and norm48, because those are
where unrelated Rust reads near zero and the present fork reads 27 to 44
percent (normalised runs shorter than 24 are mostly the language: unrelated
crates read 21 to 47 percent at N=16). Each FILE is judged on raw24 and n48d.
Per file, norm48 does not separate at any size: the 18 Sep 2026 calibration
measured 168 unrelated files from 17 crates and found norm48 reaching 99.8
percent on an unrelated CRC table and 17.8 on a 16,000-token deflate encoder,
while the same files read at most 9.1 on n48d. norm48 is still printed per
file, as a report. Limits by size are in THRESHOLDS below; the controls they
come from are in the project's baseline record. Shared integer runs and comment grams are printed as NOTES, not
failures: a constant table a format defines collides honestly, so a note is a
thing to explain, not a verdict.

WAIVERS. Some files no honest limit can clear, because a format or a public
standard dictates what is in them: an unrelated crate's copy of RFC 7693's
tables reads raw24 83.5 against this reference. Those carry reviewed rows in
simscan-waivers.toml, printed under `waived file`. A waiver is a claim
somebody verified, not a mute button: a row naming a file that has gone
fails the run, a row whose file drifted up past its own `step` fails the run,
a row awaiting a decision waives nothing, and the WHOLE-SUBJECT limit takes no
waivers at all. --no-waivers judges every file on the limits alone.
Exit 0 pass, 1 fail, 2 refusal (no subject files, an empty reference, a
malformed waiver file, a guard trip: failing to find is failing).

LIMITS. Token runs cannot see structural copying with reordered statements,
a function re-expressed in different control flow, or an architecture; the
manual structural comparison stays to be done at the closing audit. Inline
`#[cfg(test)] mod x { }` blocks and files named `tests.rs`, `test.rs` or
`*_tests.rs` are dropped from the SUBJECT by default (--keep-tests keeps them); a `cfg(all(test, ...))` spelling is not
recognised. Block comments are not nested. The reference is always whole.
"""
# selftest-roster: a research instrument for a project whose code will live
# in another repository; it guards no tree in this one, so no job here has a
# reason to run it per push. Its selftest is synthetic (no donor tree, no
# network, under 2 s) and it was run at the landing; the pass/fail mode repeats
# the no-echo guard on its real output at every run, which is the property
# the selftest exists for.
import argparse, collections, fnmatch, hashlib, io, json, os, pickle, re
import shutil, subprocess, sys, tempfile

NS = (8, 12, 16, 24, 32, 48)
# DISTINCT: a normalised 48-token window counts toward `n48d` only when it
# holds at least this many DIFFERENT token values. Normalisation maps every
# literal to one placeholder, so a constant table becomes `L , L , L ...`
# and collides with any other table in the reference: that is the measure
# saturating, not evidence. Requiring a window to be varied removes it. The
# 18 Sep 2026 per-file calibration (write-up section 9) measured 168
# unrelated files from 17 crates: norm48 reached 99.8 percent, n48d reached
# 9.1, while a donor tree with every identifier renamed still reads 78 to
# 100 on n48d. So n48d keeps what norm48 was for and drops what broke it.
DISTINCT = 12
# THRESHOLDS. Each row: a unit of at least this many tokens fails above the
# two percentages that follow.
#
# WHOLE SUBJECT, judged on raw24 and norm48, from the four original negative
# controls (write-up section 3). Unchanged by the per-file calibration, and
# no waiver may clear it.
JUDGED_WHOLE = ("raw24", "norm48")
WHOLE_LIMITS = ((5000, 3.0, 4.0), (1000, 8.0, 8.0), (400, 20.0, 10.0))
# PER FILE, judged on raw24 and n48d, from the 168-file control set of
# section 9. Ceilings seen there: raw24 11.5 and n48d 9.1 for files of 1,000
# tokens or more, raw24 6.5 and n48d 0.0 for files of 400 to 999. The limits
# are those ceilings with about a third of headroom, the same margin rule
# section 6 used. The 400 to 999 row keeps the original raw24 limit of 20.0
# rather than tightening to 8.7: in a file that small one matched 24-token
# run is already 6 percent, so the granularity, not the ceiling, sets it.
# The controls do NOT show the limit tightening as files grow; the ceiling
# rises with size for both measures, and the small-file row is looser only
# for that granularity reason.
JUDGED_FILE = ("raw24", "n48d")
FILE_LIMITS = ((1000, 15.0, 12.0), (400, 20.0, 16.0))
# Files under 400 tokens are too small to judge alone and count only toward
# the whole.
DONOR_REVS = ("4fe6ce7", "origin/master")
# WAIVERS. A file whose content a format or a public standard dictates can
# collide honestly and no honest limit clears it: RFC 7693's IV and SIGMA
# read raw24 83.5 in an unrelated crate. Such a file may carry a reviewed
# row in simscan-waivers.toml. A waiver is a claim somebody verified, not a
# mute button: a row whose file has gone, or whose file has drifted upward
# by more than its `step`, FAILS the run, and a row still awaiting a decision
# (`approved` beginning PENDING) waives nothing.
WAIVER_CLASSES = ("format-dictated-constants", "public-standard-kernel")
WAIVER_KEYS = ("path", "class", "source", "tokens", "raw24", "n48d", "step", "approved")
WAIVER_BASENAME = "simscan-waivers.toml"

KEEP = set("""as async await break const continue crate dyn else enum extern false fn for
if impl in let loop match mod move mut pub ref return self Self static struct super
trait true type unsafe use where while union macro_rules
u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize f32 f64 bool char str
auto case class default delete do double float goto inline int long namespace new
operator private protected public register short signed sizeof switch template this
throw try typedef typename unsigned virtual void volatile catch""".split())
IDKW = set(k.lower() for k in KEEP) | set(
    "vec option result string include define ifdef endif ifndef byte bytes".split())

TOKEN = re.compile(r"""
    (?P<com>/\*.*?\*/|//[^\n]*)
  | (?P<raw>b?r(?P<h>\#*)".*?"(?P=h))
  | (?P<str>b?"(?:[^"\\]|\\.)*")
  | (?P<chr>b?'(?:[^'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.))')
  | (?P<life>'[A-Za-z_]\w*)
  | (?P<num>\d\w*(?:\.\d\w*)?)
  | (?P<id>[A-Za-z_]\w*)
  | (?P<op><<=|>>=|\.\.\.|\.\.=|::|->|=>|==|!=|<=|>=|&&|\|\||\+=|-=|\*=|/=|%=|\^=|&=|\|=|<<|>>|\.\.)
  | (?P<p>[^\s\w])
""", re.S | re.X)
RENAME = re.compile(r"(?<![0-9A-Za-z_'])[A-Za-z_]\w*(?![#\"'\w])")
INT = re.compile(r"^(0x[0-9a-fA-F]+|0b[01]+|0o[0-7]+|\d+)(?![.eE\d])")


class Refusal(Exception):
    pass


def h64(text):
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8", "replace"),
                                          digest_size=8).digest(), "big", signed=True)


_tok_cache = {}


def tid(text):
    v = _tok_cache.get(text)
    if v is None:
        v = _tok_cache[text] = h64(text)
    return v


I_ID, L_ID = tid("\x00ident"), tid("\x00literal")


def rename_all(text):
    """The near-positive control: every identifier that is not kept becomes a
    mechanical new name. Comments and strings are mangled too, which is
    harmless: both are dropped or normalised before comparison."""
    names = {}

    def sub(m):
        w = m.group(0)
        if w in KEEP:
            return w
        return names.setdefault(w, "zz%dq" % len(names))
    return RENAME.sub(sub, text)


def tokenise(text):
    """-> (raw ids, normalised ids, ident strings, prose chunks, int runs)."""
    raw, norm, idents, prose, kinds = [], [], [], [], []
    for m in TOKEN.finditer(text):
        k = m.lastgroup
        s = m.group(0)
        if k == "com":
            prose.append(s)
            continue
        if k in ("raw", "str"):
            prose.append(s)
        if k == "h":
            k = "raw"
        raw.append(tid(s))
        if k in ("raw", "str", "chr", "num"):
            norm.append(L_ID)
        elif k == "id" and s not in KEEP:
            norm.append(I_ID)
            idents.append(s)
        else:
            norm.append(raw[-1])
        kinds.append((k, s))
    return raw, norm, idents, prose, kinds


def strip_tests(raw, norm, kinds):
    """Drop `#[cfg(test)] ... mod name { ... }` blocks, at token level."""
    keep = [True] * len(kinds)
    words = [s for _k, s in kinds]
    i, n = 0, len(words)
    while i < n - 7:
        if words[i:i + 7] == ["#", "[", "cfg", "(", "test", ")", "]"]:
            j = i + 7
            while j < n and words[j] == "#":          # further attributes
                depth = 0
                j += 1
                while j < n:
                    if words[j] == "[":
                        depth += 1
                    elif words[j] == "]":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
            if j < n and words[j] == "pub":
                j += 1
            if j + 2 < n and words[j] == "mod" and words[j + 2] == "{":
                depth, j = 0, j + 2
                while j < n:
                    if words[j] == "{":
                        depth += 1
                    elif words[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                for x in range(i, min(j + 1, n)):
                    keep[x] = False
                i = j + 1
                continue
        i += 1
    f = lambda seq: [v for v, ok in zip(seq, keep) if ok]
    return f(raw), f(norm), f(kinds)


def int_value(text):
    """An integer literal's value. Base 0 refuses a C octal literal (a leading
    zero, as in 0777), so read that as octal; a leading-zero run holding an 8 or
    a 9 is no octal and reads as decimal, and everything else keeps base 0."""
    if len(text) > 1 and text[0] == "0" and text[1].isdigit():
        return int(text, 8) if all(c in "01234567" for c in text) else int(text, 10)
    return int(text, 0)


def int_runs(kinds):
    runs, cur = [], []
    expect_num = True
    for k, s in kinds:
        if k == "num" and expect_num:
            m = INT.match(s.replace("_", ""))
            if m:
                cur.append(int_value(m.group(1)))
                expect_num = False
                continue
        elif s == "," and not expect_num:
            expect_num = True
            continue
        elif s == "-" and expect_num:
            continue
        if len(cur) >= 8:
            runs.append(cur)
        cur, expect_num = [], True
    if len(cur) >= 8:
        runs.append(cur)
    return runs


_words = None


def dictionary():
    global _words
    if _words is None:
        try:
            with open("/usr/share/dict/words") as fh:
                _words = set(w.strip().lower() for w in fh)
        except OSError:
            _words = set()
    return _words


def norm_idents(idents, use_dict=True):
    out = set()
    words = dictionary() if use_dict else set()
    for s in idents:
        k = s.replace("_", "").lower()
        if len(k) >= 5 and k not in IDKW and k not in words:
            out.add(k)
    return out


def word_grams(prose, n=8):
    out = set()
    for c in prose:
        w = re.findall(r"[a-z0-9]+", c.lower())
        for i in range(len(w) - n + 1):
            out.add(h64(" ".join(w[i:i + n])))
    return out


def source_files(roots, exts):
    out = []
    for root in roots:
        if os.path.isfile(root):
            out.append((os.path.basename(root), root))
            continue
        for d, _dirs, fs in os.walk(root):
            for f in fs:
                if f.endswith(exts):
                    p = os.path.join(d, f)
                    out.append((os.path.relpath(p, root), p))
    return sorted(out)


def read(path):
    with io.open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


PROBE = hash((1, 2, 3))


def build_index(roots, exts=(".rs", ".cpp", ".hpp", ".c", ".h")):
    """Reduce a reference tree to hashes. Nothing else of it is retained."""
    idx = {"probe": PROBE, "files": 0, "foreign": 0, "tokens": 0, "ids": set(), "grams": set(),
           "ints": set(), "runs": {(m, n): set() for m in ("raw", "norm") for n in NS}}
    for _rel, path in source_files(roots, exts):
        if not path.endswith(".rs"):
            idx["foreign"] += 1
        raw, norm, idents, prose, kinds = tokenise(read(path))
        idx["files"] += 1
        idx["tokens"] += len(raw)
        idx["ids"].update(h64(k) for k in norm_idents(idents, use_dict=False))
        idx["grams"] |= word_grams(prose)
        for run in int_runs(kinds):
            for i in range(len(run) - 7):
                idx["ints"].add(hash(tuple(run[i:i + 8])))
        for mode, seq in (("raw", raw), ("norm", norm)):
            for n in NS:
                dst = idx["runs"][(mode, n)]
                for i in range(len(seq) - n + 1):
                    dst.add(hash(tuple(seq[i:i + n])))
    if not idx["files"] or not idx["tokens"]:
        raise Refusal("the reference holds no source tokens: %s" % ", ".join(roots))
    return idx


def merge_index(a, b):
    a["files"] += b["files"]
    a["foreign"] = a.get("foreign", 0) + b.get("foreign", 0)
    a["tokens"] += b["tokens"]
    for k in ("ids", "grams", "ints"):
        a[k] |= b[k]
    for k in a["runs"]:
        a["runs"][k] |= b["runs"][k]
    return a


def covered(seq, n, refset, distinct=0):
    """Subject tokens lying inside a run of n that the reference also has.
    With `distinct` set, a window counts only when it holds at least that
    many different token values, which is what tells a copied function from
    a constant table in the normalised stream (see DISTINCT)."""
    diff = [0] * (len(seq) + 1)
    for i in range(len(seq) - n + 1):
        w = seq[i:i + n]
        if distinct and len(set(w)) < distinct:
            continue
        if hash(tuple(w)) in refset:
            diff[i] += 1
            diff[i + n] -= 1
    total = depth = 0
    for d in diff[:-1]:
        depth += d
        if depth > 0:
            total += 1
    return total


def scan_file(text, idx, keep_tests):
    raw, norm, idents, prose, kinds = tokenise(text)
    if not keep_tests:
        raw, norm, kinds = strip_tests(raw, norm, kinds)
        idents = [s for k, s in kinds if k == "id" and s not in KEEP]
    row = {"tokens": len(raw)}
    for mode, seq in (("raw", raw), ("norm", norm)):
        for n in NS:
            row["%s%d" % (mode, n)] = covered(seq, n, idx["runs"][(mode, n)])
    row["n48d"] = covered(norm, 48, idx["runs"][("norm", 48)], DISTINCT)
    ids = norm_idents(idents)
    row["ids"] = len(ids)
    row["ids_shared"] = sum(1 for k in ids if h64(k) in idx["ids"])
    row["grams_shared"] = len(word_grams(prose) & idx["grams"])
    runs = int_runs(kinds)
    row["int_runs"] = len(runs)
    row["int_runs_shared"] = sum(
        1 for r in runs
        if any(hash(tuple(r[i:i + 8])) in idx["ints"] for i in range(len(r) - 7)))
    return row


# A very small TOML reader, enough for an array of `[[waiver]]` tables whose
# values are one-line strings or numbers. This box's python is 3.9 and has no
# tomllib; pulling a dependency in for eight keys would be worse.
def parse_waivers(text, where):
    """-> (rows by path, root). `root` is where the paths are relative to,
    itself relative to the waiver file, and it is what lets the stale-row
    rule tell "this file is gone" from "this scan covered a subset"."""
    rows, cur, root = [], None, None
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[waiver]]":
            cur = {}
            rows.append(cur)
            continue
        if cur is None and line.startswith("root"):
            root = line.split("=", 1)[1].strip().strip('"')
            continue
        if cur is None:
            raise Refusal("%s:%d: a key outside any [[waiver]] table" % (where, n))
        if "=" not in line:
            raise Refusal("%s:%d: not a key = value line" % (where, n))
        key, val = (x.strip() for x in line.split("=", 1))
        if val.startswith('"'):
            end = val.find('"', 1)
            while end > 0 and val[end - 1] == "\\":
                end = val.find('"', end + 1)
            if end < 0:
                raise Refusal("%s:%d: unterminated string" % (where, n))
            cur[key] = val[1:end].replace('\\"', '"')
        else:
            val = val.split("#", 1)[0].strip()
            try:
                cur[key] = float(val) if ("." in val or "e" in val) else int(val)
            except ValueError:
                raise Refusal("%s:%d: value is neither a string nor a number" % (where, n))
    for i, w in enumerate(rows, 1):
        missing = [k for k in WAIVER_KEYS if k not in w]
        if missing:
            raise Refusal("%s: waiver %d is missing %s" % (where, i, ", ".join(missing)))
        if w["class"] not in WAIVER_CLASSES:
            raise Refusal("%s: waiver %d has class %r, not one of %s"
                          % (where, i, w["class"], ", ".join(WAIVER_CLASSES)))
        if not str(w["approved"]).strip():
            raise Refusal("%s: waiver %d has an empty `approved`" % (where, i))
    seen = set()
    for w in rows:
        if w["path"] in seen:
            raise Refusal("%s: two waivers for %s" % (where, w["path"]))
        seen.add(w["path"])
    if rows and not root:
        raise Refusal("%s: no `root` line, so there is no way to tell a deleted "
                      "file from one this scan did not cover" % where)
    return {w["path"]: w for w in rows}, root


def load_waivers(path):
    """Missing file, no waivers. Unreadable or malformed, refuse: failing to
    find is failing, and a waiver file that silently does not load would turn
    every waived file back into a FAIL with no explanation."""
    if not os.path.exists(path):
        return {}, None
    try:
        text = read(path)
    except OSError as e:
        raise Refusal("cannot read the waiver file %s: %s" % (path, e))
    rows, root = parse_waivers(text, path)
    if root:
        root = os.path.join(os.path.dirname(os.path.abspath(path)), root)
    return rows, root


def root_was_scanned(subjects, root):
    """True when the scan covered the whole tree the waiver paths hang off.
    A subset scan - someone scanning their own new files - must not be
    told that everybody else's waivers are stale."""
    if not root or not os.path.isdir(root):
        return False
    want = os.path.realpath(root)
    return any(os.path.isdir(x) and os.path.realpath(x) == want for x in subjects)


def waiver_active(w):
    """A row awaiting a decision waives nothing; it is recorded, not settled."""
    return not str(w["approved"]).strip().upper().startswith("PENDING")


# Work packages: table 1.1 of the plan. The "ours from birth" row is matched
# FIRST, because `codec/rar50/tree.rs` must not fall into `codec/rar50*`.
PACKAGES = [
    ("OURS. Already ours in full", """codec/address_filters.rs codec/rar13/*
        codec/rar50/tree.rs codec/rar50/probe_stats.rs codec/rar50/boundaries.rs
        codec/rar50/ratio* codec/match_index.rs rar50/blake2sp/many.rs
        rar50/blake2sp/simd.rs recovery/gf16_fold.rs recovery/workgauge.rs
        recovery/rar5/fold_team.rs crc32/pmull.rs memtrack.rs"""),
    ("A. Containers and the read API", """lib.rs error.rs detect.rs version.rs features.rs
        io_util.rs source.rs volume_extract.rs parallel.rs rar13.rs rar15_40.rs
        rar15_40/extract.rs rar50.rs rar50/extract.rs"""),
    ("B. Writers", "rar50/write/* rar15_40/write.rs write_progress.rs write_entropy.rs"),
    ("C. LZ codecs", """codec/rar20.rs codec/rar29.rs codec/rar50.rs codec/huffman.rs
        codec/filters.rs codec/fast.rs codec/mod.rs x86_filter_scan.rs"""),
    ("D. PPMd", "codec/ppmd.rs"),
    ("E. RAR 3 filter VM", "codec/rarvm.rs"),
    ("F. Crypto", "crypto/*"),
    ("G. Recovery, CRC, BLAKE2sp shell", """recovery/rar5.rs recovery/rar3.rs recovery/mod.rs
        recovery/stream.rs crc32/mod.rs rar50/blake2sp/mod.rs rar50/blake2sp/portable.rs"""),
]
UNLISTED = "Z. Not in table 1.1"


def package_of(rel):
    rel = rel.replace(os.sep, "/")
    if "/src/" in "/" + rel:
        rel = ("/" + rel).split("/src/", 1)[1]
    for name, pats in PACKAGES:
        if any(fnmatch.fnmatchcase(rel, p) for p in pats.split()):
            return name
    return UNLISTED


def pct(a, b):
    return 100.0 * a / b if b else 0.0


class Out(object):
    """Every output line passes here. A line carrying an identifier that the
    reference has, and that is neither the tool's own vocabulary nor part of
    a subject path, is refused: names and counts only."""

    def __init__(self, idx, allowed_text, stream=None):
        self.idx = idx
        self.stream = stream or sys.stdout
        self.allowed = set(re.findall(r"[A-Za-z_]\w*", allowed_text))
        self.lines = []

    def emit(self, line):
        for w in re.findall(r"[A-Za-z_]\w*", line):
            if w in self.allowed:
                continue
            k = w.replace("_", "").lower()
            if len(k) >= 5 and k not in IDKW and h64(k) in self.idx["ids"]:
                raise Refusal("output guard: a line was about to carry a reference "
                              "identifier; nothing of that line was printed")
        self.lines.append(line)
        self.stream.write(line + "\n")


VOCAB = """file files tokens raw norm ids shared grams ints runs total TOTAL PASS FAIL label
subject reference package threshold judged normalised coverage covered percent floor
index saved refused small below above limit whole verdict against count counts names
int_runs int_runs_shared ids_shared grams_shared raw24 norm48 n48d note limits by and
waiver waivers waived pending stale rose recorded step class awaits decision names no such
outlives what it was written for only mistake see clear each drifted format dictated
constants public standard kernel toml simscan its own
outside this whether is of the scan tree points at"""


def report(rows, out, label, per_file, packages, judge, calibrated=True, waivers=None,
           root_scanned=False):
    waivers = waivers or {}
    cols = ["%s%d" % (m, n) for m in ("raw", "norm") for n in NS] + ["n48d"]
    head = "%-44s %8s " % ("file", "tokens") + " ".join("%6s" % c for c in cols) + \
        " %5s %6s %5s %4s" % ("ids", "shared", "grams", "ints")

    def line(name, r):
        return "%-44s %8d " % (name[-44:], r["tokens"]) + \
            " ".join("%6.1f" % pct(r[c], r["tokens"]) for c in cols) + \
            " %5d %6d %5d %4d" % (r["ids"], r["ids_shared"], r["grams_shared"],
                                  r["int_runs_shared"])

    def total(items):
        t = collections.Counter()
        for r in items:
            t.update(r)
        return t
    out.emit("label %s: %d files, percent of tokens covered by a shared run" % (label, len(rows)))
    out.emit(head)
    if per_file:
        for rel in sorted(rows):
            out.emit(line(rel, rows[rel]))
    if packages:
        groups = collections.defaultdict(list)
        for rel, r in rows.items():
            groups[package_of(rel)].append(r)
        for name in sorted(groups):
            out.emit(line("%s (%d files)" % (name, len(groups[name])), total(groups[name])))
    tot = total(rows.values())
    out.emit(line("TOTAL", tot))
    if not judge:
        return 0
    if not calibrated:
        out.emit("not calibrated: the limits were set for Rust against Rust and do "
                 "not hold across languages; the scores above are a report, and "
                 "there is no PASS or FAIL for label %s" % label)
        return 0

    def verdict_of(r, limits, judged):
        for floor, a_max, b_max in limits:
            if r["tokens"] >= floor:
                return (pct(r[judged[0]], r["tokens"]) > a_max or
                        pct(r[judged[1]], r["tokens"]) > b_max)
        return False

    def scores(rel, r):
        return "tokens %d %s %.1f %s %.1f" % (
            r["tokens"], JUDGED_FILE[0], pct(r[JUDGED_FILE[0]], r["tokens"]),
            JUDGED_FILE[1], pct(r[JUDGED_FILE[1]], r["tokens"]))
    out.emit("judged: whole subject on %s and %s, each file on %s and %s; limits by "
             "tokens: whole %s, file %s"
             % (JUDGED_WHOLE[0], JUDGED_WHOLE[1], JUDGED_FILE[0], JUDGED_FILE[1],
                WHOLE_LIMITS, FILE_LIMITS))
    over = sorted(rel for rel, r in rows.items() if verdict_of(r, FILE_LIMITS, JUDGED_FILE))
    bad, waived, pending = [], [], []
    for rel in over:
        w = waivers.get(rel)
        if w is None:
            bad.append(rel)
        elif waiver_active(w):
            waived.append(rel)
        else:
            pending.append(rel)
    # A WAIVER IS A CLAIM SOMEBODY VERIFIED, NOT A MUTE BUTTON. Two rules hold
    # that, and neither can be satisfied by editing the gate: a row whose file
    # has gone fails, and a row whose file has drifted upward past its own
    # recorded step fails, waived or not.
    absent = sorted(path for path in waivers if path not in rows)
    stale = absent if root_scanned else []
    risen = []
    for path in sorted(waivers):
        r = rows.get(path)
        if r is None:
            continue
        w = waivers[path]
        for k in JUDGED_FILE:
            now, then, step = pct(r[k], r["tokens"]), float(w[k]), float(w["step"])
            if now > then + step:
                risen.append((path, k, then, step, now))
    for rel in waived:
        out.emit("waived file %s class %s %s (see %s)"
                 % (rel, waivers[rel]["class"], scores(rel, rows[rel]), WAIVER_BASENAME))
    for rel in pending:
        out.emit("FAIL file %s %s: its waiver awaits a decision and waives nothing"
                 % (rel, scores(rel, rows[rel])))
    for rel in bad:
        out.emit("FAIL file %s %s" % (rel, scores(rel, rows[rel])))
    for path in stale:
        out.emit("FAIL waiver %s names no file in the tree it points at: a waiver "
                 "outlives what it was written for only by mistake" % path)
    if not root_scanned:
        for path in absent:
            out.emit("note waiver %s is outside this subject; whether it is stale is "
                     "judged only by a scan of the whole tree it points at" % path)
    for path, k, then, step, now in risen:
        out.emit("FAIL waiver %s rose on %s: recorded %.1f, step %.1f, now %.1f"
                 % (path, k, then, step, now))
    # The whole-subject limit takes NO waivers.
    whole_bad = verdict_of(tot, WHOLE_LIMITS, JUDGED_WHOLE)
    if whole_bad:
        out.emit("FAIL whole subject (no waiver may clear it)")
    for rel in sorted(rows):
        r = rows[rel]
        if r["int_runs_shared"] or r["grams_shared"]:
            out.emit("note file %s shared ints %d grams %d" % (
                rel, r["int_runs_shared"], r["grams_shared"]))
    failed = bool(bad or pending or stale or risen) or whole_bad
    out.emit("verdict %s: %s" % (label, "FAIL" if failed else "PASS"))
    return 1 if failed else 0


def donor_index(repo, subdir):
    repo = os.path.expanduser(repo)
    if not os.path.isdir(repo):
        raise Refusal("no donor repository at %s (give --donor-repo, or use "
                      "--reference-index with a saved index)" % repo)
    subdirs = [d for d in re.split(r"[,\s]+", subdir or "") if d]
    if not subdirs:
        raise Refusal("--reference-set donor needs --donor-subdir, the directory "
                      "inside the donor repository that holds its source "
                      "(several, separated by commas, are read as one reference)")
    idx = None
    for rev in DONOR_REVS:
        tmp = tempfile.mkdtemp(prefix="simscan-ref-")
        try:
            ar = subprocess.Popen(["git", "-C", repo, "archive", rev] + subdirs,
                                  stdout=subprocess.PIPE)
            tar = subprocess.Popen(["tar", "-x", "-C", tmp], stdin=ar.stdout)
            ar.stdout.close()
            if tar.wait() or ar.wait():
                raise Refusal("git archive %s failed in %s" % (rev, repo))
            # A directory the revision lacks must refuse, not shrink the
            # reference without a word.
            for d in subdirs:
                if not os.path.isdir(os.path.join(tmp, d)):
                    raise Refusal("%s has no %s in %s" % (rev, d, repo))
            one = build_index([tmp])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        idx = one if idx is None else merge_index(idx, one)
    return idx


def load_index(path):
    with open(path, "rb") as fh:
        idx = pickle.load(fh)
    if idx.get("probe") != PROBE:
        raise Refusal("the index at %s was built by a python whose tuple hash "
                      "differs from this one; rebuild it" % path)
    return idx


def run(args, stream=None):
    if args.reference_index:
        idx = load_index(args.reference_index)
    elif args.reference_set == "donor":
        idx = donor_index(args.donor_repo, args.donor_subdir)
    elif args.reference_set == "unrar":
        if not args.unrar_src:
            raise Refusal("--reference-set unrar needs --unrar-src <path>; this tool "
                          "never fetches UnRAR source")
        idx = build_index([args.unrar_src])
    elif args.reference:
        idx = build_index(args.reference)
    else:
        raise Refusal("no reference given")
    if args.save_index:
        with open(args.save_index, "wb") as fh:
            pickle.dump(idx, fh, protocol=4)
    waivers, wroot = ({}, None) if args.no_waivers else load_waivers(args.waivers)
    # A waiver's path names a file in OUR tree, checked in beside this tool, so
    # it is exactly as safe to print as a subject path and joins the same set.
    out = Out(idx, VOCAB + " " + " ".join(args.subject or []) + " " + args.label
              + " " + " ".join(waivers), stream)
    if not args.subject:
        out.emit("index saved: %d files, %d tokens" % (idx["files"], idx["tokens"]))
        return 0
    files = source_files(args.subject, (".rs",))
    if not args.keep_tests:
        files = [(rel, p) for rel, p in files
                 if not re.search(r"(^|[/_])tests?\.rs$", rel.replace(os.sep, "/"))]
    if not files:
        raise Refusal("no .rs files under the subject")
    out.allowed.update(w for rel, _p in files for w in re.findall(r"[A-Za-z_]\w*", rel))
    for name in [n for n, _pats in PACKAGES] + [UNLISTED]:
        out.allowed.update(re.findall(r"[A-Za-z_]\w*", name))
    rows = {}
    for rel, path in files:
        text = read(path)
        if args.rename_subject:
            text = rename_all(text)
        rows[rel] = scan_file(text, idx, args.keep_tests)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"label": args.label, "reference_files": idx["files"],
                       "reference_tokens": idx["tokens"], "files": rows}, fh, indent=1,
                      sort_keys=True)
    judge = bool(args.reference_set or args.reference_index) or args.judge
    return report(rows, out, args.label, args.per_file or judge, args.packages, judge,
                  not idx.get("foreign"), waivers, root_was_scanned(args.subject, wroot))


def parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--subject", nargs="+")
    ap.add_argument("--reference", nargs="+")
    ap.add_argument("--reference-set", choices=("donor", "unrar"))
    ap.add_argument("--reference-index")
    ap.add_argument("--save-index")
    ap.add_argument("--donor-repo", default=os.environ.get("SIMSCAN_DONOR_REPO", ""))
    ap.add_argument("--donor-subdir", default=os.environ.get("SIMSCAN_DONOR_SUBDIR", ""))
    ap.add_argument("--unrar-src")
    ap.add_argument("--label", default="scan")
    ap.add_argument("--json", help="write per-file counts here")
    ap.add_argument("--per-file", action="store_true")
    ap.add_argument("--packages", action="store_true", help="totals per plan table 1.1")
    ap.add_argument("--judge", action="store_true")
    ap.add_argument("--keep-tests", action="store_true")
    ap.add_argument("--rename-subject", action="store_true",
                    help="near-positive control: rename every identifier first")
    ap.add_argument("--waivers", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), WAIVER_BASENAME),
        help="reviewed rows for files a format or a public standard dictates")
    ap.add_argument("--no-waivers", action="store_true",
                    help="judge every file on the limits alone")
    ap.add_argument("--selftest", action="store_true")
    return ap


def selftest():
    fails = []

    def check(name, ok):
        if not ok:
            fails.append(name)
    marks = ["zqmark%02dalpha" % i for i in range(40)]
    body = "\n".join("fn %s(%s: u32) -> u32 { let %s = %s * 3 + 1; %s ^ 0x5a }"
                     % (marks[i], marks[i + 1], marks[i + 2], marks[i + 1], marks[i + 2])
                     for i in range(0, 36))
    table = "const %s: [u16; 10] = [11, 23, 35, 47, 59, 61, 73, 85, 97, 109];" % marks[38]
    # Two UNRELATED constant tables, sharing no value. Normalised they are both
    # `L , L , L ...` and collide completely; that is the saturation DISTINCT
    # exists to drop. The values avoid any number this tool prints.
    ref_table = "const %s: [u32; 120] = [%s];" % (
        marks[39], ", ".join(str(700003 + 7 * i) for i in range(120)))
    sub_table = "const qzzplain: [u32; 120] = [%s];" % (
        ", ".join(str(910007 + 11 * i) for i in range(120)))
    prose = "// the quick marker walks nine separate words past this lazy point\n"
    ours = "\n".join("pub fn plain%d(a: &[u8]) -> usize { a.iter().filter(|b| **b == %d).count() }"
                     % (i, i) for i in range(30))
    tmp = tempfile.mkdtemp(prefix="simscan-selftest-")
    try:
        ref, sub = os.path.join(tmp, "ref"), os.path.join(tmp, "sub")
        os.makedirs(ref)
        os.makedirs(os.path.join(sub, "codec"))
        with open(os.path.join(ref, "lib.rs"), "w") as fh:
            fh.write(prose + body + "\n" + table + "\n")
        with open(os.path.join(ref, "consts.rs"), "w") as fh:
            fh.write(ref_table + "\n")
        with open(os.path.join(sub, "codec", "ppmd.rs"), "w") as fh:     # a copy
            fh.write(prose + body + "\n" + table + "\n#[cfg(test)]\nmod t { fn x() {} }\n")
        with open(os.path.join(sub, "memtrack.rs"), "w") as fh:          # unrelated
            fh.write(ours + "\n")
        with open(os.path.join(sub, "lib.rs"), "w") as fh:               # renamed copy
            fh.write(rename_all(body) + "\n")
        with open(os.path.join(sub, "consts.rs"), "w") as fh:            # unrelated table
            fh.write(sub_table + "\n")
        sub2 = os.path.join(tmp, "sub2")
        os.makedirs(os.path.join(sub2, "codec"))
        with open(os.path.join(sub2, "codec", "ppmd.rs"), "w") as fh:    # the same copy
            fh.write(prose + body + "\n" + table + "\n")
        with open(os.path.join(sub2, "filler.rs"), "w") as fh:           # unrelated bulk
            fh.write("\n".join(
                "pub fn plain%d(a: &[u8]) -> usize { a.iter().filter(|b| **b == %d).count() }"
                % (i, i % 251) for i in range(1400)) + "\n")
        index = os.path.join(tmp, "ref.idx")
        js = os.path.join(tmp, "out.json")
        captured = []
        for extra in (["--reference", ref, "--per-file", "--packages", "--judge",
                       "--json", js, "--save-index", index],
                      ["--reference-index", index],
                      ["--reference", ref, "--rename-subject", "--per-file"]):
            buf = io.StringIO()
            code = run(parser().parse_args(["--subject", sub, "--label", "st",
                                            "--no-waivers"] + extra), buf)
            captured.append((code, buf.getvalue()))
        rows = json.load(open(js))["files"]
        copy, clean, ren = rows["codec/ppmd.rs"], rows["memtrack.rs"], rows["lib.rs"]
        tbl = rows["consts.rs"]
        check("a copy reads ~100% raw", pct(copy["raw24"], copy["tokens"]) > 95)
        check("test block stripped", copy["tokens"] < 36 * 23 + 40)
        check("a copy shares its comment grams", copy["grams_shared"] >= 1)
        check("a copy shares its int run", copy["int_runs_shared"] == 1)
        check("unrelated code reads 0 at N=16", clean["norm16"] == 0 and clean["raw8"] == 0)
        check("a rename drops raw", pct(ren["raw8"], ren["tokens"]) < 40)
        check("a rename keeps normalised", pct(ren["norm24"], ren["tokens"]) > 95)
        check("judge fails the copy", captured[0][0] == 1 and captured[1][0] == 1)
        check("index round-trips", captured[0][1].split("judged")[1] ==
              captured[1][1].split("judged")[1])
        # THE NO-ECHO PROPERTY: no output carries a run of reference tokens.
        ref_words = []
        for _rel, _rp in source_files([ref], (".rs",)):
            ref_words += [s for _k, s in tokenise(read(_rp))[4]]
        ref_runs = set(tuple(ref_words[i:i + 3]) for i in range(len(ref_words) - 2))

        def leaks(text):
            for ln in text.splitlines():
                w = [s for _k, s in tokenise(ln)[4]]
                if any(tuple(w[i:i + 3]) in ref_runs for i in range(len(w) - 2)):
                    return True
                if any(m in ln for m in marks):
                    return True
            return False
        everything = "".join(t for _c, t in captured) + read(js)
        check("no output line carries a reference token run", not leaks(everything))
        check("the leak detector detects", leaks("x " + " ".join(ref_words[5:9])))
        idx = load_index(index)
        try:
            Out(idx, VOCAB, io.StringIO()).emit("file %s 3" % marks[3])
            check("the output guard refuses a reference identifier", False)
        except Refusal:
            pass
        try:
            os.makedirs(os.path.join(tmp, "empty"))
            build_index([os.path.join(tmp, "empty")])
            check("an empty reference refuses", False)
        except Refusal:
            pass
        toks = [s for _k, s in tokenise("let a = r#\"x // y\"#; /* c */ 'a' <'b> 0x1f_u8..=9")[4]]
        check("tokeniser", toks == ["let", "a", "=", "r#\"x // y\"#", ";", "'a'", "<", "'b",
                                    ">", "0x1f_u8", "..=", "9"])
        # C octal literals (base 0 refuses them) and the report-only mode for a
        # reference that is not Rust. The C source is synthetic, written here.
        check("int_value reads C octal", int_value("0777") == 511 and int_value("010") == 8
              and int_value("0") == 0 and int_value("0x1f") == 31 and int_value("09") == 9)
        cref = os.path.join(tmp, "cref")
        os.makedirs(cref)
        with open(os.path.join(cref, "t.cpp"), "w") as fh:
            fh.write("static const int qoct[] = {0777, 0644, 010, 0, 07, 0100, 0755, 0600, 3};\n"
                     "int qfn(int a) { return a + 1; }\n")
        try:
            cidx = build_index([cref])
            check("a C octal table builds an index", cidx["foreign"] == 1)
        except ValueError:
            check("a C octal table builds an index", False)
            cidx = None
        if cidx:
            check("the octal run is indexed", len(cidx["ints"]) == 2)
            buf = io.StringIO()
            bad = os.path.join(tmp, "cindex.idx")
            with open(bad, "wb") as fh:
                pickle.dump(cidx, fh, protocol=4)
            code = run(parser().parse_args(["--subject", sub, "--label", "st",
                                            "--reference-index", bad]), buf)
            check("a non-Rust reference is report-only",
                  code == 0 and "not calibrated" in buf.getvalue()
                  and "FAIL" not in buf.getvalue().replace("no PASS or FAIL", ""))
        # DISTINCT: the normalised measure saturates on a constant table, the
        # distinctness filter drops it, and a renamed copy survives both.
        check("a constant table saturates norm48", pct(tbl["norm48"], tbl["tokens"]) > 90)
        check("the distinctness filter clears a constant table", tbl["n48d"] == 0)
        check("a constant table shares no raw text", tbl["raw24"] == 0)
        check("a rename keeps n48d", pct(ren["n48d"], ren["tokens"]) > 90)

        # WAIVERS. In sub2 exactly one file trips the per-file limits and the
        # whole subject passes, so a waiver can be seen to clear the run.
        js2 = os.path.join(tmp, "out2.json")
        buf = io.StringIO()
        base = run(parser().parse_args(["--subject", sub2, "--label", "st2", "--json", js2,
                                        "--reference-index", index, "--no-waivers"]), buf)
        rows2 = json.load(open(js2))["files"]
        check("without a waiver the copy fails", base == 1)
        check("the whole subject of sub2 passes", "FAIL whole" not in buf.getvalue())

        def go(waivers=None, subject=None):
            b = io.StringIO()
            a = ["--subject", subject or sub2, "--label", "st2", "--reference-index", index]
            a += ["--waivers", waivers] if waivers else ["--no-waivers"]
            return run(parser().parse_args(a), b), b.getvalue()

        def row_text(rel, src=None, **kw):
            r = (src or rows2)[rel]
            row = {"path": rel, "class": "public-standard-kernel", "source": "synthetic",
                   "tokens": r["tokens"], "raw24": round(pct(r["raw24"], r["tokens"]), 1),
                   "n48d": round(pct(r["n48d"], r["tokens"]), 1), "step": 2.0,
                   "approved": "selftest"}
            row.update(kw)
            return "[[waiver]]\n" + "".join(
                "%s = %s\n" % (k, '"%s"' % v if isinstance(v, str) else v)
                for k, v in row.items())

        def wfile(name, body, root="sub2"):
            path = os.path.join(tmp, name)
            with open(path, "w") as fh:
                fh.write('root = "%s"\n' % root + body)
            return path
        code, text = go(wfile("w_ok.toml", row_text("codec/ppmd.rs")))
        check("an approved waiver clears its file", code == 0 and "waived file" in text)
        code, text = go(wfile("w_pending.toml",
                              row_text("codec/ppmd.rs", approved="PENDING counsel")))
        check("a pending waiver waives nothing", code == 1 and "awaits a decision" in text)
        code, text = go(wfile("w_gone.toml", row_text("codec/ppmd.rs")
                              + row_text("codec/ppmd.rs", path="codec/qzzabsent.rs")))
        check("a waiver naming no file in the subject fails",
              code == 1 and "names no file" in text)
        code, text = go(wfile("w_rose.toml",
                              row_text("codec/ppmd.rs", raw24=0.0, n48d=0.0, step=1.0)))
        check("a waiver whose file rose past its step fails",
              code == 1 and "rose on" in text)
        code, text = go(wfile("w_all.toml", "".join(row_text(rel, src=rows, step=100.0)
                                                    for rel in sorted(rows)), "sub"), sub)
        check("the whole-subject limit takes no waiver",
              code == 1 and "FAIL whole subject" in text)

        def refuses(name, body, root="sub2"):
            try:
                load_waivers(wfile(name, body, root))
                return False
            except Refusal:
                return True
        one = row_text("codec/ppmd.rs")
        check("an unknown waiver class refuses",
              refuses("w1.toml", one.replace("public-standard-kernel", "because-i-said-so")))
        check("a waiver missing a key refuses",
              refuses("w2.toml", '[[waiver]]\npath = "a.rs"\nclass = "public-standard-kernel"\n'))
        check("two waivers for one path refuse", refuses("w3.toml", one + one))
        check("a key outside any waiver table refuses", refuses("w4.toml", 'path = "a.rs"\n'))
        check("an empty approval refuses",
              refuses("w5.toml", one.replace('approved = "selftest"', 'approved = "  "')))
        check("a missing waiver file means no waivers",
              load_waivers(os.path.join(tmp, "qzznosuch.toml")) == ({}, None))
        noroot = os.path.join(tmp, "w7.toml")
        with open(noroot, "w") as fh:
            fh.write(one)
        try:
            load_waivers(noroot)
            check("a waiver file with no root refuses", False)
        except Refusal:
            pass
        # A SUBSET scan must not call everybody else's waivers stale: here the
        # root points at a tree this scan did not cover.
        code, text = go(wfile("w_subset.toml", row_text("codec/ppmd.rs")
                              + row_text("codec/ppmd.rs", path="codec/qzzelsewhere.rs"),
                              "sub"))
        check("a subset scan does not judge a waiver it did not cover",
              "FAIL waiver" not in text and "note waiver" in text)
        check("a comment and a blank line are skipped",
              len(load_waivers(wfile("w6.toml", "# a note\n\n" + one))[0]) == 1)
        check("the root is read and resolved beside the waiver file",
              load_waivers(wfile("w8.toml", one))[1] == os.path.join(tmp, "sub2"))
        check("package map", package_of("crates/x/src/codec/rar50/tree.rs").startswith("OURS")
              and package_of("codec/rar50.rs").startswith("C.")
              and package_of("recovery/rar5/fold_team.rs").startswith("OURS")
              and package_of("recovery/rar5.rs").startswith("G."))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in fails:
        print("selftest FAIL: %s" % f)
    print("selftest: %d failure(s)" % len(fails))
    return 1 if fails else 0


def main():
    args = parser().parse_args()
    if args.selftest:
        return selftest()
    try:
        return run(args)
    except Refusal as e:
        print("REFUSED: %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
