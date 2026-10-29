#!/usr/bin/env python3
"""Records what reference rar and unrar 7.23 print for every cell of
`tests/parity_land3.rs`, into
`cells.rs` beside this file, which the test includes.

Each cell runs in a scratch directory holding its group's files under
their own names, so the names the reference prints are the ones rarfast
will. The reference's logo is dropped (rarfast prints none): unrar's
`UNRAR 7.23 freeware` line, rar's `RAR 7.23` line and the unregistered
copy's `Trial version` and `Evaluation copy` lines. A cell keeps the exit
code, stderr whole, stdout whole or, for `p`, whose stdout is the payload,
its length and CRC32, and every file the run left that was not staged,
with its length (a `.rar` a creating command wrote is kept by name only:
two encoders do not write the same bytes).

    RARBIN=/path/to/rar UNRARBIN=/path/to/unrar python3 capture.py [OUT]

OUT defaults to `cells.rs` here; a capture on another machine is written
elsewhere and compared with it.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
TOOLS = {
    "rar": os.environ.get("RARBIN", "rar"),
    "unrar": os.environ.get("UNRARBIN", "unrar"),
}


def vec(name):
    return os.path.join(ROOT, "specs", "vectors-G", "archives", name)


def leftover(name):
    return os.path.join(ROOT, "crates", "rarkit-cli", "tests", "parity-leftovers", name)


def here(name):
    return os.path.join(HERE, name)


def legacy(name):
    return os.path.join(ROOT, "fixtures", "legacy", "archives", name)


def parts(at, stem, n):
    return [at("%s.part%d.rar" % (stem, i)) for i in range(1, n + 1)]


# A group's files: a path is copied under its own name; ("name", bytes) is
# written; ("name", src, offset, mask) is `src` with one byte inverted;
# ("name", src, "cut", length) is `src` cut to `length` bytes; ("name",
# bytes, "locked") is written and then made unreadable (mode 000). The
# test stages every group the same way.
GROUPS = {
    "store": [vec("r5_store.rar")],
    "flip": [("flip.rar", vec("r5_store.rar"), 60, 0x55)],
    "files": [
        ("f.txt", b"hello\n"),
        ("g.txt", b"world\n"),
        ("locked.txt", b"x\n", "locked"),
        ("arc.rar", vec("r5_store.rar"), "cut", None),
        ("cmt.rar", vec("r5_cmt.rar"), "cut", None),
    ],
    "two": parts(leftover, "two", 4),
    "twoc": parts(leftover, "twoc", 4),
    "twop": parts(leftover, "twop", 4),
    "r5_vol": parts(vec, "r5_vol", 4),
    "r4_vol": parts(vec, "r4_vol", 3),
    "r4_volvn": [vec("r4_volvn.rar"), vec("r4_volvn.r00"), vec("r4_volvn.r01")],
    "s9k": parts(here, "s9k", 6),
    "qo3": parts(here, "qo3", 3),
    "tail9k": parts(here, "tail9k", 5),
    "mixsc": parts(here, "mixsc", 4),
    "mixcs": parts(here, "mixcs", 4),
    # rar 4.20's `-hp` archive with one byte of its SECOND member's
    # enciphered header inverted: the walk reads the first member and
    # stops (land 2's `r420_dmg`).
    "r420_dmg": [("r420_dmg.rar", legacy("r420_hp.rar"), 21290, 0x55)],
    # Cut short: a RAR 5 archive inside its first member's data and inside
    # its second header, rar 4.20's inside its first member's data.
    "cut5d": [("cut.rar", vec("r5_store.rar"), "cut", 200)],
    "cut5h": [("cut.rar", vec("r5_store.rar"), "cut", 380)],
    "cut4d": [
        (
            "cut.rar",
            os.path.join(ROOT, "specs", "vectors-J", "archives", "r420_mixed_nonsolid.rar"),
            "cut",
            3000,
        )
    ],
}

CAPTURES = []


def cells(tool, group, commands, switch_sets):
    for command in commands:
        for switches in switch_sets:
            CAPTURES.append((tool, group, command[0], switches, command[1:]))


# Item 3: -inul is the third member of the -idq / -ierr last-wins set.
ORDERS = [
    ["-inul", "-ierr"],
    ["-ierr", "-inul"],
    ["-inul", "-idq"],
    ["-idq", "-inul"],
    ["-idq", "-ierr"],
    ["-ierr", "-idq"],
]
for group, archive in [("store", "r5_store.rar"), ("flip", "flip.rar")]:
    cells(
        "unrar",
        group,
        [["t", archive], ["p", archive], ["l", archive], ["x", archive, "out/"]],
        ORDERS,
    )
cells(
    "rar",
    "files",
    [
        ["l", "arc.rar"],
        ["a", "-m0", "new.rar", "f.txt"],
    ],
    ORDERS,
)

# Item 2: the creator's `Cannot open` and `Cannot create`, and what the run
# around them prints: every creator command over an archive that is not
# there, and the creates and edits that complain once or twice.
PLAIN = [[], ["-idq"], ["-ierr"]]
cells(
    "rar",
    "files",
    [[c, "nosuch.rar"] for c in ["c", "ch", "d", "k", "r", "rc", "rr", "rv1", "s", "s-"]]
    + [
        ["rn", "nosuch.rar", "f.txt", "h.txt"],
        ["cw", "nosuch.rar", "c.txt"],
        ["u", "nosuch.rar", "nosuch.txt"],
        ["f", "nosuch.rar", "f.txt"],
        ["a", "-m0", "new.rar", "nosuch.txt"],
        ["a", "-m0", "new.rar", "nosuch.txt", "other.txt"],
        ["a", "-m0", "new.rar", "f.txt", "nosuch.txt"],
        ["a", "-m0", "new.rar", "locked.txt"],
        ["a", "-m0", "new.rar", "f.txt", "locked.txt"],
        ["a", "-m0", "new.rar", "locked.txt", "nosuch.txt"],
        ["a", "-m0", "-znosuch.txt", "new.rar", "f.txt"],
        ["a", "-m0", "nodir/new.rar", "f.txt"],
        ["m", "-m0", "new.rar", "f.txt", "nosuch.txt"],
        ["c", "-znosuch.txt", "arc.rar"],
        ["cw", "cmt.rar", "nodir/c.txt"],
        ["cw", "cmt.rar", "nodir/sub/c.txt"],
        ["a", "-m0", "-zg.txt", "new.rar", "f.txt"],
        ["u", "-m0", "arc.rar", "nosuch.txt"],
    ],
    PLAIN,
)
cells(
    "rar",
    "files",
    [["a", "-m0", "nodir/new.rar", "f.txt"]],
    ORDERS,
)

# Item 1: the counter over a volume set, and over an archive whose walk a
# damaged header stopped. Exact counters, stderr under -ierr.
SETS = [
    ("two", "two.part1.rar", []),
    ("twoc", "twoc.part1.rar", []),
    ("twop", "twop.part1.rar", ["-psecret"]),
    ("r5_vol", "r5_vol.part1.rar", []),
    ("r4_vol", "r4_vol.part1.rar", []),
    ("r4_volvn", "r4_volvn.rar", []),
    ("s9k", "s9k.part1.rar", []),
    ("qo3", "qo3.part1.rar", []),
    ("tail9k", "tail9k.part1.rar", []),
    ("r420_dmg", "r420_dmg.rar", ["-pSecret"]),
]
for group, first, password in SETS:
    for command in ["t", "x", "p"]:
        rest = [first] + (["out/"] if command == "x" else [])
        CAPTURES.append(("unrar", group, command, password + ["-ierr"], rest))
for group, first, password in SETS[:1] + SETS[6:7]:
    CAPTURES.append(("unrar", group, "t", password, [first]))

# Item 6's layout: where a walk ends, `Unexpected end of archive`, plain,
# -idq and on one stream.
for group in ["cut5d", "cut5h", "cut4d"]:
    for command in ["t", "x", "l", "lt", "lb", "v"]:
        rest = ["cut.rar"] + (["out/"] if command == "x" else [])
        for switches in PLAIN:
            CAPTURES.append(("unrar", group, command, switches, rest))

# Item 5: -idn (and -idc, -idp beside it) over a sound archive, a damaged
# one, volume sets, and a set whose every member is refused for its
# password.
IDN = [["-idn"], ["-idn", "-ierr"], ["-idc"], ["-idp"]]
for group, first, password in [
    ("store", "r5_store.rar", []),
    ("flip", "flip.rar", []),
    ("two", "two.part1.rar", []),
    ("twop", "twop.part1.rar", ["-pwrong"]),
    ("twop", "twop.part1.rar", ["-psecret"]),
    ("r5_vol", "r5_vol.part1.rar", []),
]:
    for command in ["t", "x", "p", "l"]:
        rest = [first] + (["out/"] if command == "x" else [])
        for switches in IDN:
            CAPTURES.append(("unrar", group, command, password + switches, rest))

# Item 4: which volume the walk starts at and which banners it says, over
# four-part sets whose second member starts in the third volume, stored
# or compressed: no mask, the first member, the second, from the first,
# second and third volume.
for group, first_member, second_member in [
    ("two", "a.bin", "b.bin"),
    ("twoc", "a.bin", "b.bin"),
    ("mixsc", "a.dat", "b.bin"),
    ("mixcs", "a.bin", "b.dat"),
]:
    for volume in [1, 2, 3]:
        archive = "%s.part%d.rar" % (group, volume)
        for select in [[], [first_member], [second_member]]:
            for command in ["t", "x", "p"]:
                rest = [archive] + select + (["out/"] if command == "x" else [])
                for switches in [[], ["-ierr"]]:
                    if command == "p" and not switches:
                        continue
                    CAPTURES.append(("unrar", group, command, switches, rest))


def stage(work, group):
    for f in GROUPS[group]:
        if isinstance(f, str):
            shutil.copy(f, work)
            continue
        name = f[0]
        if len(f) == 2:
            data = f[1]
        elif f[2] == "locked":
            data = f[1]
        elif f[2] == "cut":
            data = open(f[1], "rb").read()
            if f[3] is not None:
                data = data[: f[3]]
        else:
            data = bytearray(open(f[1], "rb").read())
            data[f[2]] ^= f[3]
            data = bytes(data)
        path = os.path.join(work, name)
        open(path, "wb").write(data)
        if len(f) == 3 and f[2] == "locked":
            os.chmod(path, 0)


LOGOS = [
    rb"\nUNRAR 7\.23 freeware[^\n]*\n",
    rb"\nRAR 7\.23 [^\n]*\n",
    rb"Trial version[^\n]*\n",
]


def unlogo(data):
    for logo in LOGOS:
        data = re.sub(logo, b"", data, count=1)
    return data.replace(b"Evaluation copy. Please register.\n\n", b"", 1)


def listing(work, staged):
    left = []
    for dirpath, dirs, names in os.walk(work):
        for n in names:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, work)
            if rel in staged:
                continue
            size = -1 if rel.endswith(".rar") else os.path.getsize(p)
            left.append((rel, size))
    return sorted(left)


def run(tool, group, command, switches, rest):
    work = tempfile.mkdtemp()
    try:
        stage(work, group)
        staged = set(os.listdir(work))
        args = [TOOLS[tool], command] + switches + rest
        # Listings print local time: every cell runs in UTC, and so does
        # the test, or a box in another zone reads another hour.
        env = dict(os.environ, TZ="UTC")
        done = subprocess.run(
            args, cwd=work, env=env, capture_output=True, stdin=subprocess.DEVNULL
        )
        return done.returncode, unlogo(done.stdout), unlogo(done.stderr), listing(work, staged)
    finally:
        for dirpath, _, names in os.walk(work):
            for n in names:
                os.chmod(os.path.join(dirpath, n), 0o600)
        shutil.rmtree(work)


def lit(data):
    """A Rust byte string literal."""
    out = []
    for b in data:
        if b == 0x22:
            out.append('\\"')
        elif b == 0x5C:
            out.append("\\\\")
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        elif b == 0x0A:
            out.append("\\n")
        else:
            out.append("\\x%02x" % b)
    return 'b"' + "".join(out) + '"'


def strs(items):
    return "&[%s]" % ", ".join('"%s"' % s for s in items)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "cells.rs")
    lines = [
        "// Written by tests/parity-land3/capture.py from reference rar and",
        "// unrar 7.23; do not edit by hand. (tool, group, command, switches,",
        "// the rest of the line, exit, stdout, stderr, files the run left).",
        "const CAPTURES: &[Capture] = &[",
    ]
    for tool, group, command, switches, rest in CAPTURES:
        code, out, err, left = run(tool, group, command, switches, rest)
        if command == "p":
            stdout = "Stdout::Payload { len: %d, crc: 0x%08x }" % (len(out), zlib.crc32(out))
        else:
            stdout = "Stdout::Text(%s)" % lit(out)
        lines += [
            "    Capture {",
            '        tool: "%s",' % tool,
            '        group: "%s",' % group,
            '        command: "%s",' % command,
            "        switches: %s," % strs(switches),
            "        rest: %s," % strs(rest),
            "        exit: %d," % code,
            "        stdout: %s," % stdout,
            "        stderr: %s," % lit(err),
            "        left: &[%s]," % ", ".join('("%s", %d)' % (p, n) for p, n in left),
            "    },",
        ]
    lines.append("];")
    open(target, "w").write("\n".join(lines) + "\n")
    print("%d cells" % len(CAPTURES), file=sys.stderr)


if __name__ == "__main__":
    main()
