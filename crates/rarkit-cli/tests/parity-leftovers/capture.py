#!/usr/bin/env python3
"""Records what reference unrar 7.23 prints for every cell of
`tests/unrar_parity_leftovers.rs`, into `cells.rs` beside this file,
which the test includes.

Each cell runs in a scratch directory holding copies of its archives under
their own names, so the names the reference prints are the ones rarfast
will. The reference's logo line is dropped (rarfast prints none). A cell
keeps the exit code, stderr whole, stdout whole or, for `p`, whose stdout
is the payload, its length and CRC32, and for `x` every file left under
the destination with its length.

    UNRARBIN=/path/to/unrar python3 capture.py
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
UNRAR = os.environ.get("UNRARBIN", "unrar")


def vec(name):
    return os.path.join(ROOT, "specs", "vectors-G", "archives", name)


def legacy(name):
    return os.path.join(ROOT, "fixtures", "legacy", "archives", name)


def here(name):
    return os.path.join(HERE, name)


def parts(stem, n, where=here):
    return [where("%s.part%d.rar" % (stem, i)) for i in range(1, n + 1)]


# What `r420_dmg.rar` is: rar 4.20's `-hp` archive with one byte of its
# SECOND member's enciphered header inverted, so the walk reads the first
# member and then fails. The test makes it the same way.
DAMAGE = ("r420_dmg.rar", legacy("r420_hp.rar"), 21290, 0x55)

# (group, archive files, password switch, the archive argument)
SETS = {
    # Item 1: refused before any member.
    "r5_hpw": ([vec("r5_hpw.rar")], "-pwrong", "r5_hpw.rar"),
    "hv": (parts("hv", 3), "-pwrong", "hv.part1.rar"),
    "r4_hpw": ([vec("r4_hpw.rar")], "-pwrong", "r4_hpw.rar"),
    "r420_hp": ([legacy("r420_hp.rar")], "-pwrong", "r420_hp.rar"),
    "r420_dmg": ([DAMAGE], "-pSecret", "r420_dmg.rar"),
    "missing": ([], None, "nosuch.rar"),
    # Item 2 and the later volume's banner: members across volumes.
    "two": (parts("two", 4), None, "two.part1.rar"),
    "twoc": (parts("twoc", 4), None, "twoc.part1.rar"),
    "twop": (parts("twop", 4), "-psecret", "twop.part1.rar"),
    "r5_vol": (parts("r5_vol", 4, vec), None, "r5_vol.part1.rar"),
    "r4_vol": (parts("r4_vol", 3, vec), None, "r4_vol.part1.rar"),
    "r4_volvn": (
        [vec("r4_volvn.rar"), vec("r4_volvn.r00"), vec("r4_volvn.r01")],
        None,
        "r4_volvn.rar",
    ),
    "r4_pwvol": (parts("r4_pwvol", 3, vec), "-pSecret", "r4_pwvol.part1.rar"),
}

OPEN_SWITCHES = ["", "-idq", "-ierr", "-idd", "-inul", "-idd -ierr"]
VOLUME_SWITCHES = ["", "-idq", "-ierr"]

CAPTURES = []
for group in ["r5_hpw", "hv", "r4_hpw", "r420_hp", "r420_dmg", "missing"]:
    for cmd in ["t", "x", "p"]:
        for sw in OPEN_SWITCHES:
            CAPTURES.append((group, cmd, sw.split(), []))
for group in ["two", "twoc", "twop", "r5_vol", "r4_vol", "r4_volvn", "r4_pwvol"]:
    for cmd in ["t", "x", "p"]:
        for sw in VOLUME_SWITCHES:
            CAPTURES.append((group, cmd, sw.split(), []))
# `p` of the member that starts in the third volume alone: one banner, the
# first volume's.
for group in ["two", "twoc"]:
    CAPTURES.append((group, "p", ["-ierr"], ["b.bin"]))


def stage(work, files):
    for f in files:
        if isinstance(f, tuple):
            name, src, offset, mask = f
            data = bytearray(open(src, "rb").read())
            data[offset] ^= mask
            open(os.path.join(work, name), "wb").write(data)
        else:
            shutil.copy(f, work)


def run(group, cmd, switches, select):
    files, password, archive = SETS[group]
    work = tempfile.mkdtemp()
    try:
        stage(work, files)
        args = [UNRAR, cmd] + ([password] if password else []) + switches + [archive]
        args += select
        if cmd == "x":
            args.append("out/")
        done = subprocess.run(args, cwd=work, capture_output=True)
        logo = rb"\nUNRAR 7\.23 freeware[^\n]*\n"
        out = re.sub(logo, b"", done.stdout, count=1)
        err = re.sub(logo, b"", done.stderr, count=1)
        tree = []
        top = os.path.join(work, "out")
        for dirpath, _, names in os.walk(top):
            for n in names:
                p = os.path.join(dirpath, n)
                tree.append((os.path.relpath(p, top), os.path.getsize(p)))
        return done.returncode, out, err, sorted(tree)
    finally:
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


def main():
    lines = [
        "// Written by tests/parity-leftovers/capture.py from reference unrar",
        "// 7.23; do not edit by hand. (group, command, switches, selection,",
        "// exit, stdout, stderr, files left under `out/` for `x`).",
        "const CAPTURES: &[Capture] = &[",
    ]
    for group, cmd, switches, select in CAPTURES:
        code, out, err, tree = run(group, cmd, switches, select)
        if cmd == "p":
            stdout = "Stdout::Payload { len: %d, crc: 0x%08x }" % (
                len(out),
                zlib.crc32(out),
            )
        else:
            stdout = "Stdout::Text(%s)" % lit(out)
        lines.append("    Capture {")
        lines.append('        group: "%s",' % group)
        lines.append('        command: "%s",' % cmd)
        lines.append("        switches: &[%s]," % ", ".join('"%s"' % s for s in switches))
        lines.append("        select: &[%s]," % ", ".join('"%s"' % s for s in select))
        lines.append("        exit: %d," % code)
        lines.append("        stdout: %s," % stdout)
        lines.append("        stderr: %s," % lit(err))
        lines.append(
            "        left: &[%s],"
            % ", ".join('("%s", %d)' % (p, n) for p, n in tree)
        )
        lines.append("    },")
    lines.append("];")
    open(os.path.join(HERE, "cells.rs"), "w").write("\n".join(lines) + "\n")
    print("%d cells" % len(CAPTURES), file=sys.stderr)


if __name__ == "__main__":
    main()
