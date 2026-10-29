#!/usr/bin/env python3
"""Engine of the rarkit legacy fixture generator. Driven by generate.sh;
run that, not this. Written for the Python 3.9 on this box.

Reads fixtures.tsv, runs one genuine RARLAB writer command per row inside a
network-less container, walks the headers of everything written, round-trips
every archive under reference unrar and (when one is given) the old engine,
and writes MANIFEST.tsv. A row whose archive does not round-trip under
reference unrar is reported and left OUT of the manifest: a fixture the
reference refuses is not a fixture.

    build.py --pkg DIR --work DIR [--unrar CMD] [--old CMD]
             [--profile NAME] [--only PREFIX] [--stage all|write|verify]
"""
import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PW = "Secret"

# writer id -> (label, package filename, kind, platform, image)
WRITERS = {
    "d140": ("RAR 1.40.2 beta, DOS, Feb 1994", "RAR1_402.EXE", "dos", None, None),
    "d155": ("RAR 1.55, DOS, Aug 1995", "RAR155.EXE", "dos", None, None),
    "d250": ("RAR 2.50, DOS, Mar 1999", "rar250.exe", "dos", None, None),
    "r393": ("rar 3.9.3, Linux i386", "rarlinux-3.9.3.tar.gz", "nix", "linux/386", "alpine:3.20"),
    "r420": ("rar 4.2.0, Linux x86-64", "rarlinux-x64-4.2.0.tar.gz", "nix", "linux/amd64", "alpine:3.20"),
    "r550": ("rar 5.5.0, Linux x86-64", "rarlinux-x64-5.5.0.tar.gz", "nix", "linux/amd64",
             "debian:bookworm-slim"),
}
# 8.3 DOS directory each DOS package is unpacked into, and its binary
DOSDIR = {"d140": "D140", "d155": "D155", "d250": "D250"}


# ---------------------------------------------------------------- packages

def read_packages():
    rows = []
    for line in open(os.path.join(HERE, "packages.sha256")):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        sha, size, name, url = line.split("\t")
        rows.append((sha, int(size), name, url))
    return rows


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_packages(pkgdir, needed):
    """Refuse, naming what is missing and what it would take to get it."""
    have, missing, wrong = {}, [], []
    for sha, size, name, url in read_packages():
        path = os.path.join(pkgdir, name)
        if not os.path.exists(path):
            missing.append((sha, size, name, url))
            continue
        got = sha256_file(path)
        if got != sha:
            wrong.append((name, sha, got))
        else:
            have[name] = (path, sha)
    missing = [m for m in missing if m[2] in needed]
    wrong = [w for w in wrong if w[0] in needed]
    if missing or wrong:
        print("REFUSING TO RUN: the legacy writer packages are not all here.\n", file=sys.stderr)
        for sha, size, name, url in missing:
            print("  MISSING  %-26s %9d bytes  %s" % (name, size, url), file=sys.stderr)
            print("           sha256 %s" % sha, file=sys.stderr)
        for name, want, got in wrong:
            print("  WRONG HASH  %s\n    want %s\n    got  %s" % (name, want, got), file=sys.stderr)
        print("\nNo package is ever fetched by this script and none is ever committed.",
              file=sys.stderr)
        print("A download needs the owner's explicit yes first, quoting the filename, source and",
              file=sys.stderr)
        print("size above (README section 3). Put the files in %s and run again."
              % pkgdir, file=sys.stderr)
        sys.exit(2)
    return have


# --------------------------------------------------------------- fixtures

class Row(object):
    __slots__ = ("id", "writer", "tree", "switches", "files", "covers")

    def __init__(self, cols):
        self.id, self.writer, self.tree, self.switches, self.files, self.covers = cols


def read_fixtures(only=None):
    rows, seen = [], set()
    for line in open(os.path.join(HERE, "fixtures.tsv")):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if cols[0] == "id":
            continue
        if len(cols) != 6:
            sys.exit("fixtures.tsv: %d fields, want 6: %r" % (len(cols), line))
        r = Row(cols)
        if r.writer not in WRITERS:
            sys.exit("fixtures.tsv: unknown writer %r on row %s" % (r.writer, r.id))
        if r.id in seen:
            sys.exit("fixtures.tsv: duplicate id %s" % r.id)
        if WRITERS[r.writer][2] == "dos" and not re.match(r"^[A-Za-z0-9_]{1,8}$", r.id):
            sys.exit("fixtures.tsv: DOS row id %r is not an 8.3 base name. The 16-bit\n"
                     "writer truncates it to 8 characters and writes the archive under a\n"
                     "name nothing looks for, so the row is silently lost." % r.id)
        seen.add(r.id)
        if only and not r.id.startswith(only):
            continue
        rows.append(r)
    return rows


# ------------------------------------------------------------- containers

def nerdctl(profile, args, **kw):
    return subprocess.run(["colima", "-p", profile, "nerdctl", "--"] + args, **kw)


# ----------------------------------------------------------- header walk

def ref_list(unrar, path, password):
    """Ask reference unrar what the archive holds: its own name for the
    format, and one line per entry. Used for the entry counts of EVERY row,
    so those columns come from one source rather than from a parser that
    covers some formats and not others. It is the reference's reading, not
    ours; the columns from `walk` below are ours.

    Returns (detail, entries, dirs, encrypted) or (None, ...) when the
    headers are encrypted and the listing cannot be had."""
    args = [unrar, "lta", "-p" + (password or "-"), path]
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=300)
    if r.returncode != 0:
        return (None, 0, 0, 0)
    detail, entries, dirs, enc = "", 0, 0, 0
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("Details:"):
            detail = line.split(":", 1)[1].strip()
        elif line.startswith("Name:"):
            entries += 1
        elif line.startswith("Type:") and line.endswith("Directory"):
            dirs += 1
        elif line.startswith("Flags:") and "encrypted" in line:
            enc += 1
    return (detail, entries, dirs, enc)


def walk(path):
    """Report what the RAR headers of a single file say, from our own reading
    of the bytes. Decodes nothing.

    It walks the RAR 1.5-to-4.x block layout, which is the one the public
    technote describes. It does NOT walk RAR 1.3/1.4, whose blocks are laid
    out differently: for those the format is taken from the signature and the
    per-entry columns are left explicitly EMPTY rather than zero. A zero there
    would be a green line over nothing, and reverse-engineering that layout is
    spec F's subject, not this generator's."""
    buf = open(path, "rb").read()
    out = {"sig": "?", "fmt": "?", "entries": 0, "uver": set(), "meth": set(),
           "enc": 0, "dirs": 0, "mainflags": 0, "comment": False, "rr": False,
           "volume": False, "solid": False, "walked": True}
    if buf.startswith(b"RE~^"):
        out["sig"], out["fmt"] = "RE~^", "RAR 1.3/1.4"
        out["walked"] = False
        return out
    elif buf.startswith(b"Rar!\x1a\x07\x00"):
        out["sig"], pos = "Rar!1a0700", 7
    elif buf.startswith(b"Rar!\x1a\x07\x01\x00"):
        out["sig"], out["fmt"], pos = "Rar!1a070100", "RAR 5", 8
        return out
    else:
        out["sig"] = buf[:8].hex()
        return out
    first_main = True
    while pos + 7 <= len(buf):
        crc, typ, flags, hsize = struct.unpack_from("<HBHH", buf, pos)
        if hsize < 7:
            break
        add = struct.unpack_from("<I", buf, pos + 7)[0] if (flags & 0x8000) else 0
        if typ == 0x73 and first_main:                       # main header
            first_main = False
            out["mainflags"] = flags
            out["volume"] = bool(flags & 0x0001)
            out["comment"] = out["comment"] or bool(flags & 0x0002)
            out["solid"] = bool(flags & 0x0008)
            out["rr"] = out["rr"] or bool(flags & 0x0040)
            if flags & 0x0080:                               # headers encrypted
                # Nothing past the main header can be read without decrypting,
                # which is spec K's subject and not this generator's. Say so in
                # the columns rather than leaving them empty.
                out["fmt"] = out["fmt"] if out["fmt"] != "?" else "RAR 1.5-4.x"
                out["enc"] = -1
                out["walked"] = False
                out["mainflags"] = flags
                return out
        elif typ == 0x74 and pos + 32 <= len(buf):           # file header
            psize, usize, host, fcrc, ftime, uver, meth, nlen, attr = \
                struct.unpack_from("<IIBIIBBHI", buf, pos + 7)
            out["entries"] += 1
            out["uver"].add(uver)
            out["meth"].add(meth)
            if flags & 0x0004:
                out["enc"] += 1
            if flags & 0x0002:
                out["comment"] = True
            isdir = (flags & 0x00e0) == 0x00e0 or (uver < 20 and host in (0, 1, 2) and (attr & 0x10))
            if isdir:
                out["dirs"] += 1
        elif typ == 0x78:                                    # protect/recovery
            out["rr"] = True
        pos += hsize + add
    if out["fmt"] == "?":
        v = max(out["uver"]) if out["uver"] else 0
        out["fmt"] = {2: "RAR 1.3/1.4", 15: "RAR 1.5", 20: "RAR 2.0"}.get(v, "RAR 2.9") \
            if v else "RAR 1.5-4.x"
    return out


# What each writer's headers may legitimately say. A build that can only
# write one format has one entry; the RAR 2.9 builds have two, because every
# one of them writes unpack version 20 for STORED members and empty files and
# 29 only for compressed ones (observed 18 Sep 2026), so an all-stored
# archive from rar 4.2.0 reads as RAR 2.0 and is not a defect. Anything
# outside the set is refused: a RAR 5 signature from `r550` without -ma4 is
# the case this catches.
EXPECT_FMT = {"d140": ("RAR 1.3/1.4",), "d155": ("RAR 1.5",), "d250": ("RAR 2.0",),
              "r393": ("RAR 2.0", "RAR 2.9"), "r420": ("RAR 2.0", "RAR 2.9"),
              "r550": ("RAR 2.0", "RAR 2.9")}


# ---------------------------------------------------------------- verify

def roundtrip(cmd, archive, treedir, scratch, password):
    """Extract with an unrar-dialect binary and compare every extracted file
    with the input tree. Returns (rc, files, mismatches, missing)."""
    out = os.path.join(scratch, "x")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    args = [cmd, "x", "-idq", "-y", "-p" + (password or "-"), archive, out + os.sep]
    try:
        rc = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=300).returncode
    except subprocess.TimeoutExpired:
        return (None, 0, 0, 0)
    got, bad = [], 0
    for root, _dirs, names in os.walk(out):
        for n in names:
            full = os.path.join(root, n)
            rel = os.path.relpath(full, out)
            got.append(rel)
            src = os.path.join(treedir, rel.replace("\\", os.sep))
            # An extracted FILE whose input counterpart is a DIRECTORY is a
            # mismatch, not a crash: that is exactly the shape of the RAR 1.5
            # directory defect (a genuine 1.55 directory extracted as an empty
            # file), and this column exists to record such differences.
            if not os.path.isfile(src) or sha256_file(full) != sha256_file(src):
                bad += 1
    return (rc, len(got), bad, 0)


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--unrar", default="unrar")
    ap.add_argument("--old", default=None, help="old-engine binary, unrar dialect")
    ap.add_argument("--profile", default=os.environ.get("COLIMA_PROFILE", "rarkitfx"))
    ap.add_argument("--only", default=None)
    ap.add_argument("--stage", default="all", choices=["all", "write", "verify"])
    a = ap.parse_args()

    pkgdir, work = os.path.abspath(a.pkg), os.path.abspath(a.work)
    if not work.startswith(os.path.expanduser("~") + os.sep):
        sys.exit("--work must be under $HOME: the container mounts only that, "
                 "and it is mounted at its real absolute path.")
    rows = read_fixtures(a.only)
    needed = set(WRITERS[r.writer][1] for r in rows)
    pkgs = check_packages(pkgdir, needed)

    outdir = os.path.join(work, "out")
    if a.stage in ("all", "write"):
        shutil.rmtree(outdir, ignore_errors=True)
        for d in ("IN", "INX", "bin", "dos"):
            shutil.rmtree(os.path.join(work, d), ignore_errors=True)
    for d in ("out", "bin", "dos"):
        os.makedirs(os.path.join(work, d), exist_ok=True)

    # inputs, held to the committed digest list
    sys.path.insert(0, HERE)
    import inputs as inputs_mod
    lines = inputs_mod.build(work)
    open(os.path.join(work, "INPUTS.sha256"), "w").write("\n".join(lines) + "\n")
    committed = os.path.join(HERE, "INPUTS.sha256")
    if os.path.exists(committed):
        want = open(committed).read()
        if want != "\n".join(lines) + "\n":
            sys.exit("INPUTS.sha256 does not match the committed copy: the seeded\n"
                     "inputs moved. Fix inputs.py, or update the committed list in the\n"
                     "same commit as the archives it describes.")
    else:
        shutil.copy(os.path.join(work, "INPUTS.sha256"), committed)
    tree_hash = hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()

    if a.stage in ("all", "write"):
        write_stage(a, rows, work, pkgdir, outdir)

    verify_stage(a, rows, work, outdir, pkgs, tree_hash)


def write_stage(a, rows, work, pkgdir, outdir):
    unrar = a.unrar
    # --- unpack the packages. The DOS self-extractors are UNPACKED by unrar,
    # never executed; the Linux tarballs are plain tar.
    for w in sorted(set(r.writer for r in rows)):
        label, pkg, kind, plat, image = WRITERS[w]
        if kind == "dos":
            d = os.path.join(work, "dos", DOSDIR[w])
            os.makedirs(d, exist_ok=True)
            subprocess.run([unrar, "x", "-idq", "-y", os.path.join(pkgdir, pkg), d + os.sep],
                           check=True, stdout=subprocess.DEVNULL)
            # normalise the binary's name to RAR.EXE
            for n in os.listdir(d):
                if n.upper() == "RAR.EXE" and n != "RAR.EXE":
                    os.rename(os.path.join(d, n), os.path.join(d, "RAR.EXE"))
        else:
            tmp = os.path.join(work, "t_" + w)
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp)
            subprocess.run(["tar", "-xzf", os.path.join(pkgdir, pkg), "-C", tmp], check=True)
            src = os.path.join(tmp, "rar", "rar_static")
            if not os.path.exists(src):
                src = os.path.join(tmp, "rar", "rar")   # 5.5.0 ships no static build
            shutil.copy(src, os.path.join(work, "bin", w))
            os.chmod(os.path.join(work, "bin", w), 0o755)
            shutil.rmtree(tmp, ignore_errors=True)

    # --- DOS rows: one dosbox run for all of them
    dos_rows = [r for r in rows if WRITERS[r.writer][2] == "dos"]
    if dos_rows:
        conf = ["[sdl]", "usescancodes=false", "[cpu]", "cycles=max", "[autoexec]",
                "mount c " + work, "c:", "cd IN"]
        for r in dos_rows:
            sw = r.switches.replace("@CMT@", r"..\CMT.TXT")
            files = "*.*" if r.files == "." else r.files
            conf.append(r"..\dos\%s\RAR a -r -y %s ..\out\%s.RAR %s > ..\out\%s.LOG"
                        % (DOSDIR[r.writer], sw, r.id.upper(), files, r.id.upper()))
        conf.append("exit")
        open(os.path.join(work, "dos.conf"), "w").write("\n".join(conf) + "\n")
        img = "rarkit-dosbox:1"
        dockerfile = os.path.join(work, "Dockerfile.dosbox")
        shutil.copy(os.path.join(HERE, "Dockerfile.dosbox"), dockerfile)
        # the image build is the ONLY step that touches the network
        nerdctl(a.profile, ["build", "-t", img, "-f", dockerfile, work], check=True)
        print("dosbox: %d command lines" % len(dos_rows))
        nerdctl(a.profile, ["run", "--rm", "--network", "none", "-v", work + ":" + work,
                            "-w", work, "-e", "SDL_VIDEODRIVER=dummy", img,
                            "timeout", "1800", "dosbox", "-conf", os.path.join(work, "dos.conf"),
                            "-exit"])
        # DOS writes upper case; the rest of this script wants the row's own id
        for n in sorted(os.listdir(outdir)):
            low = n.lower()
            if low != n:
                os.rename(os.path.join(outdir, n), os.path.join(outdir, low))

    # --- Linux rows: one container run per writer
    for w in sorted(set(r.writer for r in rows if WRITERS[r.writer][2] == "nix")):
        label, pkg, kind, plat, image = WRITERS[w]
        wrows = [r for r in rows if r.writer == w]
        sh = ["set -u", "cd $1"]
        for r in wrows:
            sw = r.switches.replace("@CMT@", os.path.join(work, "CMT.TXT"))
            rec = "-r " if r.files == "." else ""
            files = "." if r.files == "." else r.files
            sh.append('cd %s; "$2" a -idq %s%s "%s/%s.rar" %s > "%s/%s.log" 2>&1; echo "%s $?"'
                      % (os.path.join(work, r.tree), rec, sw, outdir, r.id, files,
                         outdir, r.id, r.id))
        script = os.path.join(work, "mk_%s.sh" % w)
        open(script, "w").write("\n".join(sh) + "\n")
        print("%s (%s): %d command lines" % (w, label, len(wrows)))
        nerdctl(a.profile, ["run", "--rm", "--platform", plat, "--network", "none",
                            "-v", work + ":" + work, "-w", work, image,
                            "sh", script, work, os.path.join(work, "bin", w)])


def verify_stage(a, rows, work, outdir, pkgs, tree_hash):
    scratch = os.path.join(work, "scratch")
    os.makedirs(scratch, exist_ok=True)
    cols = ["id", "format", "writer", "writer_pkg_sha256", "command", "archive", "volumes",
            "bytes", "sha256", "inputs_sha256", "password", "signature", "unpack_versions",
            "methods", "unrar_detail", "entries", "dir_entries", "encrypted_entries", "flags",
            "unrar_7_23", "old_engine", "covers"]
    out_rows, refused = [], []
    for r in rows:
        label, pkg, kind, plat, image = WRITERS[r.writer]
        first = os.path.join(outdir, r.id + ".rar")
        if not os.path.exists(first):
            alt = os.path.join(outdir, r.id + ".part1.rar")
            first = alt if os.path.exists(alt) else first
        if not os.path.exists(first):
            refused.append((r.id, "no archive written"))
            continue
        vols = sorted(n for n in os.listdir(outdir)
                      if n.startswith(r.id + ".") and not n.endswith(".log")
                      and (n.endswith(".rar") or n.endswith(".rev")
                           or "." + n.rsplit(".", 1)[-1] != ".log"))
        vols = sorted(set(n for n in os.listdir(outdir)
                          if (n == r.id + ".rar" or n.startswith(r.id + ".part")
                              or n.startswith(r.id + ".r") or n.startswith(r.id + ".s"))
                          and not n.endswith(".log")))
        if "-v" in r.switches and len(vols) < 2:
            refused.append((r.id, "the -v row produced ONE volume, so it exercises no "
                                  "volume continuation at all"))
            continue
        info = walk(first)
        detail, n_ent, n_dir, n_enc = ref_list(a.unrar, first,
                                               PW if "-p" in r.switches or "-hp" in r.switches
                                               else "")
        want_fmt = EXPECT_FMT[r.writer]
        if info["fmt"] not in want_fmt and not (info["enc"] == -1
                                                and "RAR 2.9" in want_fmt):
            refused.append((r.id, "header says %s, this writer may only write %s"
                            % (info["fmt"], "/".join(want_fmt))))
            continue
        pw = PW if ("-p" + PW) in r.switches or ("-hp" + PW) in r.switches else ""
        treedir = os.path.join(work, r.tree)
        rc, n, bad, _ = roundtrip(a.unrar, first, treedir, scratch, pw)
        verdict = "rc=%s files=%d mismatch=%d" % (rc, n, bad)
        if rc != 0 or bad or n == 0:
            refused.append((r.id, "reference unrar: " + verdict))
            continue
        oldv = ""
        if a.old:
            orc, on, obad, _ = roundtrip(a.old, first, treedir, scratch, pw)
            oldv = "rc=%s files=%d mismatch=%d" % (orc, on, obad)
            if (orc, on, obad) != (rc, n, bad):
                oldv += " DIFFERS"
        if kind == "dos":
            sw = r.switches.replace("@CMT@", r"..\CMT.TXT")
            cmd = r"RAR a -r -y %s ..\out\%s.RAR %s" % (sw, r.id.upper(),
                                                        "*.*" if r.files == "." else r.files)
        else:
            sw = r.switches.replace("@CMT@", "../CMT.TXT")
            cmd = "rar a -idq %s%s %s.rar %s" % ("-r " if r.files == "." else "", sw, r.id,
                                                 "." if r.files == "." else r.files)
        flags = ["main=0x%04x" % info["mainflags"]] \
            if (info["walked"] or info["enc"] == -1) else ["not walked"]
        if info["volume"]:
            flags.append("volume")
        if info["solid"]:
            flags.append("solid")
        if info["comment"]:
            flags.append("comment")
        if info["rr"]:
            flags.append("recovery")
        out_rows.append([
            r.id, info["fmt"], label, pkgs[pkg][1], cmd, os.path.basename(first),
            ";".join(vols) if len(vols) > 1 else "",
            str(os.path.getsize(first)), sha256_file(first), tree_hash, pw,
            info["sig"],
            ",".join(str(v) for v in sorted(info["uver"])) if info["walked"]
            else ("headers encrypted" if info["enc"] == -1 else "not walked"),
            ",".join("0x%02x" % m for m in sorted(info["meth"])) if info["walked"]
            else ("headers encrypted" if info["enc"] == -1 else "not walked"),
            detail or "headers encrypted",
            str(n_ent), str(n_dir),
            "headers" if info["enc"] == -1 else str(n_enc),
            "+".join(flags), verdict, oldv, r.covers])

    ref = os.path.join(HERE, "REFUSED.tsv")
    with open(ref, "w") as f:
        f.write("# Rows fixtures.tsv asks for that did NOT become fixtures, with the\n"
                "# reason. A refusal is a finding, so it is recorded here rather than\n"
                "# dropped: README section 6 says what each one means.\n")
        f.write("id\treason\n")
        for rid, why in refused:
            f.write("%s\t%s\n" % (rid, why))
    man = os.path.join(HERE, "MANIFEST.tsv")
    with open(man, "w") as f:
        f.write("\t".join(cols) + "\n")
        for row in out_rows:
            f.write("\t".join(row) + "\n")
    print("\nMANIFEST.tsv: %d archives" % len(out_rows))
    if refused:
        print("\nREFUSED, not in the manifest (%d):" % len(refused))
        for rid, why in refused:
            print("  %-16s %s" % (rid, why))
    return 0


if __name__ == "__main__":
    sys.exit(main())
