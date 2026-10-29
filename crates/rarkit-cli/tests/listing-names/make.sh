#!/bin/sh
# Regenerates this directory's RAR 4 archives with REFERENCE rar 4.2.0
# (rar 7 writes no RAR 4), one member each, from real files whose names
# hold control characters, a backslash, UTF-8, and bytes that are not
# UTF-8, which only a host that takes any bytes as a file name can hold:
# run it on Linux, in a UTF-8 locale, or the 8-bit names are refused and
# the UTF-8 ones are stored without their Unicode form. They pin measurements of the reference's
# listing output. The committed archives are
# the ones the tests hold; their digests are in SHA256SUMS.
#
# And one RAR 5 archive from REFERENCE rar 7.23, whose comment holds an
# ESC, a control character and a TAB (cmt-esc.rar).
#
#   LC_ALL=C.UTF-8 RARBIN=/path/to/rar-4.2.0 RAR7BIN=/path/to/rar-7.23 \
#       sh make.sh OUTDIR
set -eu
RARBIN=${RARBIN:-rar}
RAR7BIN=${RAR7BIN:?the path to rar 7.23}
OUT=$(cd "${1:?OUTDIR}" && pwd)
unset RAR
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
one() { # tag name-as-printf-format
    n=$(printf "$2")
    printf x > "$n"
    touch -d "2020-01-02 03:04:05" "$n"
    "$RARBIN" a -idq -y -m0 "$OUT/r4-$1.rar" "$n"
    rm -f "$n"
}
one tab 'a\tb'
one esc 'a\033b'
one bs 'a\\b'
one utf8 'caf\303\251'
one latin1 'caf\351'
one two '\351\350'
one split 'a\351b\350c'
one mixed 'a\351b\303\251c'
one cont 'a\200b'
printf x > f.txt
printf 'cmt\033[31mred\001\tx\n' > cmt.txt
touch -d "2020-01-02 03:04:05" f.txt
"$RAR7BIN" a -idq -y -ma5 -m0 -zcmt.txt "$OUT/cmt-esc.rar" f.txt
