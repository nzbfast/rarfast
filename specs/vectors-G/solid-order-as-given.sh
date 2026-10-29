#!/bin/bash
# The three shapes of bug sweep item FUZZ-08OCT-5, part X, put to a genuine
# rar: is a solid archive's member order the order the names were GIVEN?
#
#   bash solid-order-as-given.sh WORKDIR [RAR [UNRAR [EXTRA SWITCH]]]
#
# Each shape gives rar two names on its command line, in the order shown,
# under four sets of switches, and prints the order `unrar lb` lists and
# the exit of `unrar t`. EXTRA SWITCH is for a writer that needs one to
# write the RAR 4 family (`-ma4` with rar 5.50).
#
#   1  an EMPTY file `zz`, then a 2 byte file `aa`
#   2  a DIRECTORY `dzz`, then a 409,605 byte file `f`
#   3  a 409,600 byte file `q`, then a 3 byte file `b`
#
# Run under bash: the switch sets are split on spaces.
set -u
W=$1; RAR=${2:-rar}; UNRAR=${3:-unrar}; EXTRA=${4:-}
rm -rf "$W"; mkdir -p "$W/in1" "$W/in2/dzz" "$W/in3"
: > "$W/in1/zz"; printf 'hi' > "$W/in1/aa"
head -c 409605 /dev/zero | tr '\0' 'f' > "$W/in2/f"
head -c 409600 /dev/zero | tr '\0' 'q' > "$W/in3/q"; printf 'abc' > "$W/in3/b"
echo "writer: $("$RAR" | sed -n 2p | cut -c1-12)  reader: $("$UNRAR" | sed -n 2p | cut -c1-12)  extra switch: ${EXTRA:-none}"
for sw in "-s" "-s -ds" "-s -m0" ""; do
  rm -f "$W"/x?.rar
  (cd "$W/in1" && "$RAR" a -idq -cfg- $EXTRA $sw ../x1.rar zz aa)
  (cd "$W/in2" && "$RAR" a -idq -cfg- $EXTRA $sw ../x2.rar dzz f)
  (cd "$W/in3" && "$RAR" a -idq -cfg- $EXTRA $sw ../x3.rar q b)
  for n in 1 2 3; do
    "$UNRAR" t -inul "$W/x$n.rar"; rc=$?
    echo "switches [${sw:-none}] shape $n: $("$UNRAR" lb "$W/x$n.rar" | tr '\n' ' ')unrar t exit $rc"
  done
done
rm -rf "$W"
