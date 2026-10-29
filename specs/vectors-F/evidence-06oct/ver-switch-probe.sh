#!/bin/bash
# What the reference's -ver and -ver<n> switches select (SPEC-F 3.2.6.4).
#
#   ver-switch-probe.sh /path/to/rar /path/to/unrar WORKDIR
#
# Writes v.txt five times into one RAR 5 archive with `rar a -ver` (the
# contents are "content 1" to "content 5"), then asks the reference to
# list it and to extract it under each form of the switch, and prints
# what each extraction created. A second archive is written with
# `rar a -ver2` to see how many old versions the writer keeps.
# One process at a time; a few kilobytes of files.
set -u
RAR=$1; UNRAR=$2; W=$3
mkdir -p "$W" && cd "$W" || exit 2
"$UNRAR" | sed -n 2p
"$RAR" | sed -n 2p
rm -f ver.rar ver2.rar
for i in 1 2 3 4 5; do
  echo "content $i" > v.txt
  "$RAR" a -inul -ver ver.rar v.txt
  "$RAR" a -inul -ver2 ver2.rar v.txt
done
show() {  # show LABEL ARCHIVE unrar-arguments...
  local label=$1 arc=$2; shift 2
  rm -rf out && mkdir out
  "$UNRAR" x -inul -o+ "$@" "$arc" out/ ${NAMES[@]+"${NAMES[@]}"} >/dev/null 2>&1
  local rc=$?
  printf '%s\trc=%d\t' "$label" "$rc"
  (cd out && for f in *; do [ -e "$f" ] && printf '%s=[%s] ' "$f" "$(cat "$f")"; done)
  printf '\n'
}
echo "== names listed (unrar lb), ver.rar then ver2.rar"
"$UNRAR" lb ver.rar | tr '\n' ' '; echo
"$UNRAR" lb -ver ver.rar | tr '\n' ' '; echo
"$UNRAR" lb -ver ver2.rar | tr '\n' ' '; echo
echo "== extraction of ver.rar, no name given"
NAMES=()
show "no switch" ver.rar
for n in "" 0 1 2 3 4 5 9; do show "-ver$n" ver.rar "-ver$n"; done
echo "== extraction of ver.rar, the name v.txt given"
NAMES=(v.txt)
for n in "" 1 3; do show "-ver$n v.txt" ver.rar "-ver$n"; done
echo "== extraction of ver.rar, the name 'v.txt;2' given"
NAMES=('v.txt;2')
show "no switch 'v.txt;2'" ver.rar
show "-ver 'v.txt;2'" ver.rar -ver
show "-ver3 'v.txt;2'" ver.rar -ver3
echo "== extraction of ver2.rar"
NAMES=()
show "-ver" ver2.rar -ver
show "-ver1" ver2.rar -ver1
rm -rf out v.txt
