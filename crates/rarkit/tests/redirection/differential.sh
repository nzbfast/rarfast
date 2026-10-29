#!/bin/sh
# The redirection differential:
# reference unrar 7.23 and rarfast, both as black boxes, over this
# directory's archives and the command lines of spec F 3.8. For each cell
# it compares the exit code, stdout, stderr and the tree left behind, and
# prints SAME or DIFF with the difference. A DIFF is not a failure by
# itself: spec F question 14 lists the rows where rarfast is deliberately
# stricter, and each is pinned in crates/rarkit-cli/tests/redirection.rs.
#
#   UNRAR=/path/to/unrar RARFAST=/path/to/rarfast sh differential.sh [WORK]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
UNRAR=${UNRAR:?reference unrar}
RARFAST=${RARFAST:?rarfast}
WORK=${1:-$(mktemp -d)}
mkdir -p "$WORK/bin"
# rarfast speaks the unrar dialect when it is called unrar.
ln -sf "$RARFAST" "$WORK/bin/unrar"
cd "$WORK"

tree() {
    (cd o 2>/dev/null && find . -print | LC_ALL=C sort | while read -r p; do
        if [ -L "$p" ]; then echo "l $p -> $(readlink "$p")"
        elif [ -d "$p" ]; then echo "d $p"
        else echo "f $p $(cksum < "$p" | cut -d' ' -f1,2)"; fi
    done)
}

one() { # arm tag archive "members" switches...
    arm=$1; tag=$2; archive=$3; members=$4; shift 4
    rm -rf o; mkdir o
    if [ "$arm" = ref ]; then bin=$UNRAR; else bin=$WORK/bin/unrar; fi
    case $archive in /*) path=$archive ;; *) path=$HERE/$archive ;; esac
    # shellcheck disable=SC2086
    "$bin" "$@" "$path" $members o/ < /dev/null > "$tag.$arm.out" 2> "$tag.$arm.err"
    echo $? > "$tag.$arm.rc"
    tree > "$tag.$arm.tree"
}

cell() { # tag archive "members" switches...
    tag=$1
    one ref "$@"; one fast "$@"
    same=yes
    for part in rc out err tree; do
        cmp -s "$tag.ref.$part" "$tag.fast.$part" || same=no
    done
    if [ $same = yes ]; then echo "SAME $tag"; return; fi
    # The two classes the link-free controls show are this dialect's own
    # and not about redirection: the copyright banner, and the counter's
    # digits. With both taken out, the rest must still agree.
    for arm in ref fast; do
        sed -e '/^UNRAR 7.23 freeware/{N;d;}' -e 's/[ 0-9][ 0-9][0-9]%/NN%/g' \
            "$tag.$arm.out" > "$tag.$arm.norm"
    done
    if cmp -s "$tag.ref.norm" "$tag.fast.norm" && cmp -s "$tag.ref.rc" "$tag.fast.rc" \
        && cmp -s "$tag.ref.err" "$tag.fast.err" && cmp -s "$tag.ref.tree" "$tag.fast.tree"; then
        echo "SAME-NORMALISED $tag"
        return
    fi
    echo "DIFF $tag (rc ref $(cat "$tag.ref.rc") fast $(cat "$tag.fast.rc"))"
    diff "$tag.ref.norm" "$tag.fast.norm" | sed "s/^/    out /" | cat -vet | head -20
    for part in err tree; do
        cmp -s "$tag.ref.$part" "$tag.fast.$part" || diff "$tag.ref.$part" "$tag.fast.$part" | sed "s/^/    $part /" | cat -vet | head -20
    done
}

# Controls with no redirection member, which say which differences are
# this dialect's own and not about links: CONTROLS=dir of archives.
if [ -n "${CONTROLS:-}" ]; then
    for a in "$CONTROLS"/*.rar; do
        cell control-$(basename "$a" .rar) "$a" "" x -y -p- -mt1
    done
fi

for w in -mt1 -mt4; do
    cell links5-x$w links5.rar "" x -y $w
    cell links5-ola$w links5.rar "" x -y -ola $w
    cell links5-oln$w links5.rar "" x -y -ol- $w
    cell links5-e$w links5.rar "" e -y $w
    cell links5-hard$w links5.rar hard_a x -y $w
    cell copies5-x$w copies5.rar "" x -y $w
    cell copies5-e$w copies5.rar "" e -y $w
    cell copies5-big2$w copies5.rar big2 x -y $w
    cell copies5-xbig1$w copies5.rar "" x -y -xbig1 $w
    cell solid5-x$w solid5.rar "" x -y $w
    cell blake5-x$w blake5.rar "" x -y $w
    cell crypt5-x$w crypt5.rar "" x -y -predir $w
    cell crypt5-nopw$w crypt5.rar "" x -y -p- $w
    cell attack5-x$w attack5.rar "" x -y $w
    cell attack5-ola$w attack5.rar "" x -y -ola $w
    cell links4-x$w links4.rar "" x -y $w
    for a in links5 copies5 solid5 blake5 links4; do
        cell $a-t$w $a.rar "" t $w
    done
done
