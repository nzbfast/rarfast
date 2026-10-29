# rarkit-cli: rarfast

One binary, `rarfast`, on the rarkit engine. It takes the commands and
switches of `rar` and `unrar`. The dialect is chosen by the name it is
run under: a copy or symlink named `unrar` behaves as unrar, one named
`rar` behaves as rar, and under its own name the command letter decides.

    rarfast a -m5 backup.rar my-folder     create an archive
    rarfast t backup.rar                   test it
    rarfast x backup.rar                   extract it

`cargo build --release -p rarkit-cli`, run at the repository root,
leaves the program at `target/release/rarfast`. It is not put on your
path: run it by that name, or copy it to a directory that is on your
path, and the lines above work as written. The root `README.md` says
what building and testing cost in time and disk.

`docs/release-0.9.0/` at the repository root has the release notes and
the known issues.
