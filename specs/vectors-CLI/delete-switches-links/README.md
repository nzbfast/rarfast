# The delete switches of create, and links (10 Oct 2026)

`../delete-switches-links-probe.py` and the two answers files here are
the probe and answers behind SPEC-CLI section 8. The probe keeps no
archive: each of its 30 arms builds a small tree in a new directory
under TMPDIR, runs the program's archiving command with a delete switch
there, and writes down what the tree holds afterwards. Its docstring
names the shapes, the commands and the answers' columns. Run it as

    delete-switches-links-probe.py --program rar=/path/to/rar

The answers kept are rar 7.23 for macOS on arm64, run as an ordinary
user (SHA-256 `c98354aec9b71a5c`, first 16), and rar 7.23 for x86-64
Linux, run as root (`56c3c4fd46faa7a9`). They agree in every arm but
one (a wipe through a link to a file of mode 0444 under `-ol`, which
root may write and an ordinary user may not) and in the order three
shapes' members are listed in. `unrar` has no archiving command.
Nothing the program printed is kept.
