# `carry/`: code brought forward from the earlier engine

`carry/` holds code this project moved in from its own predecessor, the
engine the project already owned. It is not another RAR implementation's
text and it is not vendored: it is the project's own from birth.

It is kept apart from the rest of `crates/rarkit/src` because it was moved
in rather than written here from a specification. Each module's header
says which file of the predecessor it came from and at which commit, and
says so where an item has been edited since. The other modules reuse the
capabilities their specifications name here rather than rewriting them.

`wiring.rs` is the exception: nothing in it is carried. It holds the few
adapters, written in this repository, that bind the carried kernels to the
modules that call them.

A carried item that nothing calls is weight, so the tree is pruned rather
than left to grow; where an unreferenced item is kept on purpose, its
module header says why.
