//! FUZZ-08OCT-5, part X: the read-back of the writer fuzz targets holds
//! the order spec G 3.9.1 gives a solid archive.
//!
//! `fuzz/fuzz_targets/plan.rs` decodes a member list and a set of options
//! from fuzz bytes, writes them and reads the archive back; `write_members`
//! and `write_volumes` are that file and nothing else. Its read-back held
//! the CALLER'S order for every plan, and so stopped on every solid packed
//! plan whose members the writer sorts: spec G 3.9.1 [RULE 94] writes a
//! solid archive of packed members in the order of `MemberSortKey` (every
//! file before every directory entry, then the extension, the last
//! component, the size and the whole name), which is the genuine writer's
//! order, and its closing rule says what a read-back must hold: that
//! order for a plan that is solid, packed and `ByType`, and the order
//! given for every other plan.
//!
//! The three inputs are the ones the campaign of 8 Oct 2026 kept, each a
//! shape the section names: an empty file given before a 2 byte file
//! whose name sorts first; a directory given before a file; a 409,615
//! byte file given before a 3 byte file whose name sorts first.
//!
//! The target's file is compiled into this test as it stands, so what is
//! tested is the read-back the fuzz targets run. The pool is whatever
//! `ReadOptions::default()` and `WriteOptions::default()` give, as in the
//! targets; no plan here holds more than 410 KiB of member data, so the
//! test needs a few MiB.

#[allow(dead_code)]
#[path = "../../../fuzz/fuzz_targets/plan.rs"]
mod plan;

use plan::Plan;
use rarkit::MemberSortKey;

/// A solid RAR 4 plan cut into volumes with a payload budget of 1: a
/// zero byte file named `[0x89]`, then a 2 byte file named `[0x01]`.
const EMPTY_FILE_FIRST: &str = "6b01006240008900230001406260";

/// A solid RAR 5 plan: a directory named `[0x29 0x7a 0x7a]`, then a
/// 409,605 byte file named `[0x94]`.
const DIRECTORY_FIRST: &str = "ec7db07aff7a297a7a0000000000000094017a00047a7ae71f";

/// A solid RAR 4 plan, one archive: a 409,615 byte file named `[0x20]`,
/// then a 3 byte file named `[0x08]`.
const LARGE_FILE_FIRST: &str =
    "e3696afb002001102ce104898900010200010000e21e55e3a0eb3be9010008015530e1";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
        .collect()
}

fn decoded(hex: &str) -> Plan {
    Plan::decode(&bytes(hex)).expect("the input decodes to a plan")
}

fn key(member: &plan::Member) -> MemberSortKey<'_> {
    let size = if member.is_directory {
        0
    } else {
        member.data.len() as u64
    };
    MemberSortKey::of(&member.name, size, member.is_directory)
}

/// Whether the writer puts the plan's members in another order than the
/// one given: the plan is solid and packed, and the key moves a member.
fn reordered(plan: &Plan) -> bool {
    plan.solid
        && plan.level != 0
        && plan
            .members
            .windows(2)
            .any(|pair| key(&pair[0]) > key(&pair[1]))
}

/// Each of the three inputs is a solid packed plan whose members the key
/// reorders, and the read-back passes it: the archive holds the members
/// in the key's order, and that is the order the read-back expects.
#[test]
fn a_solid_packed_plan_reads_back_in_the_order_of_the_key() {
    for (name, hex) in [
        ("an empty file first", EMPTY_FILE_FIRST),
        ("a directory first", DIRECTORY_FIRST),
        ("a large file first", LARGE_FILE_FIRST),
    ] {
        let plan = decoded(hex);
        assert_eq!(plan.members.len(), 2, "{name}");
        assert!(reordered(&plan), "{name}: the key moves a member");
        plan.run();
    }
}

/// The other side of the rule: the same members in a plan that is not
/// solid, and in a solid plan of stored members, come back in the order
/// given, and the read-back still holds that.
#[test]
fn a_plan_that_is_not_solid_or_is_stored_reads_back_in_the_order_given() {
    for hex in [EMPTY_FILE_FIRST, DIRECTORY_FIRST, LARGE_FILE_FIRST] {
        let mut plan = decoded(hex);
        plan.solid = false;
        assert!(!reordered(&plan));
        plan.run();

        let mut plan = decoded(hex);
        plan.level = 0;
        assert!(!reordered(&plan));
        plan.run();
    }
}
