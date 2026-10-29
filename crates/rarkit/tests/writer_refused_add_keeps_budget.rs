//! A member `Writer::add` refuses for the member table's budget
//! ([`MemoryPolicy::max_member_table`]) is not recorded, so it costs
//! nothing: a later add that fits the budget on its own is taken.
//!
//! The member's cost is the writer's own, so the test finds the
//! smallest budget that takes one member named `a`, then asks that
//! writer for a member with a long name first. Every member is STORED
//! and a few bytes long; no pool is started and nothing follows the
//! machine's memory.

use rarkit::{
    ErrorKind, HostOs, MemberSpec, MemoryPolicy, Payload, Resource, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};

fn writer<'a>(format: WriteFormat, table: u64) -> Writer<'a> {
    Writer::new(WriteOptions {
        format,
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        host_os: HostOs::Unix,
        memory: MemoryPolicy {
            max_member_table: table,
            ..MemoryPolicy::default()
        },
        ..WriteOptions::default()
    })
    .expect("options")
}

fn spec(name: &[u8]) -> MemberSpec<'_> {
    MemberSpec {
        name,
        payload: Payload::Bytes(b"payload"),
        mtime: None,
        attributes: 0,
        host_os: HostOs::Unix,
        is_directory: false,
    }
}

/// The smallest member table budget under which a fresh writer takes
/// one member named `a`.
fn just_enough(format: WriteFormat) -> u64 {
    (1..1 << 16)
        .find(|&table| writer(format, table).add(spec(b"a")).is_ok())
        .expect("a budget that takes one short member")
}

#[test]
fn a_refused_add_leaves_the_budget_for_a_later_one_that_fits() {
    let long = vec![b'n'; 1000];
    let mut wrong = Vec::new();
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let table = just_enough(format);
        let mut w = writer(format, table);
        match w.add(spec(&long)) {
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::LimitExceeded {
                        resource: Resource::MemberTable,
                        ..
                    }
                ) => {}
            other => wrong.push(format!("{format:?}: the long name gave {other:?}")),
        }
        if let Err(e) = w.add(spec(b"a")) {
            wrong.push(format!(
                "{format:?}: `a` refused after the refused add, budget {table}: {e}"
            ));
        }
        let mut out = Vec::new();
        if let Err(e) = w.finish_into(&mut out) {
            wrong.push(format!("{format:?}: finish: {e}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
