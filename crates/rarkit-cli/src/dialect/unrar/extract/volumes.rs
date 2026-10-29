//! The volume chain: every volume's name from the first, and the one the
//! disk does not have.

use super::*;

/// What [`volume_chain`] found: every volume's name, the volumes after
/// the first as parsed, and the volume the chain named and the disk did
/// not have.
pub(crate) struct Chain {
    pub(crate) names: Vec<String>,
    /// Volumes two onward, parsed through the command's session, in set
    /// order. It can be SHORTER than `names` by one: a volume that exists
    /// but does not parse is still named, so the walk meets it and says
    /// what is wrong with it, but it has no member list to plan from.
    pub(crate) later: Vec<Opened>,
    pub(crate) missing: Option<String>,
    /// The volume the chain named that is there and is not a RAR archive
    /// at all: the last of `names`, said as the reference's `Bad archive`.
    pub(crate) not_rar: Option<String>,
}

/// Builds the volume chain from the first archive, following the split
/// flags. A volume the chain names but the disk does not have is the
/// `Cannot find volume` the reference reports.
///
/// **Each volume is parsed ONCE, through the command's own session, and
/// that parse is the plan's.** Until 25 Sep 2026 the chain read each next
/// volume WITHOUT the password, only to learn whether it continued, and
/// the plan then opened every volume a second time with the password in a
/// fresh session. On a set whose headers are encrypted (`-hp`) the first
/// of those could not parse volume two at all, so the chain ended there: a
/// valid 43-volume set written by rar 7.23 was walked as two volumes and
/// failed with `Unexpected end of archive`, leaving a short payload
/// (reproduced on an Apple M3 Mac). Reading
/// through the session carries the password, and the session keeps the
/// key it derived, so a set whose volumes share a salt is keyed once
/// rather than once per volume twice over (53 key derivations against 1
/// on that report's 27-volume encrypted screen). The key never leaves the
/// command: the session is this command's and ends with it.
pub(crate) fn volume_chain(first: &str, opened: &Opened, session: &mut rarkit::Session) -> Chain {
    let mut names = vec![first.to_owned()];
    let mut later = Vec::new();
    if !opened.is_volume {
        return Chain {
            names,
            later,
            missing: None,
            not_rar: None,
        };
    }
    let mut current = first.to_owned();
    let mut continues = continues_past(opened);
    while continues {
        let Some(next) = next_volume_name(&current) else {
            break;
        };
        if !Path::new(&next).exists() {
            return Chain {
                names,
                later,
                missing: Some(next),
                not_rar: None,
            };
        }
        // Whether the chain continues is a property of the volume we just
        // added, so it is read after the file is known to exist. A volume
        // we cannot parse ends the chain rather than aborting the run; one
        // that is no RAR archive at all is kept by name for the listing
        // to say so (`list::every_volume`).
        let opened_next = match crate::engine::open_in(&next, session) {
            Ok(opened_next) => opened_next,
            Err(failure) => {
                let not_rar = matches!(failure, OpenFailure::NotAnArchive(_)).then(|| next.clone());
                names.push(next);
                return Chain {
                    names,
                    later,
                    missing: None,
                    not_rar,
                };
            }
        };
        continues = continues_past(&opened_next);
        later.push(opened_next);
        names.push(next.clone());
        current = next;
    }
    Chain {
        names,
        later,
        missing: None,
        not_rar: None,
    }
}

/// The set's FIRST volume, opened with its chain, when the command line
/// named a later one and the reference would start over there.
///
/// Measured against unrar 7.23 on 30 Sep 2026 over four-part sets of a
/// 10,000-byte member and a 2,000-byte one starting in the third volume,
/// each stored or compressed, naming the second and the third volume:
/// the reference
/// says the named volume's banner, then walks the set from its first
/// volume, whenever the member continued into the named volume is
/// selected (with no mask it always is) or any selected member is STORED;
/// otherwise it starts at the named volume, as this did every time. From
/// the named volume the continued member was tested as though it began
/// there, and failed its checksum (exit 3 where the reference's is 0).
///
/// A SOLID set starts over whatever is selected. Measured against unrar
/// 7.23 on 9 Oct 2026 over a nine-part set written by rar 7.23 (`a -ma5
/// -v50k -m3 -s`, eight members), naming parts three, five, seven and
/// nine with one member named each time (one that begins after the named
/// volume, one that ends before it, one continued into it, one that
/// matches nothing): every run says the named volume's banner and then
/// walks from the first volume, passing over the members in front. A
/// member of a solid chain is decoded from the chain's first, and from
/// the named volume the member failed its checksum and no file was
/// written (SWEEP3-08OCT-02).
pub(super) fn restart_at_first(
    path: &str,
    named: &Opened,
    session: &mut rarkit::Session,
    selection: &Selection,
) -> Option<(Opened, Chain)> {
    if !named.is_volume {
        return None;
    }
    let first_name = first_volume_name(path).filter(|name| name != path)?;
    if !Path::new(&first_name).exists() {
        return None;
    }
    let continued_selected = named
        .members
        .iter()
        .find(|member| member.split_before)
        .is_some_and(|member| selection.keeps(member));
    let opened = crate::engine::open_in(&first_name, session).ok()?;
    let chain = volume_chain(&first_name, &opened, session);
    if !chain.names.iter().any(|name| name == path) {
        return None;
    }
    let stored_selected = opened
        .members
        .iter()
        .chain(chain.later.iter().flat_map(|volume| volume.members.iter()))
        .any(|member| {
            !member.is_dir && !member.is_service && member.method == 0 && selection.keeps(member)
        });
    (named.solid || continued_selected || stored_selected).then_some((opened, chain))
}

/// Where the last `.part`, in any ASCII case, starts in `path`: a byte
/// offset of `path` itself, on a character boundary, with five ASCII bytes
/// after it. Looked for in the name as it is: a lowercased copy's offsets
/// are not the name's wherever lowercasing changes a character's length.
fn part_at(path: &str) -> Option<usize> {
    path.as_bytes()
        .windows(5)
        .rposition(|window| window.eq_ignore_ascii_case(b".part"))
}

/// `arc.part3.rar` to `arc.part1.rar`, and `arc.r01` to `arc.rar`: the
/// first volume of the set a volume's name belongs to.
pub(super) fn first_volume_name(path: &str) -> Option<String> {
    if let Some(pos) = part_at(path) {
        let rest = &path[pos + 5..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 {
            return Some(format!(
                "{}{:0digits$}{}",
                &path[..pos + 5],
                1,
                &rest[digits..]
            ));
        }
    }
    let (stem, ext) = path.rsplit_once('.')?;
    let lower = ext.to_lowercase();
    let number = lower.strip_prefix('r')?;
    (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{stem}.rar"))
}

/// Whether the set goes on past this volume.
///
/// The volume's own end record answers it (SPEC-F 3.5.5): its "next
/// volume follows" bit is set in every volume but the last (SPEC-G
/// 3.10.3). A member split open at the volume's end also needs the next
/// one, whatever the end record says, and that is the only sign an
/// archive written with no end record gives. Reading the split flag
/// alone stopped short of a volume that begins with a NEW member, which
/// is the layout rarkit's writer makes when a member ends exactly at a
/// volume's end. Any member, not the last one: a volume's service
/// headers sort after its file data.
pub(super) fn continues_past(opened: &Opened) -> bool {
    opened.next_follows == Some(true) || opened.members.iter().any(|m| m.split_after)
}

/// `arc.part1.rar` to `arc.part2.rar`, and `arc.rar` to `arc.r00`.
pub(crate) fn next_volume_name(path: &str) -> Option<String> {
    if let Some(pos) = part_at(path) {
        let rest = &path[pos + 5..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() {
            let width = digits.len();
            let next: u64 = digits.parse().ok()?;
            return Some(format!(
                "{}{:0width$}{}",
                &path[..pos + 5],
                next.checked_add(1)?,
                &rest[digits.len()..]
            ));
        }
    }
    let (stem, ext) = path.rsplit_once('.')?;
    if ext.eq_ignore_ascii_case("rar") {
        return Some(format!("{stem}.r00"));
    }
    let lower = ext.to_lowercase();
    let digits = lower.strip_prefix('r')?;
    let number: u64 = digits.parse().ok()?;
    Some(format!(
        "{stem}.r{:0width$}",
        number.checked_add(1)?,
        width = digits.len()
    ))
}
