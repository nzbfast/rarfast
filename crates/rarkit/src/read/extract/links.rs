//! Redirected members: a RAR 5 redirection record and a RAR 4 link, read
//! into what the sink is told.

use super::*;

/// One redirection member (spec F 3.8.1): never delivered as bytes.
///
/// At `open` its [`MemberInfo::redirection`] carries the target. A RAR 5
/// member's data area is never read and its declared size sizes nothing;
/// its verdict is the check of ZERO bytes against the stored checksum,
/// MAC-converted when the member is encrypted (3.2.6.2), and it takes
/// nothing from and gives nothing to a solid chain. A RAR 4 family link's
/// target is its content (3.3.12), decoded here into a bounded buffer and
/// checked BEFORE `open`, as a member of its chain like any other.
///
/// A sink that answers `Write` gets nothing written to its writer: the
/// caller's `open` is refused at the entry point ([`Guarded`]); a
/// driver's own writer is handed back through `close` with no bytes.
#[allow(clippy::too_many_arguments)]
pub(super) fn redirected<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    redirect: Redirect,
    chain_started: &mut bool,
    decoders: &mut Decoders,
) -> Result<()> {
    // Held apart from the arena, which the member's stream borrows, in a
    // buffer the operation keeps: nothing is allocated per member.
    let mut target = std::mem::take(&mut run.scratch.target);
    target.clear();
    let outcome = if redirect.in_content {
        rar4_link(
            run,
            walk,
            gate,
            block,
            file,
            name,
            redirect,
            &mut target,
            chain_started,
            decoders,
        )
    } else {
        target.extend_from_slice(walk.arena().get(redirect.target()).unwrap_or(&[]));
        rar5_redirect(run, walk, gate, block, file, name, redirect, &target)
    };
    run.scratch.target = target;
    outcome
}

#[allow(clippy::too_many_arguments)]
pub(super) fn rar5_redirect<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    redirect: Redirect,
    target: &[u8],
) -> Result<()> {
    let format = walk.format;
    let mut info = info_of(name, file, &block.data);
    info.redirection = Some(Redirection {
        kind: redirect.kind(),
        target: Some(target),
        target_is_directory: redirect.dir,
    });
    let out = match run.driver.open(&info)? {
        Disposition::Write(w) => Out::Write(w),
        Disposition::Verify => Out::Verify,
        Disposition::Skip => return skip_unread(run, walk, gate, block, file, name, &info),
    };
    if redirect.fault {
        let err = Error::new(ErrorKind::Corrupt(Corruption::Redirection));
        return close_unread(run, walk, gate, block, file, &info, Some(out), err);
    }
    let keys = match member_crypto(run, walk, file, format, None) {
        Ok((_, keys)) => keys,
        Err(e) => return close_unread(run, walk, gate, block, file, &info, Some(out), e),
    };
    let member = Member::of(
        Some(out),
        file,
        format,
        keys,
        &mut run.blake,
        // Nothing is decoded here, so no width is in hand and none is
        // needed: the hasher is fed no byte.
        run.policy.max_workers,
    );
    // The data area is skipped UNREAD, whatever it declares: the record
    // decides what the member is, and zero decoded bytes are checked
    // against the stored value (3.2.6.2's table).
    let mut stream = MemberStream::new(walk, gate, block, file, name);
    let skipped = stream.skip();
    let landed = land(stream, skipped, &mut run.scratch);
    if !landed.passed {
        walk.release(gate, landed.data.end)?;
    }
    let last = landed.later.as_deref().unwrap_or(file);
    close_member(
        run,
        member,
        last,
        &info,
        None,
        &landed.fragment_mismatches,
        landed.outcome,
        landed.broken,
    )
}

/// What a redirection the sink skipped is counted with: nothing read,
/// nothing judged.
const SKIPPED: MemberOutcome = MemberOutcome {
    checksum_ok: None,
    bytes: 0,
    password_refused: false,
    fragment_mismatches: 0,
};

/// A redirection member the sink skipped: its data area passed over
/// unread, and the member counted as a skipped file is
/// ([`Driver::skipped`]), with no `close`.
#[allow(clippy::too_many_arguments)]
fn skip_unread<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    info: &MemberInfo<'_>,
) -> Result<()> {
    pass_unread(walk, gate, block, file, name)?;
    run.driver.skipped(info, &SKIPPED, None)
}

/// A RAR 4 family symbolic link (spec F 3.3.12): its target is its
/// content, decoded here (bounded at 64 KiB) and checked before `open`.
#[allow(clippy::too_many_arguments)]
pub(super) fn rar4_link<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    redirect: Redirect,
    target: &mut Vec<u8>,
    chain_started: &mut bool,
    decoders: &mut Decoders,
) -> Result<()> {
    let format = walk.format;
    let solid_archive = walk.solid_archive;
    // The link is an ordinary member of its chain: the same bookkeeping
    // `member` keeps, for the same reasons.
    let solid_member = match format {
        Format::Rar13 => solid_archive && *chain_started,
        _ if file.unpack_version < 20 => solid_archive && *chain_started,
        _ => file.solid,
    };
    let solid_member = solid_member && !(walk.at_set_start && !*chain_started);
    let solid_chain = solid_archive && solid_member;
    let refused = if redirect.fault {
        Some(Error::new(ErrorKind::Corrupt(Corruption::Redirection)))
    } else if solid_chain && !*chain_started {
        Some(Error::new(ErrorKind::Corrupt(Corruption::Stream)))
    } else {
        None
    };
    if refused.is_none() && !solid_member {
        *chain_started = true;
    }
    // A link refused here is never decoded, so the window lacks its bytes
    // and the chain is broken as if its head were missing: its later
    // members fail `Corrupt(Stream)` until one with its bit clear starts
    // the next, as after a member `member` refuses (spec F 3.2.6).
    if refused.is_some() && solid_archive {
        *chain_started = false;
    }
    let continues = solid_chain || (solid_archive && file.unpacked_size == Some(0));
    let prepared = match (refused, codec_of(file, format, solid_archive)) {
        (Some(err), _) => Err(err),
        (None, Codec::Missing(kind)) => {
            // The chain breaks here, as in `member`.
            if solid_archive {
                *chain_started = false;
            }
            Err(Error::new(kind))
        }
        (None, codec) => {
            if file.encrypted {
                reading::quiesce(run, walk, file, format)?;
            }
            let probe = Probe {
                block,
                solid_archive,
                continues,
                decoders: &mut *decoders,
            };
            member_crypto(run, walk, file, format, Some(probe)).map(|crypto| (codec, crypto))
        }
    };
    let (codec, (cipher, keys)) = match prepared {
        Ok(ready) => ready,
        Err(err) => {
            let mut info = info_of(name, file, &block.data);
            info.redirection = Some(Redirection {
                kind: redirect.kind(),
                target: Some(&[]),
                target_is_directory: false,
            });
            let out = match run.driver.open(&info)? {
                Disposition::Write(w) => Out::Write(w),
                Disposition::Verify => Out::Verify,
                Disposition::Skip => return skip_unread(run, walk, gate, block, file, name, &info),
            };
            return close_unread(run, walk, gate, block, file, &info, Some(out), err);
        }
    };
    let mut stream = MemberStream::new(walk, gate, block, file, name);
    let mut member = Member::of(
        Some(Out::Write(&mut *target)),
        file,
        format,
        keys,
        &mut run.blake,
        blake_workers(&run.policy, decoders),
    );
    let policy = run.policy;
    let decoded = decode(
        &mut stream,
        &mut member,
        &mut run.blake,
        &mut Unreported,
        cipher.map(MemberDecryptor::new),
        codec,
        decoders,
        &mut run.scratch,
        &policy,
        continues,
        None,
    );
    let landed = land(stream, decoded, &mut run.scratch);
    if !landed.passed {
        walk.release(gate, landed.data.end)?;
    }
    let last = landed.later.as_deref().unwrap_or(file);
    let checksum_ok = verdict(&member, &mut run.blake, last, false);
    drop(member);
    let mut info = info_of(name, file, &block.data);
    info.redirection = Some(Redirection {
        kind: redirect.kind(),
        target: Some(target.as_slice()),
        target_is_directory: false,
    });
    let value = match run.driver.open(&info)? {
        Disposition::Write(w) => Some(w),
        Disposition::Verify => None,
        // Its data area is already read: the target was decoded first.
        Disposition::Skip => return run.driver.skipped(&info, &SKIPPED, None),
    };
    let err = match landed.outcome {
        Err(e) if landed.broken || ends_operation(&e) => return Err(e),
        Err(e) => Some(e),
        // No host takes a NUL inside a link's target (3.8.2).
        Ok(()) if target.contains(&0) => {
            Some(Error::new(ErrorKind::Corrupt(Corruption::Redirection)))
        }
        Ok(()) => None,
    };
    let checksum_ok = if err.is_some() {
        Some(false)
    } else {
        checksum_ok
    };
    // After its `open`, which a link's decode comes before (3.8.1).
    let mismatches = report_mismatches(run, &info, &landed.fragment_mismatches)?;
    let err = err.map(|e| e.with_member(name));
    run.driver.close(
        &info,
        value,
        &MemberOutcome {
            checksum_ok,
            bytes: 0,
            password_refused: crate::read::password_refused(err.as_ref()),
            fragment_mismatches: mismatches,
        },
        err,
    )
}
