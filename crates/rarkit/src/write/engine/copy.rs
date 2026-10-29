//! The copy of a stored member's payload: one buffer, the cipher where the
//! run has one, and the read ahead of the writing thread.

use super::*;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    // ---- the worker team (a non-solid set of many members) --------------

    /// How many helper threads a stored member's copy may run beside the
    /// calling thread. The read side's hard ceiling
    /// applies to the write side: `-mt N` means at most
    /// N engine threads beside the caller's own, and the reading, digest
    /// and cipher stages all count (`read_ahead`, `digest_beside`).
    ///
    /// N is [`WriteOptions::workers`](crate::WriteOptions::workers), which
    /// is what `-mt` sets, or the width of the caller's pool where no
    /// figure was named. A memory policy whose thread ceiling is one
    /// (`max_workers: 1`) is a writer that starts no thread for a copy, as
    /// it always was, and so is a build without the `parallel` feature,
    /// which SPEC-API 7.2 holds to ONE thread in all.
    pub(super) fn helpers(&self) -> usize {
        if self.options.memory.max_workers <= 1 || cfg!(not(feature = "parallel")) {
            return 0;
        }
        // Chains running ahead are helpers already (`Run::start_chains`):
        // what they hold is not the stored copy's to spend again.
        self.options
            .encoder_width()
            .min(width::pool_width())
            .saturating_sub(self.chain_threads())
    }

    /// The last cipher block of an encrypted member: the held remainder,
    /// zero padded, which is what the reference pads with.
    pub(super) fn flush_cipher(&mut self) -> Result<()> {
        let Some(crypt) = self.crypt.as_mut() else {
            return Ok(());
        };
        crypt.finish(&mut self.cipher_out)?;
        if self.cipher_out.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.cipher_out);
        self.out.write(&bytes)?;
        self.cipher_out = bytes;
        Ok(())
    }

    /// A reader with more bytes than it declared is a lie about the
    /// archive's contents, not a rounding error (spec G 3.7.2).
    pub(super) fn check_payload_end(&mut self, index: usize) -> Result<()> {
        if self.end_checked.take() == Some(index) {
            return Ok(());
        }
        let Payload::Reader { reader, .. } = &mut self.members[index].payload else {
            return Ok(());
        };
        let mut over = [0u8; 1];
        match reader.read(&mut over) {
            Ok(0) => Ok(()),
            Ok(_) => Err(Error::new(ErrorKind::Corrupt(Corruption::PayloadLength))
                .with_member(self.members[index].name)),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// The CRC32 of a small STORED reader member, taken before its header
    /// is laid down: the whole member is read into the copy buffer here,
    /// hashed, and written from there by [`Run::copy_payload`], so the
    /// header carries its checksum from the start and is never corrected.
    ///
    /// **What it saves.** Over a seekable output a header laid down with a
    /// placeholder is corrected where it lies once its member has passed
    /// (`Out::correct`), and on the CLI's direct output that correction
    /// settles the blocks in flight and seeks back to the end: one `lseek`
    /// a member, 20,046 of them over 20,000 small members at `-m0`
    /// (an 8 core x86-64 Linux box, 15 Oct 2026). A member that fits the buffer is
    /// read once whichever way round, so the order is all that changes;
    /// the header's bytes are the same, because the checksum it is
    /// corrected to is the one it now starts with.
    ///
    /// `None`, leaving the member to the placeholder as before, for
    /// anything else: a compressed member (its header carries the
    /// UNPACKED digest, taken before the encode), an output that cannot
    /// seek (it holds its bytes instead, which `WriteReport` states), a
    /// volume set (where a member may be cut into fragments), a caller's
    /// stated CRC32 (checked against the bytes as they pass), a member a
    /// chain enciphers ahead, and BLAKE2sp (whose digest is built for the
    /// helper budget, not counted here).
    pub(super) fn digest_before_header(
        &mut self,
        index: usize,
        size: u64,
    ) -> Result<Option<Digest>> {
        if size == 0
            || size > self.buffer.len() as u64
            || !self.packed.is_empty()
            || !self.out.can_patch()
            || self.options.volume_set()
            || self.options.checksum != ChecksumKind::Crc32
            || self.declared_crc32(index).is_some()
            || self.chain_now.is_some()
            || self
                .chains
                .front()
                .is_some_and(|chain| chain.index == index)
        {
            return Ok(None);
        }
        let Run {
            members,
            buffer,
            prefix,
            ..
        } = self;
        let Payload::Reader { reader, .. } = &mut members[index].payload else {
            return Ok(None);
        };
        // The serial copy's own read: the held head first, then the
        // reader, a short read being `Truncated`.
        let span = &mut buffer[..size as usize];
        let mut filled = 0;
        while filled < span.len() {
            let read = prefix
                .read(index, &mut **reader, &mut span[filled..])
                .map_err(Error::from)?;
            if read == 0 {
                return Err(Error::new(ErrorKind::Truncated));
            }
            filled += read;
        }
        let mut digest = self.copy_digest();
        digest.update(&self.buffer[..size as usize]);
        self.buffered = Some(index);
        Ok(Some(digest.finish()))
    }

    /// Copies `len` bytes of member `index` from offset `at`, through the
    /// one buffer, hashing the PLAINTEXT as it passes and encrypting it
    /// on the way out when the member is encrypted. A `fragment` digest is
    /// asked for only on a fragment that is not the member's last, and
    /// under RAR 5 encryption it is taken over the CIPHERTEXT instead,
    /// which is what such a fragment carries (spec K 3.7.6).
    pub(super) fn copy_payload(
        &mut self,
        index: usize,
        at: u64,
        len: u64,
        total: u64,
        fragment: Option<&mut Running>,
        whole: Option<&mut Running>,
    ) -> Result<()> {
        let mut left = len;
        // Asked only for a span long enough to spend a helper on: the
        // budget reads the pool's width, and a first read of it builds the
        // global pool, which is not a stored member's to allocate (spec G
        // 7.3; `tests/write_allocation.rs`).
        let helpers = if len >= READ_AHEAD_FLOOR.min(DIGEST_BESIDE_FLOOR) {
            self.helpers()
        } else {
            0
        };
        // Borrow the payload, the buffers and the sink apart from the rest.
        let Run {
            members,
            buffer,
            buffered,
            ahead_pool,
            out,
            crypt,
            cipher_out,
            packed,
            progress,
            delivered,
            prefix,
            ..
        } = self;

        // One report per chunk, never one per byte and never one that
        // allocates (spec G 3.13). What is reported is the payload bytes
        // written so far over ALL members, which is what
        // `Progress::output` means on both sides of the API.
        let step = |bytes: usize, delivered: &mut u64, progress: &mut P| -> Result<()> {
            *delivered += bytes as u64;
            progress.output(*delivered)
        };

        let cipher_fragment = fragment.is_some()
            && crypt
                .as_ref()
                .is_some_and(MemberCrypt::fragments_digest_ciphertext);
        let (mut fragment, mut whole) = (fragment, whole);
        let beside = digest_beside(len, helpers, fragment.is_some() || whole.is_some());
        let ahead = reads_ahead(len, helpers);
        let mut emit = |chunk: &[u8],
                        out: &mut Out<V>,
                        crypt: &mut Option<MemberCrypt>,
                        cipher_out: &mut Vec<u8>|
         -> Result<()> {
            if let Some(whole) = whole.as_deref_mut() {
                whole.update(chunk);
            }
            let written: &[u8] = match crypt {
                None => chunk,
                Some(crypt) => {
                    crypt.push(chunk, cipher_out)?;
                    cipher_out
                }
            };
            // A fragment's own checksum is over the bytes that land in the
            // volume where `cipher_fragment` says so (spec K 3.7.6), and
            // over the plaintext otherwise.
            if let Some(fragment) = fragment.as_deref_mut() {
                fragment.update(if cipher_fragment { written } else { chunk });
            }
            out.write(written)
        };

        if !packed.is_empty() {
            // A compressed member: what goes out is the encoder's bytes,
            // and the digest that matters is the UNPACKED one, which was
            // taken before the encode. The fragment digest below is over
            // these bytes, which is what a fragment's checksum field
            // carries (spec F 3.5.6).
            let start = at as usize;
            let end = start + len as usize;
            for chunk in packed[start..end].chunks(COPY_CHUNK) {
                let written: &[u8] = match crypt {
                    None => chunk,
                    Some(crypt) => {
                        crypt.push(chunk, cipher_out)?;
                        cipher_out
                    }
                };
                if let Some(fragment) = fragment.as_deref_mut() {
                    fragment.update(if cipher_fragment { written } else { chunk });
                }
                out.write(written)?;
                step(chunk.len(), delivered, progress)?;
            }
            // Falls through to the sample below rather than returning
            // here, so that the enciphered chunk is counted on this path
            // too.
        } else if buffered.take() == Some(index) {
            // Read and hashed before its header (`Run::digest_before_header`):
            // the whole member is in the buffer already.
            let span = &buffer[at as usize..(at + len) as usize];
            emit(span, out, crypt, cipher_out)?;
            step(span.len(), delivered, progress)?;
        } else {
            match &mut members[index].payload {
                Payload::Bytes(data) if beside => {
                    // The bytes are all in hand, so their digest does not
                    // have to ride the copy: it runs over the same span on
                    // a second thread while this one writes it out. A
                    // fragment digest over the CIPHERTEXT cannot, since
                    // those bytes exist only here, so it rides the copy.
                    let data: &[u8] = data;
                    let span = &data[at as usize..(at + len) as usize];
                    let mut on_copy = if cipher_fragment {
                        fragment.take()
                    } else {
                        None
                    };
                    let (fragment, whole) = (fragment.take(), whole.take());
                    #[cfg(test)]
                    BESIDE.with(|count| count.set(count.get() + 1));
                    std::thread::scope(|scope| -> Result<()> {
                        #[cfg(test)]
                        let census = HELPERS.with(std::sync::Arc::clone);
                        let hasher = scope.spawn(move || {
                            #[cfg(test)]
                            let _live = Live::enter(&census);
                            if let Some(fragment) = fragment {
                                fragment.update(span);
                            }
                            if let Some(whole) = whole {
                                whole.update(span);
                            }
                        });
                        let mut written: Result<()> = Ok(());
                        for chunk in span.chunks(COPY_CHUNK) {
                            written = match crypt {
                                None => out.write(chunk),
                                Some(crypt) => crypt.push(chunk, cipher_out).and_then(|()| {
                                    if let Some(fragment) = on_copy.as_deref_mut() {
                                        fragment.update(cipher_out);
                                    }
                                    out.write(cipher_out)
                                }),
                            }
                            .and_then(|()| step(chunk.len(), delivered, progress));
                            if written.is_err() {
                                break;
                            }
                        }
                        // Joined on every path, the error one included: the
                        // digest's state is the caller's and must not be
                        // left half fed by a thread still running.
                        if let Err(panic) = hasher.join() {
                            std::panic::resume_unwind(panic);
                        }
                        written
                    })?;
                }
                Payload::Bytes(data) => {
                    let start = at as usize;
                    let end = start + len as usize;
                    for chunk in data[start..end].chunks(COPY_CHUNK) {
                        emit(chunk, out, crypt, cipher_out)?;
                        step(chunk.len(), delivered, progress)?;
                    }
                }
                Payload::Reader { reader, .. } if ahead => {
                    // The reading, the plaintext digests and the cipher
                    // run on helper threads, as many as the helper budget allows,
                    // and this one writes (`read_ahead`). A fragment
                    // digest over the CIPHERTEXT goes with the cipher.
                    let on_copy = if cipher_fragment {
                        fragment.take()
                    } else {
                        None
                    };
                    let digests = [fragment.take(), whole.take()];
                    let cipher = crypt.as_mut().map(|crypt| CipherWork {
                        crypt,
                        digest: on_copy,
                    });
                    #[cfg(test)]
                    AHEAD.with(|count| count.set(count.get() + 1));
                    // The held head of a member spec G 3.8.3 sampled is
                    // the start of what the reading must take, before the
                    // reader itself (`store::Prefix::then`).
                    let mut source = prefix.then(index, &mut **reader);
                    read_ahead(
                        &mut source,
                        len,
                        ahead_pool,
                        helpers,
                        digests,
                        cipher,
                        |bytes, plain| {
                            out.write(bytes)?;
                            // One report per plaintext `COPY_CHUNK`, the
                            // serial copy's cadence (spec G 3.13).
                            let mut left = plain;
                            while left > 0 {
                                let piece = left.min(COPY_CHUNK);
                                step(piece, delivered, progress)?;
                                left -= piece;
                            }
                            Ok(())
                        },
                    )?;
                }
                Payload::Reader { reader, .. } => {
                    while left > 0 {
                        let want = left.min(buffer.len() as u64) as usize;
                        let read = prefix
                            .read(index, &mut **reader, &mut buffer[..want])
                            .map_err(Error::from)?;
                        if read == 0 {
                            return Err(Error::new(ErrorKind::Truncated));
                        }
                        emit(&buffer[..read], out, crypt, cipher_out)?;
                        step(read, delivered, progress)?;
                        left -= read as u64;
                    }
                }
            }
        }
        // ONCE, and not per chunk. The only term that grows inside the
        // loops above is `cipher_out`, which holds ONE chunk and is
        // bounded by `COPY_CHUNK` however long the member is; the kept
        // recovery copy grows here too and is sampled where it peaks,
        // at `Run::close_volume`. Sampling per chunk would put this in
        // an inner copy loop for no figure it would change.
        self.note_peak();
        Ok(())
    }
}

/// The shortest reader payload span that is READ AHEAD on a second
/// thread ([`read_ahead`]) rather than read inside the copy loop. The
/// same arithmetic floor as [`DIGEST_BESIDE_FLOOR`]: a scoped spawn and
/// join against a few milliseconds of reading.
pub(super) const READ_AHEAD_FLOOR: u64 = 4 << 20;

/// One read-ahead buffer's length. Four of them, [`READ_AHEAD_DEPTH`], are
/// the whole of what the read-ahead holds, however long the member.
pub(super) const READ_AHEAD_CHUNK: usize = 2 << 20;

/// How many buffers the read-ahead cycles through: one being read, one
/// being written, and two of slack so that neither side waits on a short
/// stall of the other.
pub(super) const READ_AHEAD_DEPTH: usize = 4;

/// Whether a reader payload's span is read ahead: at least
/// [`READ_AHEAD_FLOOR`] long, with at least one helper thread to spend
/// ([`Run::helpers`]).
pub(super) fn reads_ahead(len: u64, helpers: usize) -> bool {
    helpers >= 1 && len >= READ_AHEAD_FLOOR
}

/// Which stages of the read-ahead pipeline run on helper threads.
///
/// **The read side's hard ceiling applies
/// to the write side: `-mt N` means at most N engine threads
/// beside the caller's own.** The reader, the digest stage and the cipher
/// stage all count, so what does not get a thread of its own is folded
/// onto a neighbour, chosen by what pays most (counted with
/// `-hp` on a Zen 5 rental, 29 Sep 2026: the
/// AES-CBC chain 1.21 GB/s, a one-thread BLAKE2sp 4.4, the page-cache
/// write 7.9, the read 38, CRC32 47):
///
/// - an ENCRYPTED member's critical path is its CBC chain, one serial
///   stream a member, so a lone helper enciphers and the
///   caller reads, hashes and writes around it; a second helper reads,
///   with the plaintext digests; a third takes a digest of its own;
/// - a member in CLEAR with an expensive digest (BLAKE2sp) spends a lone
///   helper on that digest, the caller reading and writing, and a second
///   on reading; helpers beyond the stages widen the digest's team
///   (`Run::copy_digest`). Spending the second on the team instead, the
///   caller reading and writing, was measured and refused: on x86, where
///   the team does not widen, it put the read and the write on the
///   critical path, 2.97 s to 3.27 at the default width on 12 GiB
///   (a Zen 5 rental, untimed). With only CRC32, which costs less than
///   the read, a lone helper reads and hashes and a second takes the
///   digest;
/// - the digest stage takes the LAST digest wanted (the member's), and
///   the reading thread any other (a volume fragment's own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stages {
    pub(super) reader: bool,
    pub(super) digest: bool,
    pub(super) cipher: bool,
}

impl Stages {
    /// `digests` is how many plaintext digests are wanted (0 to 2), and
    /// `costly` whether they are BLAKE2sp.
    pub(super) fn plan(helpers: usize, digests: usize, costly: bool, cipher: bool) -> Stages {
        debug_assert!(helpers >= 1, "a pipeline with no helper to run it");
        let digest = digests > 0;
        match (cipher, helpers) {
            (true, 1) => Stages {
                reader: false,
                digest: false,
                cipher: true,
            },
            (true, 2) => Stages {
                reader: true,
                digest: false,
                cipher: true,
            },
            (true, _) => Stages {
                reader: true,
                digest,
                cipher: true,
            },
            (false, 1) => Stages {
                reader: !(digest && costly),
                digest: digest && costly,
                cipher: false,
            },
            (false, _) => Stages {
                reader: true,
                digest,
                cipher: false,
            },
        }
    }

    pub(super) fn threads(self) -> usize {
        usize::from(self.reader) + usize::from(self.digest) + usize::from(self.cipher)
    }
}

/// The member's cipher, lent to the pipeline for one span, and the
/// fragment digest that is taken over its CIPHERTEXT (RAR 5, spec K
/// 3.7.6), which only the enciphering thread can take.
pub(super) struct CipherWork<'c> {
    pub(super) crypt: &'c mut MemberCrypt,
    pub(super) digest: Option<&'c mut Running>,
}

/// One buffer on its way down the pipeline: `len` bytes of it are live,
/// and `plain` is how many PLAINTEXT bytes they stand for, which is what
/// progress counts (a cipher holds back a partial block until the next).
pub(super) struct Chunk {
    pub(super) buffer: Vec<u8>,
    pub(super) len: usize,
    pub(super) plain: usize,
}

pub(super) type Filled = Result<Chunk>;

/// Fills `buffer[..want]` from `reader`, a short read being `Truncated`.
pub(super) fn fill(reader: &mut (dyn Read + Send), buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => return Err(Error::new(ErrorKind::Truncated)),
            Ok(read) => filled += read,
            Err(error) => return Err(Error::from(error)),
        }
    }
    Ok(())
}

/// Enciphers one chunk into `into`, which is what the cipher stage and
/// the serial copy both do; the fragment digest over the ciphertext
/// follows it.
pub(super) fn encipher(work: &mut CipherWork<'_>, plain: &[u8], into: &mut Vec<u8>) -> Result<()> {
    work.crypt.push(plain, into)?;
    if let Some(digest) = work.digest.as_deref_mut() {
        digest.update(into);
    }
    Ok(())
}

/// Copies `len` bytes of `reader` into `sink`, spending at most `helpers`
/// threads beside this one on the stages [`Stages::plan`]
/// picks: reading, a second plaintext digest, and enciphering.
///
/// **What each thread does.** Without a cipher, the reading thread fills a
/// buffer, feeds it to the plaintext `digests` and passes it on; a digest
/// stage, where there is one, takes the second digest; this thread hands
/// the bytes to `sink`, which writes them. With a cipher, a CIPHER STAGE
/// runs the member's one serial CBC chain from each plaintext
/// buffer into a ciphertext buffer of its own, hands the plaintext buffer
/// straight back to be read into again, and passes the ciphertext on; so
/// the write, the read and the hashing sit beside the chain rather than
/// in series with it. With ONE helper that stage is the helper, and this
/// thread reads and hashes as well as writing, interleaved so that the
/// chain is never waiting on a buffer it could have had.
///
/// `sink` is given each run of bytes to write and the plaintext length it
/// stands for.
///
/// **What it holds**: [`READ_AHEAD_DEPTH`] plaintext buffers of
/// [`READ_AHEAD_CHUNK`], two more when the second digest has its stage,
/// and as many ciphertext buffers again when there is a cipher, all kept
/// in `pool` for the rest of the run, whatever `len` is. The bytes reach
/// `sink` in order, and every digest and every cipher block is taken over
/// the same bytes in the same order as the serial copy, so what is
/// written is the serial copy's.
///
/// **On failure** a stage passes the error on down the chain and stops;
/// this thread, stopping, drops its ends of every channel, which each
/// stage sees at its next send or wait. Every thread is joined on every
/// path, and a panic in one is carried on here.
pub(super) fn read_ahead(
    reader: &mut (dyn Read + Send),
    len: u64,
    pool: &mut Vec<Vec<u8>>,
    helpers: usize,
    digests: [Option<&mut Running>; 2],
    cipher: Option<CipherWork<'_>>,
    mut sink: impl FnMut(&[u8], usize) -> Result<()>,
) -> Result<()> {
    use std::sync::mpsc;

    // The member's digest is the LAST one wanted; with only one, it is
    // `second` whichever slot it came in, so the digest stage takes it.
    let [first, second] = match digests {
        [Some(one), None] => [None, Some(one)],
        both => both,
    };
    let costly = second.as_deref().is_some_and(Running::is_costly);
    let wanted = usize::from(first.is_some()) + usize::from(second.is_some());
    let stages = Stages::plan(helpers, wanted, costly, cipher.is_some());
    debug_assert!(stages.threads() <= helpers, "more helpers than allowed");
    let plain_depth = if stages.digest {
        READ_AHEAD_DEPTH + 2
    } else {
        READ_AHEAD_DEPTH
    };
    let cipher_depth = if stages.cipher { READ_AHEAD_DEPTH } else { 0 };
    while pool.len() < plain_depth + cipher_depth {
        pool.push(vec![0u8; READ_AHEAD_CHUNK]);
    }
    let mut buffers = pool.drain(..);
    let (empty_tx, empty_rx) = mpsc::channel::<Vec<u8>>();
    for buffer in buffers.by_ref().take(plain_depth) {
        // The receiver is alive until every stage has ended.
        let _ = empty_tx.send(buffer);
    }
    let (cipher_empty_tx, cipher_empty_rx) = mpsc::channel::<Vec<u8>>();
    for buffer in buffers {
        let _ = cipher_empty_tx.send(buffer);
    }
    #[cfg(test)]
    let census = HELPERS.with(std::sync::Arc::clone);

    std::thread::scope(|scope| {
        // Built from the end of the chain backwards: each stage is handed
        // the sender of the stage after it.
        let (full_tx, full_rx) = mpsc::sync_channel::<Filled>(plain_depth);

        // The cipher stage, last before this thread.
        let mut cipher_input = None;
        let cipher_thread = cipher.map(|mut work| {
            let (in_tx, in_rx) = mpsc::sync_channel::<Filled>(plain_depth);
            cipher_input = Some(in_tx);
            let out = full_tx.clone();
            let back = empty_tx.clone();
            #[cfg(test)]
            let census = std::sync::Arc::clone(&census);
            scope.spawn(move || {
                #[cfg(test)]
                let _live = Live::enter(&census);
                for item in in_rx {
                    let chunk = match item {
                        Ok(chunk) => chunk,
                        Err(error) => {
                            let _ = out.send(Err(error));
                            break;
                        }
                    };
                    let Ok(mut into) = cipher_empty_rx.recv() else {
                        break;
                    };
                    if let Err(error) = encipher(&mut work, &chunk.buffer[..chunk.len], &mut into) {
                        let _ = out.send(Err(error));
                        break;
                    }
                    let _ = back.send(chunk.buffer);
                    let len = into.len();
                    if out
                        .send(Ok(Chunk {
                            buffer: into,
                            len,
                            plain: chunk.len,
                        }))
                        .is_err()
                    {
                        break;
                    }
                }
                cipher_empty_rx
            })
        });
        // Where plaintext goes once it is read and hashed.
        let after_plain = cipher_input.unwrap_or_else(|| full_tx.clone());

        // The digest stage, between the reading and the rest.
        let (to_digest, digest_thread, reader_second) = if stages.digest {
            let (mid_tx, mid_rx) = mpsc::sync_channel::<Filled>(plain_depth);
            let second = second.expect("a digest stage with no second digest");
            let out = after_plain.clone();
            #[cfg(test)]
            let census = std::sync::Arc::clone(&census);
            let thread = scope.spawn(move || {
                #[cfg(test)]
                let _live = Live::enter(&census);
                for item in mid_rx {
                    if let Ok(chunk) = &item {
                        second.update(&chunk.buffer[..chunk.len]);
                    }
                    if out.send(item).is_err() {
                        break;
                    }
                }
            });
            (mid_tx, Some(thread), None)
        } else {
            (after_plain.clone(), None, second)
        };
        drop(after_plain);

        // The reading stage, or nothing when this thread reads.
        let mut local = None;
        let reader_thread = if stages.reader {
            let forward = to_digest;
            #[cfg(test)]
            let census = std::sync::Arc::clone(&census);
            Some(scope.spawn(move || {
                #[cfg(test)]
                let _live = Live::enter(&census);
                let (mut first, mut second) = (first, reader_second);
                let mut left = len;
                while left > 0 {
                    let Ok(mut buffer) = empty_rx.recv() else {
                        break;
                    };
                    let want = left.min(buffer.len() as u64) as usize;
                    if let Err(error) = fill(reader, &mut buffer[..want]) {
                        let _ = forward.send(Err(error));
                        break;
                    }
                    for digest in [first.as_deref_mut(), second.as_deref_mut()]
                        .into_iter()
                        .flatten()
                    {
                        digest.update(&buffer[..want]);
                    }
                    left -= want as u64;
                    let chunk = Chunk {
                        buffer,
                        len: want,
                        plain: want,
                    };
                    if forward.send(Ok(chunk)).is_err() {
                        break;
                    }
                }
                empty_rx
            }))
        } else {
            local = Some((to_digest, empty_rx, reader, first, reader_second));
            None
        };
        // Only the stages hold a sender of the last channel now, so a stage
        // that ends without an answer - a panic - ends this thread's wait.
        drop(full_tx);

        let mut outcome = Ok(());
        let mut done = 0u64;
        let mut sent = 0u64;
        'copy: while done < len {
            // With one helper, this thread keeps the cipher stage fed: every
            // plaintext buffer it has back is read, hashed and sent before
            // it waits on the next ciphertext.
            if let Some((forward, free, reader, first, second)) = local.as_mut() {
                while sent < len {
                    let Ok(mut buffer) = free.try_recv() else {
                        break;
                    };
                    let want = (len - sent).min(buffer.len() as u64) as usize;
                    if let Err(error) = fill(&mut **reader, &mut buffer[..want]) {
                        outcome = Err(error);
                        break 'copy;
                    }
                    for digest in [first.as_deref_mut(), second.as_deref_mut()]
                        .into_iter()
                        .flatten()
                    {
                        digest.update(&buffer[..want]);
                    }
                    sent += want as u64;
                    let chunk = Chunk {
                        buffer,
                        len: want,
                        plain: want,
                    };
                    if forward.send(Ok(chunk)).is_err() {
                        break 'copy;
                    }
                }
            }
            match full_rx.recv() {
                Ok(Ok(chunk)) => {
                    outcome = sink(&chunk.buffer[..chunk.len], chunk.plain);
                    done += chunk.plain as u64;
                    let _ = if stages.cipher {
                        cipher_empty_tx.send(chunk.buffer)
                    } else {
                        empty_tx.send(chunk.buffer)
                    };
                    if outcome.is_err() {
                        break;
                    }
                }
                Ok(Err(error)) => {
                    outcome = Err(error);
                    break;
                }
                // A stage ended without an answer, which only a panic
                // does; the joins below carry it on.
                Err(_) => break,
            }
        }
        drop(full_rx);
        drop(empty_tx);
        drop(cipher_empty_tx);
        let local_free = local.map(|(forward, free, ..)| {
            drop(forward);
            free
        });

        let mut panic = None;
        let keep = |rx: mpsc::Receiver<Vec<u8>>, pool: &mut Vec<Vec<u8>>| {
            pool.extend(rx.try_iter());
        };
        if let Some(thread) = reader_thread {
            match thread.join() {
                // Every buffer this span did not lose to a failure goes
                // back to the run.
                Ok(free) => keep(free, pool),
                Err(caught) => panic = Some(caught),
            }
        }
        if let Some(thread) = digest_thread {
            if let Err(caught) = thread.join() {
                panic.get_or_insert(caught);
            }
        }
        if let Some(thread) = cipher_thread {
            match thread.join() {
                Ok(free) => keep(free, pool),
                Err(caught) => {
                    panic.get_or_insert(caught);
                }
            }
        }
        if let Some(free) = local_free {
            keep(free, pool);
        }
        if let Some(caught) = panic {
            std::panic::resume_unwind(caught);
        }
        outcome
    })
}
