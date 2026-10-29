//! The blocks that are not payload: the archive's head, each member's
//! header, the comment, the quick-open block and the end of a volume.

use super::*;

/// The signature every RAR 5 volume opens with.
pub(super) const RAR5_SIGNATURE: &[u8] =
    crate::carry::b_writers::rar50::write::reference::RAR5_SIGNATURE;

/// Data larger than this earns a cached header in the quick-open block.
pub(super) const QUICK_OPEN_MIN_DATA: u64 =
    crate::carry::b_writers::rar50::write::reference::QUICK_OPEN_MIN_DATA as u64;

/// The buffers one member header is built through, owned by the run and
/// reused by every member of it (spec G 7.3: no allocation per header,
/// per name or per chunk).
///
/// A member that is CORRECTED builds its header twice, and the second
/// one goes through these same buffers: the first is already written out
/// by then, and only its length is still wanted.
#[derive(Default)]
pub(super) struct HeaderScratch {
    /// The header image, complete.
    pub(super) bytes: Vec<u8>,
    /// What the family's emitter lays the header out through.
    pub(super) inner: rar5::Scratch,
    /// A member's name in the form the RAR 4 family stores.
    pub(super) name: Vec<u8>,
}

impl HeaderScratch {
    /// What these buffers hold NOW, for the run's working-memory figure
    /// (spec G 7.2). They follow the widest header the run has built,
    /// which follows the longest NAME and never the member's size.
    ///
    /// Bytes TOUCHED and not capacity, which is the rule for
    /// every term of that figure: a buffer's untouched reserve costs
    /// address space and not memory, so it is not working memory. These
    /// buffers are cleared and refilled for each header, so this is only
    /// a peak when it is sampled as one - [`Run::note_peak`] does that,
    /// from [`Run::write_header_and_cache`].
    pub(super) fn held(&self) -> u64 {
        (self.bytes.len()
            + self.name.len()
            + self.inner.extra.len()
            + self.inner.specific.len()
            + self.inner.body.len()
            + self.inner.header.len()) as u64
    }
}

/// What the reference layout has to know before the main header is laid
/// down (spec G 3.6.2 and 3.6.3).
///
/// The reference lays the main header out first and PATCHES the locator's
/// quick-open offset once the block's position is known. Every length
/// here is a function of the members and the options, so this run works
/// the offset out BEFORE it writes, which produces the same bytes and
/// needs no seek and no hold. A header's length does not depend on the
/// value of a checksum, only on its kind, so a payload whose checksum is
/// not yet known does not disturb it.
pub(super) struct ReferencePlan {
    /// The width the locator's quick-open offset takes.
    pub(super) reserve: usize,
    /// Where the quick-open block will start, counted from the first byte
    /// after the signature, or none when no member earns a cached header.
    pub(super) quick_open_offset: Option<u64>,
    /// Where the recovery record block will start, counted the same way,
    /// when the archive carries one (spec G 3.11). It sits after the
    /// quick-open block, and the reference writes it at the same reserved
    /// width as the quick-open offset (measured on rar 7.23: 3 bytes for
    /// one 3 byte member, 5 for 70 KB and for 500 KB, and with `-qo-`
    /// the locator carries this offset alone).
    pub(super) recovery_offset: Option<u64>,
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// Writes one block HEADER, through the header cipher when the
    /// archive has one. Returns where the block starts, so that a header
    /// corrected after its payload has passed can replace it.
    ///
    /// A block's data area is NOT written through here: a member's bytes
    /// carry their own cipher (spec K 3.6), exactly as they do without
    /// header encryption.
    pub(super) fn write_header(&mut self, header: &[u8]) -> Result<u64> {
        let at = self.out.position();
        match self.header_key.as_mut() {
            None => self.out.write(header)?,
            Some(key) => {
                let mut iv = [0u8; 16];
                match self.header_iv_next.take() {
                    Some(ahead) => iv = ahead,
                    None => self.draw.fill(&mut iv)?,
                }
                self.header_iv = iv;
                let wrapped = key.wrap(header, &iv)?;
                self.out.write(&wrapped)?;
            }
        }
        Ok(at)
    }

    /// Replaces a header written earlier with its corrected form, under
    /// the SAME initialisation vector, so the block is exactly as long.
    pub(super) fn correct_header(&mut self, at: u64, header: &[u8]) -> Result<()> {
        match self.header_key.as_mut() {
            None => self.out.correct(at, header),
            Some(key) => {
                let iv = self.header_iv;
                let wrapped = key.wrap(header, &iv)?;
                self.out.correct(at, &wrapped)
            }
        }
    }

    // ---- the archive's own blocks --------------------------------------

    pub(super) fn write_archive_head(&mut self, first: bool) -> Result<()> {
        match self.options.format {
            WriteFormat::Rar5 => {
                self.out.write(RAR5_SIGNATURE)?;
                // Written FIRST, before the main header, and itself in
                // clear; every block after it is encrypted (spec G 3.3.6).
                if let Some(key) = &self.header_key {
                    let body = rar5_archive_encryption_body(&self.header_salt, key);
                    let block = rar5::frame(BLOCK_TYPE_ARCHIVE_ENCRYPTION, 0, None, &body, &[]);
                    self.out.write(&block)?;
                }
                let locator = self.reference.as_ref().and_then(|plan| {
                    reference_locator(
                        plan.reserve,
                        self.options.quick_open(),
                        self.options.recovery_percent.is_some(),
                        plan.quick_open_offset,
                        plan.recovery_offset,
                    )
                });
                let locator = locator.or(self.default_locator.map(|width| rar5::Locator {
                    quick_open: None,
                    recovery: Some((0, width)),
                }));
                let header = rar5::main_header(&self.main_plan(locator));
                self.main_at = self.write_header(&header)?;
            }
            WriteFormat::Rar4(_) => {
                self.out.write(RAR4_MARKER)?;
                let plan = rar4::MainPlan {
                    volume_set: self.options.volume_set(),
                    first_volume: first,
                    numbered_volumes: matches!(
                        self.options.volume_naming,
                        crate::write::VolumeNaming::Numbered
                    ),
                    locked: self.options.lock,
                    solid: self.options.solid,
                    recovery: self.options.recovery_percent.is_some(),
                    encrypted_headers: self.options.encrypt_headers,
                };
                // The RAR 4 family has no archive encryption header: its
                // main header stays in clear with flag 0x0080 set, and
                // every block after it is encrypted (`r4_hpw`).
                let header = rar4::main_header(&plan);
                self.out.write(&header)?;
            }
        }
        // Where this volume's first member can start, which is what the
        // FILE budget reads to tell a full volume from a cap that cannot
        // hold this member's header at all.
        self.head_bytes = self.out.position();
        Ok(())
    }

    /// How many bytes a header image of `plain` bytes takes in the volume:
    /// itself, or under header encryption the framing's prefix and the
    /// image zero padded to a whole cipher block (`HeaderKey::wrap`). The
    /// FILE budget pays for what lands in the file, so every figure it
    /// reserves for a header goes through this: until 29 Sep 2026 it
    /// reserved the PLAIN image, and a `-hp` set of 120,000 byte volumes
    /// wrote volumes of 120,030.
    pub(super) fn on_disk(&self, plain: usize) -> u64 {
        match &self.header_key {
            None => plain as u64,
            Some(key) => (key.prefix_len() + plain.next_multiple_of(CIPHER_BLOCK)) as u64,
        }
    }

    pub(super) fn write_comment(&mut self) -> Result<()> {
        let Some(comment) = self.options.comment.clone() else {
            return Ok(());
        };
        match self.options.format {
            WriteFormat::Rar5 => {
                let header = rar5::service_header(
                    SERVICE_COMMENT,
                    comment.len() as u64,
                    Some(crate::checksum::crc32(&comment)),
                    self.service_host(),
                    false,
                    None,
                    self.options.reserve,
                );
                self.write_header(&header)?;
            }
            WriteFormat::Rar4(_) => {
                let header = rar4::comment_sub_block(&comment, self.rar4_service_host());
                self.write_header(&header)?;
            }
        }
        self.out.write(&comment)?;
        Ok(())
    }

    pub(super) fn write_end(&mut self, next_volume: bool) -> Result<()> {
        match self.options.format {
            WriteFormat::Rar5 => {
                let header = rar5::end_header(next_volume);
                self.write_header(&header).map(|_| ())
            }
            WriteFormat::Rar4(_) => {
                let plan = rar4::EndPlan {
                    volume_set: self.options.volume_set(),
                    next_volume,
                    volume_number: self.volume as u16,
                };
                let header = rar4::end_block(&plan);
                self.write_header(&header).map(|_| ())
            }
        }
    }

    pub(super) fn write_quick_open(&mut self) -> Result<()> {
        if self.cached.is_empty() {
            return Ok(());
        }
        let start = self.out.position();
        let mut index = Vec::new();
        for (position, header) in &self.cached {
            index.extend_from_slice(&rar5::quick_open_entry(start - position, header));
        }
        let header = rar5::quick_open_header(index.len() as u64, self.service_host());
        self.write_header(&header)?;
        self.out.write(&index)?;
        Ok(())
    }

    /// The main header's plan for the open volume, carrying `locator`.
    pub(super) fn main_plan(&self, locator: Option<rar5::Locator>) -> rar5::MainPlan {
        rar5::MainPlan {
            volume_set: self.options.volume_set(),
            volume_number: self.volume,
            solid: self.options.solid,
            recovery: self.options.recovery_percent.is_some(),
            locked: self.options.lock,
            locator,
        }
    }

    /// One member's header, into `scratch.bytes`.
    pub(super) fn member_header(
        &self,
        index: usize,
        fragment: Fragment,
        packed: u64,
        digest: Option<Digest>,
        scratch: &mut HeaderScratch,
    ) {
        self.member_header_with(index, fragment, packed, digest, None, scratch)
    }

    /// The same, with a placeholder encryption record: the reference
    /// layout works a header's LENGTH out before the member's
    /// initialisation vector has been drawn, and the record is fixed
    /// width, so a placeholder of the right length answers it.
    pub(super) fn member_header_with(
        &self,
        index: usize,
        fragment: Fragment,
        packed: u64,
        digest: Option<Digest>,
        placeholder_record: Option<&[u8]>,
        scratch: &mut HeaderScratch,
    ) {
        let member = &self.members[index];
        match self.options.format {
            WriteFormat::Rar5 => {
                let plan = rar5::FilePlan {
                    name: member.name,
                    unpacked_size: member.size,
                    packed_size: packed,
                    attributes: u64::from(member.attributes),
                    host_os: rar5_host_byte(member.host_os),
                    is_directory: member.is_directory,
                    mtime: member.mtime,
                    digest,
                    compression: Compression {
                        method: self.member_method(index),
                        // A stored member carries power 0 in BOTH
                        // layouts. Spec G 3.4.1 says the reference writes
                        // a power that reflects its fitted dictionary even
                        // for a stored member; `vectors-G/refmodel.py`,
                        // which reproduces rar 7.23 on 24 shapes including
                        // a 1 MiB member, writes 0. The model is the
                        // stronger evidence and this follows it; the
                        // sentence in 3.4.1 is reported.
                        power: if self.member_stored(index) {
                            0
                        } else {
                            dictionary_power(self.dictionary)
                        },
                        solid: self.member_solid,
                    },
                    fragment,
                    reserve: self.options.reserve,
                    packed_reserve: self.packed_reserve(index),
                    // A fragment that is not the member's last carries the
                    // record without the MAC flag, since its checksum is
                    // not converted (spec K 3.7.6).
                    encryption: self
                        .crypt
                        .as_ref()
                        .and_then(|crypt| match fragment {
                            Fragment::First | Fragment::Middle => crypt.fragment_record.as_deref(),
                            Fragment::Whole | Fragment::Last => crypt.record.as_deref(),
                        })
                        .or(placeholder_record),
                    service_data: None,
                    service: false,
                };
                rar5::file_header_into(&plan, &mut scratch.inner, &mut scratch.bytes);
            }
            WriteFormat::Rar4(_) => {
                rar4_name_into(member.name, &mut scratch.name);
                let plan = rar4::FilePlan {
                    name: &scratch.name,
                    unpacked_size: member.size,
                    packed_size: packed,
                    host_os: rar4_host_byte(member.host_os),
                    crc32: rar4::crc_of(digest),
                    mtime: member.mtime,
                    method: self.member_method(index),
                    attributes: member.attributes,
                    is_directory: member.is_directory,
                    dictionary: rar4::dictionary_value(self.dictionary),
                    solid: self.member_solid,
                    fragment,
                    salt: self.crypt.as_ref().and_then(|crypt| crypt.salt),
                    sub_block: false,
                    skip_if_unknown: false,
                    after_name: &[],
                };
                rar4::file_header_into(&plan, &mut scratch.inner, &mut scratch.bytes);
            }
        }
    }

    pub(super) fn write_header_and_cache(
        &mut self,
        index: usize,
        header: &[u8],
        data: u64,
    ) -> Result<()> {
        // The header image is complete, which is where the header
        // buffers are at their widest for this member.
        self.note_peak();
        let at = self.write_header(header)?;
        self.cache_header(index, at, header, data);
        Ok(())
    }

    /// Caches a member's header for the quick-open block, when the layout
    /// asks for one and the member's data earns it (spec G 3.6.6).
    /// The copy this makes is the one allocation the quick-open block
    /// needs and it is per CACHED header, not per header: a member has
    /// to carry more than `QUICK_OPEN_MIN_DATA` to earn one, and the
    /// run's own header buffer is about to be overwritten by the next
    /// member (spec G 3.6.6).
    pub(super) fn cache_header(&mut self, _index: usize, at: u64, header: &[u8], data: u64) {
        if !self.options.quick_open() {
            return;
        }
        if data > QUICK_OPEN_MIN_DATA {
            self.cached.push((at, header.to_vec()));
        }
    }

    // ---- the reference layout -------------------------------------------

    /// Works out the locator's reserved width and where the quick-open
    /// and recovery record blocks will land, before the main header is
    /// written.
    pub(super) fn plan_reference(&self) -> ReferencePlan {
        let reserve = self.locator_reserve();
        let quick_open = self.options.quick_open();
        let recovery = self.options.recovery_percent.is_some();
        if !quick_open && !recovery {
            return ReferencePlan {
                reserve,
                quick_open_offset: None,
                recovery_offset: None,
            };
        }

        // Only the widths matter here, so the offsets are laid down as
        // zeros at the width they will be written in.
        let main = rar5::main_header(&rar5::MainPlan {
            volume_set: false,
            volume_number: 0,
            solid: self.options.solid,
            recovery,
            locked: self.options.lock,
            locator: reference_locator(reserve, quick_open, recovery, None, None),
        });

        let mut at = main.len() as u64;
        if let Some(comment) = &self.options.comment {
            let header = rar5::service_header(
                SERVICE_COMMENT,
                comment.len() as u64,
                Some(0),
                self.service_host(),
                false,
                None,
                self.options.reserve,
            );
            at += header.len() as u64 + comment.len() as u64;
        }

        // Each cached header's entry length depends on its own length and
        // on the width of its distance back from the block, and nothing
        // else (`rar5::quick_open_entry`), so the block's length is known
        // once every member's header has been laid out.
        let mut cached: Vec<(u64, usize)> = Vec::new();
        let mut scratch = HeaderScratch::default();
        for index in 0..self.members.len() {
            let size = if self.members[index].is_directory {
                0
            } else {
                self.members[index].size
            };
            let packed = if self.key.encrypting() {
                padded_len(size)
            } else {
                size
            };
            self.member_header_with(
                index,
                Fragment::Whole,
                packed,
                self.placeholder_digest(index),
                self.key.encrypting().then_some(&RECORD_PLACEHOLDER[..]),
                &mut scratch,
            );
            if quick_open && size > QUICK_OPEN_MIN_DATA {
                cached.push((at, scratch.bytes.len()));
            }
            at += scratch.bytes.len() as u64 + packed;
        }

        let quick_open_offset = (!cached.is_empty()).then_some(at);
        if quick_open_offset.is_some() {
            let index: u64 = cached
                .iter()
                .map(|&(header_at, len)| rar5::quick_open_entry_len(at - header_at, len))
                .sum();
            at += rar5::quick_open_header(index, self.service_host()).len() as u64 + index;
        }

        ReferencePlan {
            reserve,
            quick_open_offset,
            recovery_offset: recovery.then_some(at),
        }
    }

    // ---- small helpers ---------------------------------------------------

    /// A service block's host byte is the WRITER's platform, which is the
    /// opposite of a member's rule (spec G 3.3.4).
    pub(super) fn service_host(&self) -> u64 {
        rar5_host_byte(self.options.host_os)
    }

    pub(super) fn rar4_service_host(&self) -> u8 {
        rar4_host_byte(self.options.host_os)
    }
}

/// The reference layout's locator (spec G 3.6.2 and 3.11), as rar 7.23
/// writes it: the quick-open offset whenever the index is on, 0 when no
/// member earned an entry; the recovery record's offset whenever there is
/// a record; both at the one reserved width; and no locator at all when
/// neither is on (`-qo-` without `-rr`).
pub(super) fn reference_locator(
    reserve: usize,
    quick_open: bool,
    recovery: bool,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
) -> Option<rar5::Locator> {
    (quick_open || recovery).then(|| rar5::Locator {
        quick_open: quick_open.then(|| (quick_open_offset.unwrap_or(0), reserve)),
        recovery: recovery.then(|| (recovery_offset.unwrap_or(0), reserve)),
    })
}

/// A RAR 5 encryption record's fixed length, for the reference layout's
/// look ahead: version, flags, exponent, salt, initialisation vector and
/// the check record (spec K 3.5).
pub(super) const RECORD_PLACEHOLDER: [u8; 47] = [0; 47];

/// A member's name in the form its family stores: RAR 5 keeps the API's
/// `/`, and RAR 4 uses a backslash (spec G 3.14.5).
pub(super) fn rar4_name_into(name: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend(
        name.iter()
            .map(|byte| if *byte == b'/' { b'\\' } else { *byte }),
    );
}
