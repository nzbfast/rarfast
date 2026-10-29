//! Where the writer asks spec K for a cipher, and where the bytes it
//! returns go (spec G section 3.12).
//!
//! Every cipher, key, salt and initialisation vector is SPEC-K's. This
//! module's part is the ORDER and the PLACES: which members are
//! encrypted, what the header says about them, and that every entropy
//! byte is drawn from `WriteOptions::entropy`, in a fixed order, so that
//! a seeded source reproduces an archive byte for byte.

use crate::carry::b_writers::write_entropy::Seeded;
use crate::crypto::{Aes128Enc, Aes256Enc, Rar4Key, Rar5Keys, FLAG_CHECK, FLAG_MAC};
use crate::error::Error;
use crate::types::Password;
use crate::write::rar5::put_vint;
use crate::write::{Digest, Entropy};
use crate::Result;

/// The block a RAR 4 or RAR 5 cipher works in.
pub(crate) const CIPHER_BLOCK: usize = 16;

/// The KDF exponent this writer asks for, which is what reference `rar`
/// 7.23 writes (`r5_pw`: `kdf_count=15`).
pub(crate) const RAR5_KDF_LOG2: u8 = 15;

/// Where salts and initialisation vectors come from. A draw that fails is
/// the caller's error, never a silent fall back to the system.
pub(crate) enum Draw {
    /// The operating system's generator.
    Os,
    /// A fixed seed, for a reproducible archive.
    Seeded(Seeded),
    /// The caller's own generator.
    Source(Box<dyn crate::write::EntropySource>),
}

impl Draw {
    /// The source `options` chose.
    pub(crate) fn new(entropy: Entropy) -> Draw {
        match entropy {
            Entropy::Os => Draw::Os,
            Entropy::Seeded(seed) => Draw::Seeded(Seeded { seed, counter: 0 }),
            Entropy::Source(source) => Draw::Source(source),
        }
    }

    /// Fills `buf` completely.
    pub(crate) fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        match self {
            Draw::Os => getrandom::fill(buf).map_err(Error::caller),
            Draw::Seeded(state) => {
                state.fill(buf);
                Ok(())
            }
            Draw::Source(source) => source.fill(buf),
        }
    }
}

/// A header key and the salt it was derived from, which the archive
/// encryption header carries.
pub(crate) type HeaderKeyed = (HeaderKey, [u8; 16]);

/// What the archive derived once, and every member then uses.
pub(crate) enum ArchiveKey {
    /// No password: nothing is encrypted.
    None,
    /// RAR 5: one key derivation salt per archive (spec G 3.13).
    Rar5 { keys: Box<Rar5Keys>, salt: [u8; 16] },
    /// The RAR 4 family: one 8-byte salt per archive and the one key and
    /// IV derived from it (spec K 3.6.5), which every encrypted member's
    /// header names and, under header encryption, every block's prefix
    /// carries. Genuine writers do the same (3.6.2: every encrypted member
    /// of each observed `-ma4` archive shares one salt).
    Rar4 { key: Box<Rar4Key>, salt: [u8; 8] },
}

impl ArchiveKey {
    /// Derives what the archive needs, drawing its salt in the order
    /// section 3.13 fixes: the archive's first, then a member's.
    pub(crate) fn derive(
        password: Option<&Password>,
        rar4: bool,
        draw: &mut Draw,
    ) -> Result<ArchiveKey> {
        let Some(password) = password else {
            return Ok(ArchiveKey::None);
        };
        if rar4 {
            crate::crypto::rar4_check_write_password(password)?;
            let mut salt = [0u8; 8];
            draw.fill(&mut salt)?;
            let key = Rar4Key::derive(password.as_bytes(), Some(salt))
                .map_err(|_| crate::write::options::refuse("a RAR 4 password that is not UTF-8"))?;
            return Ok(ArchiveKey::Rar4 {
                key: Box::new(key),
                salt,
            });
        }
        let mut salt = [0u8; 16];
        draw.fill(&mut salt)?;
        let keys = Rar5Keys::derive(password.as_bytes(), &salt, RAR5_KDF_LOG2, None)?;
        Ok(ArchiveKey::Rar5 {
            keys: Box::new(keys),
            salt,
        })
    }

    /// The archive's key and, when `headers` asks for them, the header
    /// key with the salt the archive encryption header carries.
    ///
    /// **RAR 5 keys its headers with the archive's ONE salt** (spec K
    /// 3.7.7: "one 16-byte salt per archive ... the observed writer uses
    /// one salt for every member and for the archive encryption header"),
    /// so the header key IS the member key and one derivation serves
    /// both: a reader of the archive derives once, as it does for one
    /// `rar` made. Until 30 Sep 2026 this writer drew a second salt for the
    /// headers and ran a second derivation (on a helper thread when the
    /// width allowed), which cost every reader a second ladder.
    ///
    /// **So does the RAR 4 family** (spec K 3.6.5: "one 8-byte salt per
    /// archive ... the archive's one salt in front of each" encrypted
    /// block): the header key is the member key, and neither is derived
    /// again. Until 30 Sep 2026 that writer drew a salt and ran the
    /// derivation for every member, and a further salt for the headers.
    pub(crate) fn derive_with_headers(
        password: Option<&Password>,
        rar4: bool,
        headers: bool,
        draw: &mut Draw,
    ) -> Result<(ArchiveKey, Option<HeaderKeyed>)> {
        let key = ArchiveKey::derive(password, rar4, draw)?;
        let header = match (password, headers, &key) {
            (Some(_), true, ArchiveKey::Rar5 { keys, salt }) => {
                Some((HeaderKey::rar5(keys.as_ref().clone()), *salt))
            }
            (Some(_), true, ArchiveKey::Rar4 { key, salt }) => {
                Some(HeaderKey::rar4(key.as_ref().clone(), *salt))
            }
            _ => None,
        };
        Ok((key, header))
    }

    /// Whether members are encrypted at all.
    pub(crate) fn encrypting(&self) -> bool {
        !matches!(self, ArchiveKey::None)
    }
}

/// One member's cipher, and what its header must say about it.
pub(crate) struct MemberCrypt {
    cipher: Cipher,
    /// Plaintext bytes short of a whole cipher block, held until the next
    /// chunk completes one or the member ends and they are padded.
    carry: Vec<u8>,
    /// The RAR 5 encryption extra record (spec K 3.5), already built.
    pub(crate) record: Option<Vec<u8>>,
    /// The same record for a fragment that is NOT the member's last: the
    /// check flag alone, because such a fragment's checksum is the plain
    /// one of its ciphertext and is not MAC-converted (spec K 3.7.6).
    pub(crate) fragment_record: Option<Vec<u8>>,
    /// The RAR 4 salt the member's header carries.
    pub(crate) salt: Option<[u8; 8]>,
    /// The RAR 5 keys, for converting the stored checksums.
    mac: Option<Box<Rar5Keys>>,
}

enum Cipher {
    Aes128(Box<Aes128Enc>),
    Aes256(Box<Aes256Enc>),
}

impl MemberCrypt {
    /// The cipher for one member. A RAR 5 member's initialisation vector
    /// is drawn here, so that the draw order is one per member; a RAR 4
    /// member draws nothing, its IV being the archive key's own.
    pub(crate) fn new(archive: &ArchiveKey, draw: &mut Draw) -> Result<Option<MemberCrypt>> {
        match archive {
            ArchiveKey::None => Ok(None),
            ArchiveKey::Rar5 { keys, salt } => {
                let mut iv = [0u8; 16];
                draw.fill(&mut iv)?;
                let record = rar5_record(salt, &iv, keys, FLAG_CHECK | FLAG_MAC);
                let fragment_record = rar5_record(salt, &iv, keys, FLAG_CHECK);
                Ok(Some(MemberCrypt {
                    cipher: Cipher::Aes256(Box::new(Aes256Enc::new(keys, &iv))),
                    carry: Vec::with_capacity(CIPHER_BLOCK),
                    record: Some(record),
                    fragment_record: Some(fragment_record),
                    salt: None,
                    mac: Some(keys.clone()),
                }))
            }
            ArchiveKey::Rar4 { key, salt } => Ok(Some(MemberCrypt {
                cipher: Cipher::Aes128(Box::new(Aes128Enc::new(key))),
                carry: Vec::with_capacity(CIPHER_BLOCK),
                record: None,
                fragment_record: None,
                salt: Some(*salt),
                mac: None,
            })),
        }
    }

    /// A twin of a RAR 5 member's cipher that carries what its HEADERS say
    /// (the records, the checksum keys), for the thread that writes them
    /// while the cipher itself runs ahead on another (`write::engine`'s
    /// chains ahead). The twin's own chain is never fed.
    pub(crate) fn header_twin(&self) -> Option<MemberCrypt> {
        let keys = self.mac.as_ref()?;
        Some(MemberCrypt {
            cipher: Cipher::Aes256(Box::new(Aes256Enc::new(keys, &[0; 16]))),
            carry: Vec::new(),
            record: self.record.clone(),
            fragment_record: self.fragment_record.clone(),
            salt: self.salt,
            mac: Some(keys.clone()),
        })
    }

    /// Encrypts `plain` into `out`, whose previous contents are replaced.
    /// Bytes short of a whole block are held for the next call.
    ///
    /// The plaintext is read where it lies and the ciphertext written
    /// straight into `out` (`Aes256Enc::encrypt_from`), so a chunk is not
    /// first copied into `out` and then encrypted over. `out` keeps its
    /// length from one chunk to the next, so a run of equal chunks sizes
    /// it once and never writes it twice.
    pub(crate) fn push(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let total = self.carry.len() + plain.len();
        let whole = total - total % CIPHER_BLOCK;
        if out.len() < whole {
            out.resize(whole, 0);
        } else {
            out.truncate(whole);
        }
        if whole == 0 {
            self.carry.extend_from_slice(plain);
            return Ok(());
        }
        // A block begun by the last call is finished from the front of
        // this one and encrypted on its own; the chain carries on from it.
        let mut from = 0;
        let mut at = 0;
        if !self.carry.is_empty() {
            from = CIPHER_BLOCK - self.carry.len();
            out[..self.carry.len()].copy_from_slice(&self.carry);
            out[self.carry.len()..CIPHER_BLOCK].copy_from_slice(&plain[..from]);
            self.carry.clear();
            self.encrypt(&mut out[..CIPHER_BLOCK])?;
            at = CIPHER_BLOCK;
        }
        let body = whole - at;
        self.encrypt_from(&plain[from..from + body], &mut out[at..])?;
        self.carry.extend_from_slice(&plain[from + body..]);
        Ok(())
    }

    /// The last bytes of the member: the held remainder, zero padded to a
    /// whole block, which is what the reference pads with.
    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        if self.carry.is_empty() {
            return Ok(());
        }
        out.extend_from_slice(&self.carry);
        out.resize(out.len().next_multiple_of(CIPHER_BLOCK), 0);
        self.carry.clear();
        self.encrypt(out)
    }

    fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.cipher {
            Cipher::Aes128(state) => state.encrypt(buf),
            Cipher::Aes256(state) => state.encrypt(buf),
        }
    }

    fn encrypt_from(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        match &mut self.cipher {
            Cipher::Aes128(state) => state.encrypt_from(src, dst),
            Cipher::Aes256(state) => state.encrypt_from(src, dst),
        }
    }

    /// Whether a fragment that is not the member's last carries the plain
    /// checksum of its CIPHERTEXT: RAR 5's rule (spec K 3.7.6), and the
    /// RAR 4 family's too, which spec G 3.10.2 left open and was
    /// settled on 28 Sep 2026 by reference `unrar`
    /// 7.23's verdict ("packed data checksum error" on a set whose middle
    /// fragment carried its plaintext's). Every encrypted member, both
    /// families.
    pub(crate) fn fragments_digest_ciphertext(&self) -> bool {
        true
    }

    /// The checksum a header stores for an encrypted member: RAR 5
    /// converts it under the MAC key, the RAR 4 family stores it plain
    /// (`r4_pw`, whose CRC32 is the unencrypted member's).
    pub(crate) fn stored_digest(&self, digest: Digest) -> Digest {
        match (&self.mac, digest) {
            (Some(keys), Digest::Crc32(value)) => Digest::Crc32(keys.stored_word_under_key(value)),
            (Some(keys), Digest::Blake2sp(bytes)) => Digest::Blake2sp(keys.mac_digest(&bytes)),
            (None, digest) => digest,
        }
    }
}

/// The RAR 5 file encryption record's body (spec K 3.5), as `r5_pw`
/// carries it: version 0, the flags, the exponent, the archive's salt,
/// this member's initialisation vector and the password check record.
/// The flags are the check and MAC flags on a member's last (or only)
/// fragment and the check flag alone on any other (spec K 3.7.6).
fn rar5_record(salt: &[u8; 16], iv: &[u8; 16], keys: &Rar5Keys, flags: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(47);
    put_vint(&mut body, 0);
    put_vint(&mut body, flags);
    body.push(RAR5_KDF_LOG2);
    body.extend_from_slice(salt);
    body.extend_from_slice(iv);
    keys.append_check_record(&mut body);
    body
}

/// The length a member's ciphertext takes: whole cipher blocks, padded.
pub(crate) fn padded_len(plain: u64) -> u64 {
    plain.next_multiple_of(CIPHER_BLOCK as u64)
}

// ---- Header encryption (spec G 3.3.6 and 3.12, spec K 3.6) --------------

/// The cipher every block after the archive's first is written through,
/// when `encrypt_headers` is set.
///
/// The framing is spec K 3.6's and the writer's part is only the ORDER:
/// RAR 5 puts an archive encryption header first, in clear, and every
/// block after it becomes `IV (16) | AES-256-CBC(header, zero padded)`;
/// the RAR 4 family has no such header at all, marks its main header
/// 0x0080 and leaves it in clear, and every block after it becomes
/// `salt (8) | AES-128-CBC(header, zero padded)`. In both families the
/// DATA AREA after a header is not covered by this layer: a member's
/// bytes are encrypted by the member's own cipher, exactly as they are
/// without header encryption.
pub(crate) enum HeaderKey {
    /// RAR 5: the archive's keys, and ONE chain under them, its key
    /// expanded once and restarted from each block's fresh initialisation
    /// vector. The writer's own chain, not the `aes` crate's
    /// per-block call, which on a VAES-512 part broadcasts the whole key
    /// schedule for every block it is handed (about 6,000 instructions a
    /// header on Zen 4, counted 30 Sep 2026).
    Rar5 {
        keys: Box<Rar5Keys>,
        enc: Box<Aes256Enc>,
    },
    /// The RAR 4 family: one key, whose salt is written before every
    /// block because that is where the reader looks for it, and one
    /// chain under it, restarted from the key's IV for every block.
    Rar4 {
        key: Box<Rar4Key>,
        enc: Box<Aes128Enc>,
        salt: [u8; 8],
    },
}

impl HeaderKey {
    /// The RAR 5 header key: the archive's own keys (one salt, spec K
    /// 3.7.7), with the schedule every header is enciphered under.
    pub(crate) fn rar5(keys: Rar5Keys) -> HeaderKey {
        let enc = Box::new(Aes256Enc::new(&keys, &[0; 16]));
        HeaderKey::Rar5 {
            keys: Box::new(keys),
            enc,
        }
    }

    /// The RAR 4 family's header key: the archive's one key, its salt in
    /// front of every block (spec K 3.6.5).
    pub(crate) fn rar4(key: Rar4Key, salt: [u8; 8]) -> HeaderKeyed {
        let enc = Box::new(Aes128Enc::new(&key));
        (
            HeaderKey::Rar4 {
                key: Box::new(key),
                enc,
                salt,
            },
            [0; 16],
        )
    }

    /// How many bytes this framing puts in front of a block's ciphertext.
    pub(crate) fn prefix_len(&self) -> usize {
        match self {
            HeaderKey::Rar5 { .. } => 16,
            HeaderKey::Rar4 { .. } => 8,
        }
    }

    /// Wraps one header image: the prefix the reader looks for, then the
    /// header zero padded to a whole cipher block and encrypted.
    ///
    /// `iv` is the RAR 5 initialisation vector to use, so that a header
    /// CORRECTED after its payload has passed re-encrypts to exactly the
    /// same length under the same chain; the RAR 4 family ignores it and
    /// uses the archive's salt.
    pub(crate) fn wrap(&mut self, header: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>> {
        let padded = header.len().next_multiple_of(CIPHER_BLOCK);
        let mut out = Vec::with_capacity(self.prefix_len() + padded);
        match self {
            HeaderKey::Rar5 { enc, .. } => {
                out.extend_from_slice(iv);
                let at = out.len();
                out.extend_from_slice(header);
                out.resize(at + padded, 0);
                enc.restart(iv);
                enc.encrypt(&mut out[at..])?;
            }
            HeaderKey::Rar4 { key, enc, salt } => {
                out.extend_from_slice(salt);
                let at = out.len();
                out.extend_from_slice(header);
                out.resize(at + padded, 0);
                enc.restart(&key.iv);
                enc.encrypt(&mut out[at..])?;
            }
        }
        Ok(out)
    }
}

/// The archive encryption header's body (spec K 3.6): version 0, the
/// check flag, the exponent, the salt the headers were derived from and
/// the password check record. `r5_hpw` carries exactly this.
pub(crate) fn rar5_archive_encryption_body(salt: &[u8; 16], key: &HeaderKey) -> Vec<u8> {
    let HeaderKey::Rar5 { keys, .. } = key else {
        unreachable!("an archive encryption header under the RAR 4 family")
    };
    let mut body = Vec::with_capacity(31);
    put_vint(&mut body, 0);
    put_vint(&mut body, FLAG_CHECK);
    body.push(RAR5_KDF_LOG2);
    body.extend_from_slice(salt);
    keys.append_check_record(&mut body);
    body
}
