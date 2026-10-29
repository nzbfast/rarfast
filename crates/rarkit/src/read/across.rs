//! Fragments abreast: a stored member's run of fragments UNDER the wide
//! read's floor, read and hashed by one team of readers KEPT across the
//! volume files they sit in, their CRC32s joined in order.
//!
//! **What it is for.** A stored big member posted as 859 volumes of 15 MB is the
//! commonest shape there is, and every fragment of it is under
//! `wide::FLOOR`, 16 MiB: the wide read took the member and then read each
//! fragment in order on the member's own thread, because `wide::verify_range`
//! reads ONE range and starts and joins its threads for it. `t` of that member
//! read warm on one thread where the same bytes in 100 MiB volumes, each
//! fragment a range of its own, read on every lane the width gave
//! (measured 2 Oct 2026). Nothing in the work is
//! serial: the wall is the copy out of the page cache and the CRC32 over
//! it, a piece's CRC32 is independent of every other piece's, and
//! [`Crc32::append`] joins two registers exactly, across a fragment's end
//! as inside one.
//!
//! **The arrangement.** The member's thread hands out the pieces and
//! combines them, as it does in `read::wide`. It takes each fragment's unread rest
//! off the member's stream as a [`Lead`] (the volume's source, the range,
//! and what the fragment's header says of its packed CRC32), cuts it into
//! pieces of [`Plan::piece`] bytes, and hands them to [`Plan::workers`]
//! threads of the extraction's team (`read::team`), kept for the run and
//! for whatever the extraction reads after it. When a fragment is cut to its
//! end the stream is asked for the next one, which crosses the volume
//! boundary on this thread exactly as a read to the fragment's end would
//! have (spec F 3.5.4), so pieces of the next volume are being read while
//! this one's are still being joined. Answers come back in any order and
//! are joined in the member's byte order on this thread, the only one that
//! touches the stream, the member, its writer or the tally.
//!
//! **The bounds.** A piece is dispatched only while fewer than
//! [`Plan::workers`] pieces are dispatched and not joined, and
//! `workers * piece` is at most `MemoryPolicy::read_ahead`, so no byte is
//! asked of a source more than `read_ahead` beyond the byte being joined
//! (spec F 3.7.2), whichever volume it is in. A volume crossed to ahead of
//! the join is one the walk holds open behind itself, so each takes a place
//! in `read::forwarded`'s count before it is opened, as a fragment forwarded
//! to a pool worker does, and gives it back when its last piece is joined:
//! never more volumes open than that bound allows. This thread never WAITS
//! for a place while it holds pieces of its own to join; it joins them.
//!
//! **Nothing moves.** The member's CRC32, each fragment's packed CRC32 and
//! the writer are fed exactly the values, lengths and bytes a read in order
//! feeds them, in the same order. A source that ends inside a fragment, a
//! source error and a crossing that fails each end the run only after every
//! byte in front of them is joined, with the error the read in order gives.

use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use crate::checksum::Crc32;
use crate::error::{Error, Result};
use crate::read::cursor::read_upto_at;
use crate::read::forwarded::{self, Held};
use crate::read::wide::{Aligned, Plan};
use crate::source::RangeSource;

/// One fragment's unread rest, taken off the member's stream whole: the
/// stream has passed it, and reading, judging and counting it are the
/// taker's.
pub(crate) struct Lead {
    /// The volume the fragment is in.
    pub(crate) source: Arc<dyn RangeSource>,
    /// Its bytes not in `head`: `len` of them at `at` of `source`.
    pub(crate) at: u64,
    pub(crate) len: u64,
    /// The bytes in front of `at` that the stream had in hand already (the
    /// walk's header window), so no byte range is read twice (spec F 3.7.2).
    pub(crate) head: Vec<u8>,
    /// The fragment's packed CRC32 over the bytes the stream delivered
    /// before the take, and the value its header carries where it is to be
    /// judged (spec F 3.5.6).
    pub(crate) carried: Crc32,
    pub(crate) judge: Option<u32>,
    /// The volume's number, which a read error or a mismatch names.
    pub(crate) volume: u32,
    /// Its place among the volumes opened ahead (`read::forwarded`); `None`
    /// for the fragment the stream was in when the run began.
    pub(crate) held: Option<Held>,
}

/// What a member's stream answers when asked for its next fragment.
pub(crate) enum Next {
    Lead(Lead),
    /// The stream stands at a fragment this run does not take: one at or
    /// over the floor, or one the stream cannot give by handle. Nothing of
    /// it is consumed.
    Over,
    /// The member has ended.
    End,
}

/// How a run ended that did not fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ended {
    /// The member has ended.
    Member,
    /// The stream stands at a fragment the run left untaken ([`Next::Over`]).
    Over,
}

/// Why a run stopped short, every byte in front of it joined.
pub(crate) enum Stop {
    /// A volume's source ended at this offset, inside a fragment.
    Short { volume: u32, at: u64 },
    /// A volume's source failed.
    Source { volume: u32, error: Error },
    /// The stream's own crossing failed, or the combiner's callback did.
    Other(Error),
}

/// A piece to read: its place in the run, where it is, and the buffer lent
/// for it, if any.
struct Job {
    seq: u64,
    source: Arc<dyn RangeSource>,
    at: u64,
    want: usize,
    buf: Option<Aligned>,
}

/// A piece's answer: its CRC32, how many bytes the source gave, and the
/// lent buffer; or the source's error.
struct Done {
    crc: u32,
    got: usize,
    buf: Option<Aligned>,
}

type Answer = (u64, std::result::Result<Done, Error>);

/// What is dispatched and not joined, in the member's byte order.
enum Entry {
    /// A fragment's head, read on this thread when the fragment was taken:
    /// its bytes, its volume and where it ends in it.
    Head(Vec<u8>, u32, u64),
    /// A piece out with a reader, or answered.
    Piece {
        volume: u32,
        at: u64,
        want: usize,
        answer: Option<std::result::Result<Done, Error>>,
    },
}

/// What stands lowest in the flight.
enum Front {
    Empty,
    Head,
    Out,
    Answered,
}

/// A fragment with entries not yet joined.
struct Fragment {
    crc: Crc32,
    judge: Option<u32>,
    volume: u32,
    /// Entries of it dispatched and not joined, and whether every one has
    /// been dispatched.
    left: usize,
    cut: bool,
    /// Dropped with the fragment: its place among the volumes open ahead.
    _held: Option<Held>,
}

/// The fragment being cut into pieces.
struct Cutting {
    source: Arc<dyn RangeSource>,
    volume: u32,
    at: u64,
    left: u64,
}

/// The member's stream, as the run uses it. Every call is made on the
/// member's own thread.
pub(crate) trait Fragments {
    /// Cross to the member's next fragment and answer it, given the place
    /// its volume takes among those open ahead of the join (`None` where
    /// nothing is unjoined, so nothing is ahead) and the most bytes the
    /// member may still take.
    fn next(&mut self, held: Option<Held>, room: Option<u64>) -> Result<Next>;
    /// `len` more bytes of `volume` are joined, up to `upto` of it.
    fn passed(&mut self, volume: u32, upto: u64, len: u64) -> Result<()>;
    /// The last byte taken from `volume` is joined; `mismatch` says its
    /// packed CRC32 disagreed with its header's field.
    fn joined(&mut self, volume: u32, mismatch: bool) -> Result<()>;
}

/// What the calling thread does with each joined run of bytes, in order:
/// their CRC32, their length, and the bytes where they were lent.
pub(crate) type Accept<'a> = dyn FnMut(u32, u64, Option<&[u8]>) -> Result<()> + 'a;

fn read_piece(job: &Job, buf: &mut [u8]) -> std::result::Result<(u32, usize), Error> {
    let got = read_upto_at(&*job.source, job.at, &mut buf[..job.want])?;
    Ok((crate::checksum::crc32(&buf[..got]), got))
}

/// One piece's answer, read into the buffer its job brings or into `own`,
/// the buffer of the thread that reads it.
fn answer(own: &mut Aligned, mut job: Job) -> Answer {
    let seq = job.seq;
    let result = match job.buf.take() {
        Some(mut buf) => read_piece(&job, buf.bytes_mut()).map(|(crc, got)| Done {
            crc,
            got,
            buf: Some(buf),
        }),
        None => read_piece(&job, own.bytes_mut()).map(|(crc, got)| Done {
            crc,
            got,
            buf: None,
        }),
    };
    (seq, result)
}

/// What a reader says of a piece: its answer, or `None` for the result
/// where the reader fell (panicked) on it.
type Said = (u64, Option<std::result::Result<Done, Error>>);

/// A reader's word to its run, and the piece it is on: if the reader
/// unwinds with a piece in hand, the run is told that the piece fell, and
/// panics on its own thread as a scope whose thread panicked did.
struct Says {
    to: Sender<Said>,
    on: Option<u64>,
}

impl Drop for Says {
    fn drop(&mut self) {
        if let Some(seq) = self.on.take() {
            let _ = self.to.send((seq, None));
        }
    }
}

fn next_job(jobs: &Mutex<Receiver<Job>>) -> Option<Job> {
    jobs.lock().unwrap_or_else(|e| e.into_inner()).recv().ok()
}

/// Read a member's fragments from `first` on, each as `next` gives it, on
/// up to `plan.workers` threads of the extraction's team (`read::team`), and hand `accept`
/// every byte's CRC32 (and the bytes, with `lend`) in the member's order,
/// on the calling thread.
///
/// `stream` is the member's stream ([`Fragments`]): asked for the next
/// fragment it crosses to it, or says the run is over; it is told each
/// run of bytes joined and each fragment's end, with whether its packed
/// CRC32 disagreed with its header's field. `room` is the most bytes the
/// member may still take at the start, `None` where it declares no size.
///
/// **`ahead`** lets the stream be asked for the next fragment while pieces
/// of this one are still to be joined, so the readers stay busy across a
/// volume's end; without it the run joins everything it holds before it
/// crosses, and the next volume is opened with nothing unjoined behind it.
///
/// **With `lend`** (`p`), the buffers circulate, `workers` of them, and a
/// piece's bytes come home with its CRC32 to be written from the calling
/// thread; **without** (`t`), each reader keeps one buffer of its own. At
/// most `workers * piece` bytes are held either way, and the fragments'
/// heads, a few kibibytes each.
pub(crate) fn run(
    plan: Plan,
    lend: bool,
    first: Lead,
    room: Option<u64>,
    ahead: bool,
    stream: &mut dyn Fragments,
    accept: &mut Accept<'_>,
) -> std::result::Result<Ended, Stop> {
    let piece = plan.piece;
    // The buffers lent; a thread's own is charged by the thread that keeps
    // it (`team::Scratch`).
    let held_bytes = if lend {
        (plan.workers * (piece + 4096)) as u64
    } else {
        0
    };
    crate::memory::charge(held_bytes);
    // The seats are taken first, so they are given back last on every way
    // out: after the pieces' sender below has let every reader go.
    let mut seats = crate::read::team::seats(0);
    // The pieces go to the readers down a channel of the run's own; its
    // sending end is dropped when this function returns, which is what
    // lets a reader waiting for a piece leave its thread to the team.
    let (job_tx, job_rx) = channel::<Job>();
    let jobs = Arc::new(Mutex::new(job_rx));
    let outcome = {
        let (said_tx, done_rx) = channel::<Said>();
        // A reader is a job that reads the run's pieces on a thread of the
        // extraction's team until the run has no more (`read::team`). One
        // is taken on when a piece is dispatched with every reader so far
        // out with one, up to the plan's: a run of one short fragment (a
        // member's tail in a set of large volumes) takes as many as it has
        // pieces, not the whole team. A seat starts a thread only where
        // the team has none free, and the run does not wait for its
        // readers to leave.
        let mut start_reader = || {
            if !seats.more() {
                return false;
            }
            let jobs = Arc::clone(&jobs);
            let mut says = Says {
                to: said_tx.clone(),
                on: None,
            };
            seats.hand(Box::new(move |scratch| {
                while let Some(job) = next_job(&jobs) {
                    says.on = Some(job.seq);
                    let (seq, result) = answer(scratch.buffer(piece, 0), job);
                    says.on = None;
                    if says.to.send((seq, Some(result))).is_err() {
                        break;
                    }
                }
            }));
            true
        };
        let mut readers = 0usize;
        // The host will start no more (`crate::threads`): the run goes as
        // wide as the readers it has. With none at all, this thread answers
        // each piece itself as it is dispatched: the read in order, a piece
        // at a time.
        let mut refused = false;
        let mut inline = false;
        let workers = plan.workers.max(1);
        let mut own_here: Option<Aligned> = None;
        // The lent buffers: made as pieces first need them, `workers` at
        // most, then circulating.
        let mut spare: Vec<Aligned> = Vec::new();
        let mut made = 0usize;

        let mut flight: VecDeque<Entry> = VecDeque::with_capacity(workers + 2);
        let mut fragments: VecDeque<Fragment> = VecDeque::new();
        let mut cutting: Option<Cutting> = None;
        let mut first = Some(first);
        let mut room = room;
        // Pieces dispatched and not joined, and their sequence numbers: an
        // answer finds its entry by how far it is past the lowest unjoined.
        let mut out = 0usize;
        let (mut sent, mut joined) = (0u64, 0u64);
        // Why no more is dispatched: the stream said so, or its crossing
        // failed. Either is acted on once everything in flight is joined.
        let mut ended: Option<Ended> = None;
        let mut failed: Option<Error> = None;

        let result = (|| loop {
            while ended.is_none() && failed.is_none() && out < workers {
                let Some(cut) = cutting.as_mut().filter(|c| c.left > 0) else {
                    // The fragment before is cut to its end: the next one.
                    let lead = match first.take() {
                        Some(lead) => Ok(Next::Lead(lead)),
                        // Nothing unjoined: the next volume is opened as
                        // the walk opens any, ahead of nothing.
                        None if flight.is_empty() => stream.next(None, room),
                        None if !ahead => break,
                        None => {
                            // A place among the volumes open ahead, before
                            // the next is opened. This thread joins what it
                            // holds rather than wait on itself.
                            let Some(held) = forwarded::try_take() else {
                                break;
                            };
                            #[cfg(feature = "test-support")]
                            crate::probe::note_crossed_ahead();
                            stream.next(Some(held), room)
                        }
                    };
                    match lead {
                        Ok(Next::Lead(lead)) => {
                            let taken = lead.head.len() as u64 + lead.len;
                            room = room.map(|r| r.saturating_sub(taken));
                            let mut fragment = Fragment {
                                crc: lead.carried,
                                judge: lead.judge,
                                volume: lead.volume,
                                left: 0,
                                cut: lead.len == 0,
                                _held: lead.held,
                            };
                            if !lead.head.is_empty() {
                                fragment.left += 1;
                                flight.push_back(Entry::Head(lead.head, lead.volume, lead.at));
                            }
                            fragments.push_back(fragment);
                            cutting = Some(Cutting {
                                source: lead.source,
                                volume: lead.volume,
                                at: lead.at,
                                left: lead.len,
                            });
                        }
                        Ok(Next::Over) => ended = Some(Ended::Over),
                        Ok(Next::End) => ended = Some(Ended::Member),
                        Err(error) => failed = Some(error),
                    }
                    continue;
                };
                let want = cut.left.min(piece as u64) as usize;
                let buf = if lend {
                    let buf = match spare.pop() {
                        Some(buf) => buf,
                        None if made < workers => {
                            made += 1;
                            Aligned::new(piece)
                        }
                        None => break,
                    };
                    Some(buf)
                } else {
                    None
                };
                if !inline && !refused && readers < workers && out >= readers {
                    if start_reader() {
                        readers += 1;
                    } else {
                        refused = true;
                        inline = readers == 0;
                    }
                }
                let job = Job {
                    seq: sent,
                    source: Arc::clone(&cut.source),
                    at: cut.at,
                    want,
                    buf,
                };
                flight.push_back(Entry::Piece {
                    volume: cut.volume,
                    at: cut.at,
                    want,
                    answer: None,
                });
                cut.at += want as u64;
                cut.left -= want as u64;
                let fragment = fragments.back_mut().expect("the fragment being cut");
                fragment.left += 1;
                fragment.cut = cut.left == 0;
                sent += 1;
                out += 1;
                if inline {
                    let own = own_here.get_or_insert_with(|| Aligned::new(piece));
                    let (_, result) = answer(own, job);
                    if let Some(Entry::Piece { answer, .. }) = flight.back_mut() {
                        *answer = Some(result);
                    }
                } else if job_tx.send(job).is_err() {
                    unreachable!("this thread holds the pieces' receiver");
                }
            }
            // Join the lowest entry, where it is answered.
            let front = match flight.front() {
                None => Front::Empty,
                Some(Entry::Head(..)) => Front::Head,
                Some(Entry::Piece { answer: None, .. }) => Front::Out,
                Some(Entry::Piece { .. }) => Front::Answered,
            };
            let (crc, len, lent) = match front {
                Front::Empty => {
                    return match (failed.take(), ended) {
                        (Some(error), _) => Err(Stop::Other(error)),
                        (None, Some(ended)) => Ok(ended),
                        (None, None) => unreachable!("an empty flight dispatches or ends"),
                    };
                }
                Front::Head => {
                    let Some(Entry::Head(bytes, volume, upto)) = flight.pop_front() else {
                        unreachable!("checked")
                    };
                    let crc = crate::checksum::crc32(&bytes);
                    accept(crc, bytes.len() as u64, lend.then_some(&bytes[..]))
                        .map_err(Stop::Other)?;
                    stream
                        .passed(volume, upto, bytes.len() as u64)
                        .map_err(Stop::Other)?;
                    (crc, bytes.len() as u64, None)
                }
                Front::Out => {
                    // The lowest piece is still out, so an answer is
                    // coming, unless its reader fell and says so. That
                    // reader's thread has said why; this thread ends as a
                    // scope whose thread panicked did.
                    let Ok((seq, Some(result))) = done_rx.recv() else {
                        panic!("a reader of fragments abreast panicked");
                    };
                    // Its entry: so many pieces past the lowest unjoined,
                    // heads not counted.
                    let mut ahead = seq - joined;
                    for entry in flight.iter_mut() {
                        if let Entry::Piece { answer, .. } = entry {
                            if ahead == 0 {
                                *answer = Some(result);
                                break;
                            }
                            ahead -= 1;
                        }
                    }
                    continue;
                }
                Front::Answered => {
                    let Some(Entry::Piece {
                        volume,
                        at,
                        want,
                        answer: Some(result),
                    }) = flight.pop_front()
                    else {
                        unreachable!("checked")
                    };
                    joined += 1;
                    out -= 1;
                    let done = result.map_err(|error| Stop::Source { volume, error })?;
                    if done.got > 0 {
                        let bytes = done.buf.as_ref().map(|b| &b.bytes()[..done.got]);
                        accept(done.crc, done.got as u64, bytes).map_err(Stop::Other)?;
                    }
                    if done.got < want {
                        return Err(Stop::Short {
                            volume,
                            at: at + done.got as u64,
                        });
                    }
                    stream
                        .passed(volume, at + want as u64, want as u64)
                        .map_err(Stop::Other)?;
                    (done.crc, done.got as u64, done.buf)
                }
            };
            spare.extend(lent);
            // The fragment the entry was of: its packed CRC32, and its end.
            let fragment = fragments.front_mut().expect("an entry's fragment");
            if fragment.judge.is_some() {
                fragment.crc.append(crc, len);
            }
            fragment.left -= 1;
            if fragment.left == 0 && fragment.cut {
                let mismatch = fragment
                    .judge
                    .is_some_and(|field| field != fragment.crc.finish());
                let volume = fragment.volume;
                // Its place among the volumes open ahead goes back first.
                fragments.pop_front();
                stream.joined(volume, mismatch).map_err(Stop::Other)?;
            }
        })();
        result
    };
    drop(job_tx);
    crate::memory::release(held_bytes);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::crc32;
    use crate::error::ErrorKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// One volume: its bytes, and where it stops answering, if it does.
    struct Volume {
        data: Vec<u8>,
        ends_at: Option<u64>,
        fails_at: Option<u64>,
        /// Every byte asked of any volume of the set so far.
        asked: Arc<AtomicU64>,
    }

    impl RangeSource for Volume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.fails_at.is_some_and(|f| offset + buf.len() as u64 > f) {
                return Err(std::io::Error::other("injected"));
            }
            let end = self.ends_at.unwrap_or(self.data.len() as u64) as usize;
            let start = (offset as usize).min(end);
            let n = buf.len().min(end - start);
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            self.asked.fetch_add(buf.len() as u64, Ordering::Relaxed);
            Ok(n)
        }
        fn available(&self) -> u64 {
            self.data.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.data.len() as u64)
        }
    }

    fn noise(seed: u32, len: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9u32 ^ seed.wrapping_mul(0x85eb_ca6b) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// A set of fragments: `(junk in front, head bytes, the rest)` each,
    /// the head being what the stream had in hand at the take.
    struct Set {
        volumes: Vec<Arc<Volume>>,
        /// Each fragment's offset of its head in its volume, its head's
        /// length and its whole length.
        cut: Vec<(u64, usize, usize)>,
        asked: Arc<AtomicU64>,
    }

    fn set(shape: &[(usize, usize, usize)]) -> Set {
        let asked = Arc::new(AtomicU64::new(0));
        let mut volumes = Vec::new();
        let mut cut = Vec::new();
        for (at, (front, head, rest)) in shape.iter().enumerate() {
            let data = noise(at as u32, front + head + rest + 33);
            volumes.push(Arc::new(Volume {
                data,
                ends_at: None,
                fails_at: None,
                asked: Arc::clone(&asked),
            }));
            cut.push((*front as u64, *head, head + rest));
        }
        Set {
            volumes,
            cut,
            asked,
        }
    }

    impl Set {
        fn member(&self) -> Vec<u8> {
            let mut all = Vec::new();
            for (volume, (front, _, len)) in self.volumes.iter().zip(&self.cut) {
                let front = *front as usize;
                all.extend_from_slice(&volume.data[front..front + len]);
            }
            all
        }

        fn lead(&self, at: usize, judge: Option<u32>, held: Option<Held>) -> Lead {
            let (front, head, len) = self.cut[at];
            let from = front as usize;
            let volume = &self.volumes[at];
            Lead {
                source: Arc::clone(volume) as Arc<dyn RangeSource>,
                at: front + head as u64,
                len: (len - head) as u64,
                head: volume.data[from..from + head].to_vec(),
                carried: Crc32::new(),
                judge,
                volume: at as u32,
                held,
            }
        }

        /// The packed CRC32 fragment `at`'s header would carry.
        fn field(&self, at: usize) -> u32 {
            let (front, _, len) = self.cut[at];
            let front = front as usize;
            crc32(&self.volumes[at].data[front..front + len])
        }
    }

    /// The set as a member's stream: fragments in order, a field made
    /// wrong, a crossing that fails, a fragment left untaken.
    struct Feed<'a> {
        set: &'a Set,
        given: usize,
        wrong: Option<usize>,
        stop_at: Option<usize>,
        over_at: Option<usize>,
        ahead: bool,
        mismatches: Vec<u32>,
        joined: Vec<u32>,
        passed: u64,
    }

    impl Feed<'_> {
        fn field(&self, at: usize) -> Option<u32> {
            let field = self.set.field(at);
            Some(if self.wrong == Some(at) {
                !field
            } else {
                field
            })
        }
    }

    impl Fragments for Feed<'_> {
        fn next(&mut self, held: Option<Held>, _room: Option<u64>) -> Result<Next> {
            // A place is taken only to open a volume ahead of the join.
            assert!(self.ahead || held.is_none());
            if self.stop_at == Some(self.given) {
                return Err(Error::new(ErrorKind::Truncated).with_volume(self.given as u32));
            }
            if self.over_at == Some(self.given) {
                return Ok(Next::Over);
            }
            if self.given == self.set.cut.len() {
                return Ok(Next::End);
            }
            self.given += 1;
            let at = self.given - 1;
            Ok(Next::Lead(self.set.lead(at, self.field(at), held)))
        }

        fn passed(&mut self, volume: u32, upto: u64, len: u64) -> Result<()> {
            // In order: only the lowest fragment not yet joined to its end.
            assert_eq!(volume as usize, self.joined.len());
            let (front, _, whole) = self.set.cut[volume as usize];
            assert!(upto <= front + whole as u64);
            self.passed += len;
            Ok(())
        }

        fn joined(&mut self, volume: u32, mismatch: bool) -> Result<()> {
            assert_eq!(volume as usize, self.joined.len());
            self.joined.push(volume);
            if mismatch {
                self.mismatches.push(volume);
            }
            Ok(())
        }
    }

    /// What a run did: how it ended, the member's CRC32 and bytes as
    /// joined, the mismatched volumes, and the most bytes ever asked of
    /// the sources beyond the bytes joined.
    struct Ran {
        ended: std::result::Result<Ended, String>,
        crc: u32,
        bytes: Vec<u8>,
        joined: u64,
        mismatches: Vec<u32>,
        ahead: u64,
        ends: Vec<u32>,
    }

    fn ran(
        set: &Set,
        plan: Plan,
        lend: bool,
        ahead_of_join: bool,
        wrong: Option<usize>,
        stop_at: Option<usize>,
        over_at: Option<usize>,
    ) -> Ran {
        let mut crc = Crc32::new();
        let mut bytes = Vec::new();
        let mut joined = 0u64;
        let mut ahead = 0u64;
        let heads: u64 = set.cut.iter().map(|c| c.1 as u64).sum();
        let mut feed = Feed {
            set,
            given: 1,
            wrong,
            stop_at,
            over_at,
            ahead: ahead_of_join,
            mismatches: Vec::new(),
            joined: Vec::new(),
            passed: 0,
        };
        let first = set.lead(0, feed.field(0), None);
        let ended = run(
            plan,
            lend,
            first,
            Some(1 << 30),
            ahead_of_join,
            &mut feed,
            &mut |c, len, lent| {
                crc.append(c, len);
                joined += len;
                // The heads were never asked of a source.
                ahead =
                    ahead.max((set.asked.load(Ordering::Relaxed) + heads).saturating_sub(joined));
                assert_eq!(lent.is_some(), lend);
                if let Some(lent) = lent {
                    assert_eq!(lent.len() as u64, len);
                    bytes.extend_from_slice(lent);
                }
                Ok(())
            },
        );
        if ended.is_ok() {
            assert_eq!(feed.passed, joined, "every joined byte is passed");
        }
        Ran {
            ended: ended.map_err(|stop| match stop {
                Stop::Short { volume, at } => format!("short {volume} {at}"),
                Stop::Source { volume, .. } => format!("source {volume}"),
                Stop::Other(error) => format!("other {:?} {:?}", error.kind(), error.volume()),
            }),
            crc: crc.finish(),
            bytes,
            joined,
            mismatches: feed.mismatches,
            ahead,
            ends: feed.joined,
        }
    }

    const SHAPE: [(usize, usize, usize); 7] = [
        (11, 0, 300_000),
        (40, 3_000, 180_000),
        (40, 500, 1),
        (9, 77, 0),
        (40, 0, 65_536),
        (0, 4_096, 262_144),
        (5, 1, 99_999),
    ];

    /// Every plan joins the member's own CRC32 and, lent, its own bytes in
    /// order; no fragment is called mismatched; and never more is asked of
    /// the sources than the window beyond the bytes joined.
    #[test]
    fn the_run_joins_the_members_bytes_in_order_inside_its_window() {
        let set = set(&SHAPE);
        let member = set.member();
        for (workers, piece) in [(1, 65_536), (2, 4_096), (3, 131_072), (8, 16_384)] {
            for (lend, ahead) in [(false, true), (true, true), (false, false), (true, false)] {
                set.asked.store(0, Ordering::Relaxed);
                let plan = Plan { workers, piece };
                let ran = ran(&set, plan, lend, ahead, None, None, None);
                assert_eq!(ran.ended, Ok(Ended::Member), "{workers} x {piece}");
                assert_eq!(ran.ends, (0..SHAPE.len() as u32).collect::<Vec<_>>());
                assert_eq!(ran.joined, member.len() as u64);
                assert_eq!(ran.crc, crc32(&member), "{workers} x {piece} lend {lend}");
                if lend {
                    assert!(ran.bytes == member, "{workers} x {piece}: the bytes moved");
                }
                assert!(ran.mismatches.is_empty());
                // A head is joined with the piece behind it still out, so
                // the window is the pieces and the heads between them.
                let window = (workers * piece) as u64 + 8_192;
                assert!(
                    ran.ahead <= window,
                    "{workers} x {piece}: {} asked beyond the join, over {window}",
                    ran.ahead
                );
            }
        }
    }

    /// A fragment whose packed CRC32 disagrees with its field is named by
    /// its volume, once, and the member's own CRC32 is what the bytes say.
    #[test]
    fn a_fragment_whose_field_disagrees_is_named() {
        let set = set(&SHAPE);
        let member = set.member();
        for wrong in [0usize, 2, 3, 6] {
            let plan = Plan {
                workers: 3,
                piece: 32_768,
            };
            let ran = ran(&set, plan, false, wrong % 2 == 0, Some(wrong), None, None);
            assert_eq!(ran.ended, Ok(Ended::Member));
            assert_eq!(ran.mismatches, vec![wrong as u32]);
            assert_eq!(ran.crc, crc32(&member));
        }
    }

    /// A crossing that fails ends the run with that error only once every
    /// byte of the fragments in front of it is joined.
    #[test]
    fn a_failed_crossing_is_given_after_every_byte_in_front_of_it() {
        let set = set(&SHAPE);
        let member = set.member();
        let plan = Plan {
            workers: 4,
            piece: 16_384,
        };
        for stop_at in 1..SHAPE.len() {
            let ran = ran(
                &set,
                plan,
                true,
                stop_at % 2 == 0,
                None,
                Some(stop_at),
                None,
            );
            assert_eq!(
                ran.ended,
                Err(format!("other Truncated Some({stop_at})")),
                "stopped at {stop_at}"
            );
            let front: usize = set.cut[..stop_at].iter().map(|c| c.2).sum();
            assert!(ran.bytes == member[..front], "stopped at {stop_at}");
        }
    }

    /// A volume that ends, or fails, inside a fragment ends the run at
    /// that byte, every byte in front of it joined and none after.
    #[test]
    fn a_source_that_ends_or_fails_stops_the_run_at_that_byte() {
        let plan = Plan {
            workers: 4,
            piece: 16_384,
        };
        for (which, ends) in [(1usize, true), (5, true), (1, false), (4, false)] {
            let mut set = set(&SHAPE);
            let member = set.member();
            let (front, head, len) = set.cut[which];
            // Part way through the fragment's fourth piece.
            let at = front + head as u64 + 3 * 16_384 + 1_000;
            assert!(at < front + len as u64);
            let old = &set.volumes[which];
            set.volumes[which] = Arc::new(Volume {
                data: old.data.clone(),
                ends_at: ends.then_some(at),
                fails_at: (!ends).then_some(at),
                asked: Arc::clone(&set.asked),
            });
            let ran = ran(&set, plan, true, true, None, None, None);
            let before: usize = set.cut[..which].iter().map(|c| c.2).sum();
            if ends {
                assert_eq!(ran.ended, Err(format!("short {which} {at}")));
                let got = before + (at - front) as usize;
                assert!(ran.bytes == member[..got], "volume {which} ended");
            } else {
                assert_eq!(ran.ended, Err(format!("source {which}")));
                let got = before + head + 3 * 16_384;
                assert!(ran.bytes == member[..got], "volume {which} failed");
            }
        }
    }

    /// A stream that stands at a fragment the run does not take ends it
    /// `Over`, everything taken joined.
    #[test]
    fn a_fragment_left_untaken_ends_the_run_over() {
        let set = set(&SHAPE);
        let plan = Plan {
            workers: 2,
            piece: 8_192,
        };
        for ahead in [true, false] {
            let ran = ran(&set, plan, true, ahead, None, None, Some(3));
            assert_eq!(ran.ended, Ok(Ended::Over));
            let front: usize = set.cut[..3].iter().map(|c| c.2).sum();
            assert!(ran.bytes == set.member()[..front]);
            assert_eq!(ran.ends, vec![0, 1, 2]);
        }
    }
}
