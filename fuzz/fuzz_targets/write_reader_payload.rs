//! SPEC-G section 6.4: a scripted reader - short reads, errors, extra
//! bytes, zero-length reads - behind a member the writer pulls.
//!
//! The assertion is spec G section 4: no panic, no spin, and an error
//! that is one of the four the specification names for a payload.
//!
//! The same script drives the STORED path and section 3.7.3's WINDOWED
//! one, and `finish_into` and `finish_seek`, because those are four ways
//! a reader is pulled and a short read, an error and an over-long payload
//! have to land the same way in all of them. The dictionary is named
//! small so that the window is small and a payload of a few hundred bytes
//! still crosses one.
#![no_main]

use std::io::Read;

use libfuzzer_sys::fuzz_target;
use rarkit::{
    Corruption, ErrorKind, MemberSpec, Payload, WriteMethod, WriteOptions, Writer,
};

/// A reader that answers from a script rather than from a buffer.
struct Scripted<'a> {
    /// What is left to hand over.
    data: &'a [u8],
    /// One entry per call: 0 hands over nothing, 0xff errors, anything
    /// else hands over that many bytes.
    script: &'a [u8],
    at: usize,
}

impl Read for Scripted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let step = self.script.get(self.at).copied().unwrap_or(16);
        self.at += 1;
        if step == 0xff {
            return Err(std::io::Error::other("the script said so"));
        }
        let want = usize::from(step).min(buf.len()).min(self.data.len());
        buf[..want].copy_from_slice(&self.data[..want]);
        self.data = &self.data[want..];
        Ok(want)
    }
}

/// One run: `level` 0 stores and 1 to 5 compress, `seek` picks the entry
/// point, and `cap` writes a solid VOLUME SET instead of one archive.
///
/// The volume arm is what reaches spec G 3.5's streamed walk, which cuts
/// a member's packed bytes into fragments AS THE ENCODER PRODUCES THEM
/// and so pulls the reader inside the fragment walk rather than before
/// it. A short read, an error and an over-long payload have to land the
/// same way there as anywhere else, and the caller's `data` is repeated
/// up over one window so the member is large enough to take that walk.
fn run(level: u8, seek: bool, cap: Option<u64>, size: u64, payload: &[u8], script: &[u8]) {
    let mut reader = Scripted {
        data: payload,
        script,
        at: 0,
    };
    let options = WriteOptions {
        method: if level == 0 {
            WriteMethod::Stored
        } else {
            WriteMethod::Compressed {
                level,
                dictionary: Some(128 << 10),
            }
        },
        solid: cap.is_some(),
        volume_file_size: cap,
        ..WriteOptions::default()
    };
    let mut writer = match Writer::new(options) {
        Ok(writer) => writer,
        Err(_) => return,
    };
    if writer
        .add(MemberSpec {
            name: b"scripted.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .is_err()
    {
        return;
    }
    let patches = seek || cap.is_some();
    let outcome = if cap.is_some() {
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes)
    } else if seek {
        writer.finish_seek(std::io::Cursor::new(Vec::new()))
    } else {
        writer.finish_into(Vec::new())
    };
    match outcome {
        Ok(report) => assert!(
            !patches || report.held_volume_bytes == 0,
            "an output that can be patched held {} bytes",
            report.held_volume_bytes
        ),
        Err(error) => assert!(
            matches!(
                error.kind(),
                ErrorKind::Truncated
                    | ErrorKind::Caller
                    | ErrorKind::Cancelled
                    | ErrorKind::Corrupt(Corruption::PayloadLength)
                    | ErrorKind::Corrupt(Corruption::Checksum)
                    | ErrorKind::Unsupported(_)
                    | ErrorKind::LimitExceeded { .. }
            ),
            "a payload gave an error section 4 does not name: {error}"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&declared, rest)) = data.split_first() else {
        return;
    };
    let Some((&shape, rest)) = rest.split_first() else {
        return;
    };
    let split = rest.len() / 2;
    let (payload, script) = rest.split_at(split);
    // The declared size is deliberately allowed to disagree with what the
    // reader will hand over, which is the case section 4 names twice.
    let size = u64::from(declared) * 7;

    run(shape % 6, shape & 0x40 != 0, None, size, payload, script);

    // The volume arm, over a member big enough to be streamed. The body
    // is the same bytes repeated, so a 400 KiB member costs no corpus,
    // and the declared size still straddles the body's own length so
    // that `Truncated` and `PayloadLength` are both still reachable.
    if shape & 0x80 != 0 && !payload.is_empty() {
        let body = payload.repeat((400 * 1024) / payload.len() + 1);
        let size = (body.len() as u64 + u64::from(declared)).saturating_sub(128);
        let cap = u64::from(declared) * 512 + 1_024;
        run(shape % 5 + 1, shape & 0x40 != 0, Some(cap), size, &body, script);
    }
});
