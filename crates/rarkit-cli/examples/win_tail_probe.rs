//! EXPORT-08OCT-3's trace (8 Oct 2026): what a handle opened past the OS
//! cache says to each call a member's close makes, one line a call.
//!
//! `win_tail_probe DIR [LEN...]`: for each length (bytes; the default set is
//! one byte either side of 64 MiB and three small ones) a file in `DIR` is
//! created with `FILE_FLAG_NO_BUFFERING` (`O_DIRECT` on Linux), written in
//! whole 4 KiB sectors from sector aligned memory up to the length rounded
//! up, and then asked, in the order the extract's close asks:
//!
//! 1. `set_len(LEN)`: the cut back to the member's exact length;
//! 2. `seek(LEN)`: the handle put at the member's end;
//! 3. `seek(LEN rounded down to 512)` and `seek(LEN rounded up to 4096)`,
//!    to show which positions the handle takes;
//! 4. the file's length by name.
//!
//! It prints each call's own result and removes the file. It measures
//! nothing and takes no lock: a few megabytes written once.

use std::io::{Seek, SeekFrom};

fn open(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_NO_BUFFERING.
        options.custom_flags(0x2000_0000);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECT);
    }
    options.open(path)
}

fn write_at(file: &std::fs::File, bytes: &[u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_write(bytes, offset)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_at(bytes, offset)
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: win_tail_probe DIR [LEN...]");
        std::process::exit(2);
    };
    let mut lengths: Vec<u64> = args.filter_map(|a| a.parse().ok()).collect();
    if lengths.is_empty() {
        lengths = vec![6, 4096, 560_000, (64 << 20) - 1, 64 << 20, (64 << 20) + 1];
    }
    const SECTOR: usize = 4096;
    const BLOCK: usize = 4 << 20;
    let store = vec![0x5au8; BLOCK + SECTOR];
    let skip = store.as_ptr().align_offset(SECTOR);
    let block = &store[skip..skip + BLOCK];
    for len in lengths {
        let path = std::path::Path::new(&dir).join(format!("win-tail-probe-{len}.bin"));
        println!(
            "LEN {len} (mod 512 = {}, mod 4096 = {})",
            len % 512,
            len % 4096
        );
        let mut file = match open(&path) {
            Ok(file) => file,
            Err(e) => {
                println!("  open past the cache: {e}");
                continue;
            }
        };
        let padded = len.div_ceil(SECTOR as u64) * SECTOR as u64;
        let mut at = 0u64;
        let mut wrote = Ok(());
        while at < padded {
            let n = (padded - at).min(BLOCK as u64) as usize;
            match write_at(&file, &block[..n], at) {
                Ok(m) if m == n => at += n as u64,
                Ok(m) => {
                    wrote = Err(format!("short write {m} of {n} at {at}"));
                    break;
                }
                Err(e) => {
                    wrote = Err(format!("at {at}: {e}"));
                    break;
                }
            }
        }
        println!("  write {padded} bytes in whole sectors: {wrote:?}");
        println!(
            "  set_len({len}): {:?}",
            file.set_len(len).map_err(|e| e.to_string())
        );
        println!(
            "  seek({len}): {:?}",
            file.seek(SeekFrom::Start(len)).map_err(|e| e.to_string())
        );
        let down = len / 512 * 512;
        println!(
            "  seek({down}), down to 512: {:?}",
            file.seek(SeekFrom::Start(down)).map_err(|e| e.to_string())
        );
        println!(
            "  seek({padded}), up to 4096: {:?}",
            file.seek(SeekFrom::Start(padded))
                .map_err(|e| e.to_string())
        );
        drop(file);
        println!(
            "  length by name: {:?}",
            std::fs::metadata(&path)
                .map(|m| m.len())
                .map_err(|e| e.to_string())
        );
        let _ = std::fs::remove_file(&path);
    }
}
