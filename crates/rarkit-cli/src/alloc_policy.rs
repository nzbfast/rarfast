//! The process's allocator policy: under a STATED memory budget (since
//! 29 Sep 2026), and for a CREATE with none stated (since 30 Sep
//! 2026).
//!
//! **Why, under a budget.** Under `-mm<size>` the engine's admission holds
//! what it counts inside the budget, but on glibc what a read frees is not
//! what the process gives back: blocks under the engine's 2 MiB release size (the
//! sequential look-ahead's 1 MiB chunks, packed buffers, scratch) return to
//! the worker thread's arena and stay resident there. On a Zen 5 rental
//! (glibc, 16 cores, bin4g `p`) max RSS read 204 MiB under `-mm128m` and
//! 281 to 289 under `-mm256m`; with the trim threshold at 0, 138 and 157 to
//! 171 (the whole-process accounting count).
//!
//! **Why, for a create.** A create's worker team and its lead allocate
//! buffers of 1 to 32 MiB (finders, parse scratches, block outputs, packed
//! members) on whichever pool thread runs them; glibc's default raises its
//! mmap threshold as such blocks are freed, so later ones come from the
//! arenas and what they free stays resident there. bin4g's `-m3` create at
//! the default policy peaked at 517 MiB on a Zen 4 rental (8 cores with SMT),
//! over the 512 MiB ceiling, and at 486 MiB with the threshold held at
//! 1 MiB, for 0.7 percent of wall (30 Sep 2026).
//! That setting was chosen over the alternatives.
//!
//! **What.** When the command line states a budget, the binary sets glibc's
//! trim threshold to 0, so every free that leaves free memory at the top of
//! a heap gives it back. Otherwise, when the command compresses new data
//! into an archive (`a`, `m`, `mf`, `u`, `f`), it holds glibc's mmap
//! threshold at 1 MiB, so every block of 1 MiB or more is mapped on its own
//! and unmapped when freed. Every other command pays nothing and changes
//! nothing. This is the BINARY's choice, never the library's: an
//! application that links `rarkit` keeps its own allocator policy.
//!
//! **Where.** glibc on Linux only. musl's allocator (mallocng) has no such
//! thresholds and returns freed large blocks to the kernel by itself, and
//! macOS is judged on phys_footprint, where the engine's
//! ring release applies; every other target compiles this to nothing.

#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

/// Which policy this process set, for the tests: 0 none, 1 the stated
/// budget's, 2 the create's.
#[cfg(test)]
static APPLIED: AtomicU8 = AtomicU8::new(0);

/// The mmap threshold a create holds: the smallest of the
/// buffers the count found retained, so all of them are mapped apart.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const CREATE_MMAP_THRESHOLD: i32 = 1 << 20;

/// Apply the allocator policy for a command line: the budget policy when
/// `memory_cap`, the command line's `-mm<size>`, states a budget; else
/// the create policy when `creates`, the command compressing new data into an
/// archive; else none.
pub(crate) fn on_command(memory_cap: Option<u64>, creates: bool) {
    if memory_cap.is_some() {
        trim_eagerly();
    } else if creates {
        map_large_blocks();
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn trim_eagerly() {
    // SAFETY: `mallopt` only sets a tunable of glibc's allocator and takes
    // no pointer. It is called once, on the main thread, before the
    // command starts any worker, so no allocation is in flight in another
    // thread; glibc takes its own arena lock for it in any case. A refusal
    // (a return of 0) leaves the default threshold, which is exactly the
    // behaviour without this call.
    let _ = unsafe { libc::mallopt(libc::M_TRIM_THRESHOLD, 0) };
    #[cfg(test)]
    APPLIED.store(1, Ordering::Relaxed);
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn trim_eagerly() {
    #[cfg(test)]
    APPLIED.store(1, Ordering::Relaxed);
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn map_large_blocks() {
    // SAFETY: as `trim_eagerly`: a tunable, no pointer, once on the main
    // thread before any worker starts. Setting it also stops glibc raising
    // the threshold by itself, which is the point. A refusal leaves the
    // default, the behaviour without this call.
    let _ = unsafe { libc::mallopt(libc::M_MMAP_THRESHOLD, CREATE_MMAP_THRESHOLD) };
    #[cfg(test)]
    APPLIED.store(2, Ordering::Relaxed);
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn map_large_blocks() {
    #[cfg(test)]
    APPLIED.store(2, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_command_line_gets_its_policy() {
        APPLIED.store(0, Ordering::Relaxed);
        on_command(None, false);
        assert_eq!(
            APPLIED.load(Ordering::Relaxed),
            0,
            "no -mm, no create: none"
        );
        on_command(None, true);
        assert_eq!(
            APPLIED.load(Ordering::Relaxed),
            2,
            "a create: the create policy"
        );
        on_command(Some(128 << 20), true);
        assert_eq!(
            APPLIED.load(Ordering::Relaxed),
            1,
            "-mm wins: the budget policy"
        );
        APPLIED.store(0, Ordering::Relaxed);
        on_command(Some(128 << 20), false);
        assert_eq!(
            APPLIED.load(Ordering::Relaxed),
            1,
            "-mm128m: the budget policy"
        );
    }
}
