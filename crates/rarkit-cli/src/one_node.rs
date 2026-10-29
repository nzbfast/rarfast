//! A create kept to ONE NUMA node's CPUs, behind a knob that is OFF as
//! shipped (`RARFAST_ONE_NODE=1`).
//!
//! **Why.** On a machine of two NUMA nodes (2 x 96 cores, Zen 4, 2 Oct
//! 2026) a create left to the scheduler ran its threads on both nodes while
//! each engine's history, chain tables and buffers lay on whichever node
//! first touched them, and an engine is handed to another pool thread every
//! round: of the loads that reached memory, 32 to 52 percent were served
//! from the other node, against 2 to 16 percent with the process on one
//! node. One node's CPUs with the memory left to first touch took the whole
//! gain (1.06x to 1.20x of wall on a 4 GiB member and on 9,516 files at
//! levels 1 and 3); the same CPUs with the memory dealt over both nodes
//! gave it all back (counted 2 Oct 2026).
//!
//! **What.** With the knob set, a command that compresses new data into an
//! archive narrows this thread's CPU mask to the CPUs of the node it is
//! running on, before any worker starts, so every thread started after
//! inherits it and the memory they touch is that node's. No memory policy
//! is set. It only ever NARROWS the mask the process already has (a
//! `taskset`, a cgroup's cpuset): it does nothing where that mask already
//! lies inside one node, where the node's share of it would be empty or
//! holds fewer physical cores than [`CORES_LEAST`], or where the command
//! line states `-mt<n>` above the node's share, which is the user's word
//! for a width one node cannot give. A width is all it
//! moves: no archive byte follows it.
//!
//! **Where.** Linux only; every other target compiles this to nothing.
//! With the knob unset nothing is read and no call is made. This is the
//! BINARY's choice, never the library's: an application that links
//! `rarkit` places its own threads.

/// The knob: set to `1`, a create is kept to one node.
const KNOB: &str = "RARFAST_ONE_NODE";

/// The fewest physical cores a node's share of the mask must hold for the
/// create to be kept to it. Under it the cores are worth more than the
/// node. Timed 2 Oct 2026 on a machine of 2 x 96 cores with the mask cut
/// to N CPUs a node (K=3, the parent's wall over the confined run's): a 4
/// GiB member at level 3 read 0.53x at 24, 0.87x at 32, 0.94x at 48, 1.00x
/// at 64 and 1.15x at 96, and at level 1 0.54x at 12 (the segment team
/// starts at 16 cores at level 1 and 32 at levels 2 and 3, and its parses
/// use the rest); 9,516 files and level 5 won from 24 and 32. So 64, the
/// least share at which no row lost
/// (counted 2 Oct 2026).
const CORES_LEAST: usize = 64;

/// Keep this process to one node's CPUs for a command line: when
/// `creates`, the command compressing new data into an archive, and the
/// knob is set. `threads` is the command line's `-mt<n>`. Called once, on
/// the main thread, before the command starts any worker.
pub(crate) fn on_command(threads: Option<u64>, creates: bool) {
    if !creates || !crate::knob::writer_var(KNOB).is_ok_and(|value| value.trim() == "1") {
        return;
    }
    confine(threads);
}

/// The CPUs of a kernel CPU list ("0-95", "0,2-3", "7"), ascending as
/// written; `None` where any part does not parse or a range runs
/// backwards.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn cpu_list(text: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',').filter(|part| !part.is_empty()) {
        let (first, last) = match part.split_once('-') {
            Some((first, last)) => (first.trim().parse().ok()?, last.trim().parse().ok()?),
            None => {
                let cpu: usize = part.trim().parse().ok()?;
                (cpu, cpu)
            }
        };
        if last < first {
            return None;
        }
        cpus.extend(first..=last);
    }
    Some(cpus)
}

/// The CPUs to keep, or `None` to leave the process as it is.
///
/// `allowed` is the mask the process has now, `nodes` each node's CPUs,
/// `here` the CPU the calling thread is on, `threads` a stated `-mt<n>`,
/// and `cores` counts the physical cores among some CPUs (the floor,
/// [`CORES_LEAST`], is in cores: two threads of one core are one).
/// The node is the one `here` belongs to, or, where that cannot be told,
/// the node holding the most allowed CPUs (the lowest numbered of equals).
/// What is kept is that node's share of `allowed`, in `allowed`'s order.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn choose(
    allowed: &[usize],
    nodes: &[Vec<usize>],
    here: Option<usize>,
    threads: Option<u64>,
    cores: impl Fn(&[usize]) -> usize,
) -> Option<Vec<usize>> {
    let shares: Vec<Vec<usize>> = nodes
        .iter()
        .map(|node| {
            allowed
                .iter()
                .copied()
                .filter(|cpu| node.contains(cpu))
                .collect()
        })
        .collect();
    // A mask inside one node already is where this would put it.
    if shares.iter().filter(|share| !share.is_empty()).count() < 2 {
        return None;
    }
    let home = here.and_then(|cpu| shares.iter().position(|share| share.contains(&cpu)));
    let index = home.or_else(|| {
        let most = shares.iter().map(Vec::len).max()?;
        shares.iter().position(|share| share.len() == most)
    })?;
    let share = &shares[index];
    if share.is_empty() {
        return None;
    }
    // A stated width one node cannot give is the user's word.
    if threads.is_some_and(|stated| stated > share.len() as u64) {
        return None;
    }
    // A node too small to give the create every engine it would have had.
    if cores(share) < CORES_LEAST {
        return None;
    }
    Some(share.clone())
}

/// The physical cores among `cpus`, where `siblings(cpu)` is that CPU's
/// sibling list as the kernel writes it ("0,96", "0-1", "3"): two CPUs are
/// one core when their lists name the same first CPU. A list that cannot
/// be read or parsed counts its CPU as a core of its own.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn distinct_cores(cpus: &[usize], siblings: impl Fn(usize) -> Option<String>) -> usize {
    let mut firsts: Vec<usize> = cpus
        .iter()
        .map(|&cpu| {
            siblings(cpu)
                .and_then(|list| cpu_list(&list))
                .and_then(|list| list.first().copied())
                .unwrap_or(cpu)
        })
        .collect();
    firsts.sort_unstable();
    firsts.dedup();
    firsts.len()
}

#[cfg(target_os = "linux")]
fn confine(threads: Option<u64>) {
    let Some(allowed) = allowed_cpus() else {
        return;
    };
    let Some(nodes) = node_cpus() else {
        return;
    };
    let cores = |cpus: &[usize]| {
        distinct_cores(cpus, |cpu| {
            std::fs::read_to_string(format!(
                "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
            ))
            .ok()
        })
    };
    if let Some(keep) = choose(&allowed, &nodes, current_cpu(), threads, cores) {
        keep_to(&keep);
    }
}

#[cfg(not(target_os = "linux"))]
fn confine(_threads: Option<u64>) {}

/// Every node's CPUs, from `/sys/devices/system/node/node<N>/cpulist`;
/// `None` where the directory or any node's list cannot be read, since a
/// partial map would name a node that is not one.
#[cfg(target_os = "linux")]
fn node_cpus() -> Option<Vec<Vec<usize>>> {
    let mut found: Vec<(usize, Vec<usize>)> = Vec::new();
    for entry in std::fs::read_dir("/sys/devices/system/node").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let Some(number) = name.to_str().and_then(|name| name.strip_prefix("node")) else {
            continue;
        };
        let Ok(number) = number.parse::<usize>() else {
            continue;
        };
        let list = std::fs::read_to_string(entry.path().join("cpulist")).ok()?;
        found.push((number, cpu_list(&list)?));
    }
    found.sort_unstable_by_key(|(number, _)| *number);
    Some(found.into_iter().map(|(_, cpus)| cpus).collect())
}

/// The CPUs in this thread's affinity mask, ascending.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn allowed_cpus() -> Option<Vec<usize>> {
    // SAFETY: `cpu_set_t` is plain bits, for which all zeroes is the
    // empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a live, writable `cpu_set_t` and the size passed is
    // its own, which is all the call requires; pid 0 is this thread.
    let ok =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if ok != 0 {
        return None;
    }
    let bits = 8 * std::mem::size_of::<libc::cpu_set_t>();
    // SAFETY: `set` is initialised and `cpu` is below its size in bits.
    Some(
        (0..bits)
            .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
            .collect(),
    )
}

/// The CPU this thread is running on, where the kernel says.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn current_cpu() -> Option<usize> {
    // SAFETY: the call takes no argument and writes nothing.
    let cpu = unsafe { libc::sched_getcpu() };
    usize::try_from(cpu).ok()
}

/// Narrow this thread's affinity mask to `cpus`. A refusal leaves the mask
/// as it was, which is the behaviour without this call.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn keep_to(cpus: &[usize]) {
    let bits = 8 * std::mem::size_of::<libc::cpu_set_t>();
    // SAFETY: as in `allowed_cpus`: all zeroes is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &cpu in cpus.iter().filter(|&&cpu| cpu < bits) {
        // SAFETY: `set` is initialised and `cpu` is below its size in bits.
        unsafe { libc::CPU_SET(cpu, &mut set) };
    }
    // SAFETY: `set` is a live `cpu_set_t` and the size passed is its own;
    // pid 0 is this thread, the only one the process has yet, so every
    // thread started after it inherits the mask. The call reads the set
    // and keeps no pointer to it.
    let _ = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_nodes() -> Vec<Vec<usize>> {
        vec![(0..8).collect(), (8..16).collect()]
    }

    /// Every share is over the floor: the rule without it.
    fn roomy(_cpus: &[usize]) -> usize {
        CORES_LEAST
    }

    #[test]
    fn a_cpu_list_is_read_as_the_kernel_writes_it() {
        assert_eq!(cpu_list("0-3\n"), Some(vec![0, 1, 2, 3]));
        assert_eq!(cpu_list("0,2-3,7"), Some(vec![0, 2, 3, 7]));
        assert_eq!(cpu_list("5"), Some(vec![5]));
        assert_eq!(cpu_list(""), Some(Vec::new()));
        assert_eq!(cpu_list("3-1"), None);
        assert_eq!(cpu_list("0-x"), None);
    }

    #[test]
    fn the_node_the_thread_is_on_is_kept() {
        let all: Vec<usize> = (0..16).collect();
        assert_eq!(
            choose(&all, &two_nodes(), Some(11), None, roomy),
            Some((8..16).collect())
        );
        assert_eq!(
            choose(&all, &two_nodes(), Some(0), None, roomy),
            Some((0..8).collect())
        );
    }

    #[test]
    fn it_only_narrows_the_mask_the_process_has() {
        // Half of each node allowed: the node's share of the mask.
        let mask = [0, 1, 2, 3, 8, 9, 10, 11];
        assert_eq!(
            choose(&mask, &two_nodes(), Some(9), None, roomy),
            Some(vec![8, 9, 10, 11])
        );
        // A mask inside one node, and a machine of one node: nothing.
        assert_eq!(
            choose(&[8, 9, 10], &two_nodes(), Some(9), None, roomy),
            None
        );
        let one = vec![(0..16).collect::<Vec<usize>>()];
        let all: Vec<usize> = (0..16).collect();
        assert_eq!(choose(&all, &one, Some(3), None, roomy), None);
        assert_eq!(choose(&all, &[], Some(3), None, roomy), None);
    }

    #[test]
    fn a_stated_width_above_the_node_is_the_users_word() {
        let all: Vec<usize> = (0..16).collect();
        assert_eq!(choose(&all, &two_nodes(), Some(2), Some(9), roomy), None);
        assert_eq!(
            choose(&all, &two_nodes(), Some(2), Some(8), roomy),
            Some((0..8).collect())
        );
    }

    #[test]
    fn an_unknown_cpu_takes_the_node_with_the_most_allowed() {
        let mask = [0, 1, 8, 9, 10];
        assert_eq!(
            choose(&mask, &two_nodes(), None, None, roomy),
            Some(vec![8, 9, 10])
        );
        // A CPU outside every node's share is unknown too; equals take
        // the lowest numbered node.
        let even = [0, 1, 8, 9];
        assert_eq!(
            choose(&even, &two_nodes(), Some(99), None, roomy),
            Some(vec![0, 1])
        );
    }

    #[test]
    fn a_node_under_the_floor_is_not_kept() {
        let all: Vec<usize> = (0..16).collect();
        let few = |_: &[usize]| CORES_LEAST - 1;
        assert_eq!(choose(&all, &two_nodes(), Some(2), None, few), None);
        // Two threads a core: sixteen CPUs of eight cores.
        let siblings = |cpu: usize| Some(format!("{},{}", cpu % 8, cpu % 8 + 8));
        assert_eq!(distinct_cores(&all, siblings), 8);
        assert_eq!(distinct_cores(&all, |_| None), 16);
        assert_eq!(distinct_cores(&[4, 5], |cpu| Some(format!("{cpu}"))), 2);
        assert_eq!(distinct_cores(&[0, 1], |_| Some("0-1\n".to_owned())), 1);
    }

    #[test]
    fn the_knob_unset_and_a_command_that_creates_nothing_do_nothing() {
        // Neither reaches `confine`: with the knob unset in the test
        // process this thread's mask is what it was.
        #[cfg(target_os = "linux")]
        {
            let before = allowed_cpus();
            on_command(None, false);
            if std::env::var(KNOB).is_err() {
                on_command(None, true);
            }
            assert_eq!(allowed_cpus(), before);
        }
        #[cfg(not(target_os = "linux"))]
        {
            on_command(None, true);
            on_command(Some(4), false);
        }
    }
}
