//! The `unrar` help screen, one constant per platform.
//!
//! unrar prints its screen for `unrar` with no arguments (exit 0) and for
//! an unknown COMMAND (exit 7), and so does this dialect. What a script
//! can rely on in that screen is kept exactly as the pinned reference
//! prints it (the captured `unrar` 7.23 inventory in the
//! project's harness): the usage line, the two block headers, and every
//! command and switch spelling, in the same order, with its description
//! starting in the same column. The DESCRIPTIONS are rarfast's own,
//! written from what each switch does. The reference's are RARLAB's text
//! and are not reproduced (the project's
//! research notes, the provenance audit of 14 Sep 2026, section 5.9).
//!
//! So the `no-arguments` and `bad-command` conformance rows differ on
//! stdout by design and carry a waiver for that one field; their exit
//! codes and stderr are still compared, and the spelling column is held
//! to the reference's by the test at the bottom of this file. When the
//! pin moves, re-capture the inventory, add any new spelling here with a
//! description of our own, and update the test's list.

/// The macOS and Linux screen.
pub(crate) const HELP_UNIX: &str = r#"Usage:     unrar <command> -<switch 1> -<switch N> <archive> <files...>
               <@listfiles...> <path_to_extract/>

<Commands>
  e             Extract everything into one folder, dropping stored paths
  l[t[a],b]     Show the members [with details[and service data], names only]
  p             Send a member's contents to standard output
  t             Decode every member and check its checksum
  v[t[a],b]     Show members with packed size, ratio and checksum [as l]
  x             Extract, recreating each member's stored folder path

<Switches>
  -             Treat all later arguments as names, never as switches
  @[+]          Stop [or resume] reading names from @listfile arguments
  ad[1,2]       Extract below a folder named after the archive [variants]
  ag[format]    Name the archive after today's date and time [pattern]
  ai            Do not restore the stored file attributes
  ap<path>      Extract only what sits under this folder in the archive
  c-            Do not print archive comments
  cfg-          Ignore the configuration file and RAR environment variable
  cl            Turn names into lower case
  cu            Turn names into upper case
  dh            Read files even while another program has them open
  ep            Leave folder paths out of names
  ep3           Use absolute paths, drive letter and all
  ep4<path>     Remove this leading folder from each name
  f             Only replace files on disk that exist and are older
  id[c,d,n,p,q] Silence parts of the output [banner,done,names,percent,most]
  ierr          Print everything on standard error
  inul          Print nothing, error reports included
  kb            Keep an extracted file even if its checksum is wrong
  me[par]       Choose encryption options [parameters]
  n<file>       Only process names that also match this mask
  n@            Take extra include masks from standard input
  n@<list>      Take extra include masks from a list file
  o[+|-]        When a file exists: + replaces it, - keeps it
  ol[a,-]       Keep symlinks as links [allow absolute targets, skip them]
  om[-|1][=lst] Pass the Mark of the Web to extracted files [off|all][=masks]
  op<path>      Write extracted files under this folder
  or            Pick a new name instead of overwriting a file
  ow            Store or reapply the user and group that own each file
  p[password]   Password to use; asked for when left empty
  r             Include subfolders too
  sc<chr>[obj]  Text encoding for list, comment and log files [which ones]
  si[name]      Take the input from standard input [its name]
  sl<size>[u]   Only files smaller than this size [unit]
  ta[mcao]<d>   Only files whose time is after <d> YYYYMMDDHHMMSS
  tb[mcao]<d>   Only files whose time is before <d> YYYYMMDDHHMMSS
  tn[mcao]<t>   Only files younger than the period <t>
  to[mcao]<t>   Only files at least as old as the period <t>
  ts[m,c,a,p]   Keep file times [m modified, c created, a accessed, p precise]
  u             Extract files that are missing or newer than the copy on disk
  v             Show every volume of a set, not only the first
  ver[n]        Work with numbered older versions of files [number]
  vp            Wait for a keypress before starting each volume
  x<file>       Skip names that match this mask
  x@            Take skip masks from standard input
  x@<list>      Take skip masks from a list file
  y             Answer yes to every question
"#;

/// The Windows screen. Five switches exist only here (`-ac`, `-ioff`,
/// `-mlp`, `-oc`, `-ri`), which is the whole reason the inventory is
/// captured twice.
pub(crate) const HELP_WINDOWS: &str = r#"Usage:     unrar <command> -<switch 1> -<switch N> <archive> <files...>
               <@listfiles...> <path_to_extract\>

<Commands>
  e             Extract everything into one folder, dropping stored paths
  l[t[a],b]     Show the members [with details[and service data], names only]
  p             Send a member's contents to standard output
  t             Decode every member and check its checksum
  v[t[a],b]     Show members with packed size, ratio and checksum [as l]
  x             Extract, recreating each member's stored folder path

<Switches>
  -             Treat all later arguments as names, never as switches
  @[+]          Stop [or resume] reading names from @listfile arguments
  ac            Reset each file's Archive flag once it is processed
  ad[1,2]       Extract below a folder named after the archive [variants]
  ag[format]    Name the archive after today's date and time [pattern]
  ai            Do not restore the stored file attributes
  ap<path>      Extract only what sits under this folder in the archive
  c-            Do not print archive comments
  cfg-          Ignore the configuration file and RAR environment variable
  cl            Turn names into lower case
  cu            Turn names into upper case
  dh            Read files even while another program has them open
  ep            Leave folder paths out of names
  ep3           Use absolute paths, drive letter and all
  ep4<path>     Remove this leading folder from each name
  f             Only replace files on disk that exist and are older
  id[c,d,n,p,q] Silence parts of the output [banner,done,names,percent,most]
  ierr          Print everything on standard error
  inul          Print nothing, error reports included
  ioff[n]       Power the computer off when done [mode]
  kb            Keep an extracted file even if its checksum is wrong
  me[par]       Choose encryption options [parameters]
  mlp           Request large-page memory from Windows
  n<file>       Only process names that also match this mask
  n@            Take extra include masks from standard input
  n@<list>      Take extra include masks from a list file
  o[+|-]        When a file exists: + replaces it, - keeps it
  oc            Keep the NTFS compression flag
  ol[a,-]       Keep symlinks as links [allow absolute targets, skip them]
  om[-|1][=lst] Pass the Mark of the Web to extracted files [off|all][=masks]
  op<path>      Write extracted files under this folder
  or            Pick a new name instead of overwriting a file
  ow            Store or reapply the user and group that own each file
  p[password]   Password to use; asked for when left empty
  r             Include subfolders too
  ri<P>[:<S>]   Run at priority P (0 normal, 1 low..15 high), S ms pauses
  sc<chr>[obj]  Text encoding for list, comment and log files [which ones]
  si[name]      Take the input from standard input [its name]
  sl<size>[u]   Only files smaller than this size [unit]
  ta[mcao]<d>   Only files whose time is after <d> YYYYMMDDHHMMSS
  tb[mcao]<d>   Only files whose time is before <d> YYYYMMDDHHMMSS
  tn[mcao]<t>   Only files younger than the period <t>
  to[mcao]<t>   Only files at least as old as the period <t>
  ts[m,c,a,p]   Keep file times [m modified, c created, a accessed, p precise]
  u             Extract files that are missing or newer than the copy on disk
  v             Show every volume of a set, not only the first
  ver[n]        Work with numbered older versions of files [number]
  vp            Wait for a keypress before starting each volume
  x<file>       Skip names that match this mask
  x@            Take skip masks from standard input
  x@<list>      Take skip masks from a list file
  y             Answer yes to every question
"#;

/// The screen for the platform this binary was built for.
pub(crate) fn help_screen() -> &'static str {
    if cfg!(windows) {
        HELP_WINDOWS
    } else {
        HELP_UNIX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spelling column of each screen, commands then switches, in
    /// screen order: the pinned reference's own, parsed off its captured
    /// inventory. The descriptions beside them are ours; these are not.
    const UNIX_SPELLINGS: &str = "\
    e l[t[a],b] p t v[t[a],b] x - @[+] ad[1,2] ag[format] ai ap<path> c- cfg- \
    cl cu dh ep ep3 ep4<path> f id[c,d,n,p,q] ierr inul kb me[par] n<file> n@ \
    n@<list> o[+|-] ol[a,-] om[-|1][=lst] op<path> or ow p[password] r \
    sc<chr>[obj] si[name] sl<size>[u] ta[mcao]<d> tb[mcao]<d> tn[mcao]<t> \
    to[mcao]<t> ts[m,c,a,p] u v ver[n] vp x<file> x@ x@<list> y";
    const WINDOWS_SPELLINGS: &str = "\
    e l[t[a],b] p t v[t[a],b] x - @[+] ac ad[1,2] ag[format] ai ap<path> c- \
    cfg- cl cu dh ep ep3 ep4<path> f id[c,d,n,p,q] ierr inul ioff[n] kb \
    me[par] mlp n<file> n@ n@<list> o[+|-] oc ol[a,-] om[-|1][=lst] op<path> \
    or ow p[password] r ri<P>[:<S>] sc<chr>[obj] si[name] sl<size>[u] \
    ta[mcao]<d> tb[mcao]<d> tn[mcao]<t> to[mcao]<t> ts[m,c,a,p] u v ver[n] vp \
    x<file> x@ x@<list> y";

    /// Reads the spelling column back off a screen, refusing a line whose
    /// description does not start in column 16 or that would wrap on an
    /// 80-column terminal.
    fn spellings(screen: &str) -> Vec<&str> {
        let mut found = Vec::new();
        let mut in_block = false;
        for line in screen.lines() {
            if line == "<Commands>" || line == "<Switches>" {
                in_block = true;
                continue;
            }
            if !in_block || line.is_empty() {
                continue;
            }
            let bytes = line.as_bytes();
            assert!(
                bytes.len() > 16 && &bytes[..2] == b"  " && bytes[2] != b' ',
                "not a spelling line: {line:?}"
            );
            assert!(
                bytes[15] == b' ' && bytes[16] != b' ',
                "description out of column: {line:?}"
            );
            assert!(line.len() < 80, "wider than a terminal: {line:?}");
            found.push(line[2..16].trim_end());
        }
        found
    }

    #[test]
    fn the_spelling_column_is_the_reference_screens() {
        for screen in [HELP_UNIX, HELP_WINDOWS] {
            assert!(screen.starts_with(
                "Usage:     unrar <command> -<switch 1> -<switch N> <archive> <files...>\n"
            ));
        }
        let unix = spellings(HELP_UNIX);
        let windows = spellings(HELP_WINDOWS);
        assert_eq!(unix, UNIX_SPELLINGS.split(' ').collect::<Vec<_>>());
        assert_eq!(windows, WINDOWS_SPELLINGS.split(' ').collect::<Vec<_>>());
        // The Windows-only switches are the whole reason there are two
        // constants.
        for spell in ["ac", "ioff[n]", "mlp", "oc", "ri<P>[:<S>]"] {
            assert!(
                windows.contains(&spell),
                "the Windows screen lost {spell:?}"
            );
            assert!(
                !unix.contains(&spell),
                "{spell:?} is Windows-only and must not be on the unix screen"
            );
        }
    }
}
