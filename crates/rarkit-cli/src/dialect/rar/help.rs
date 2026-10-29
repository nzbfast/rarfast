//! The `rar` help screen, one constant per platform.
//!
//! `rar` prints its screen for `rar` with no arguments (exit 0) and for
//! an unknown COMMAND (exit 7), and so does this dialect. What a script
//! can rely on in that screen is kept exactly as the pinned reference
//! prints it (the captured `rar` 7.23 inventory in the
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
//!
//! The two screens differ by twelve switches and by the path separator
//! in the usage line, which is why they are two constants rather than
//! one with a runtime substitution.

/// The macOS and Linux screen.
pub(crate) const HELP_UNIX: &str = r#"Usage:     rar <command> -<switch 1> -<switch N> <archive> <files...>
               <@listfiles...> <path_to_extract/>

<Commands>
  a             Put files into an archive, creating it when needed
  c             Attach a comment to an archive
  ch            Apply the given switches to an existing archive
  cw            Save an archive's comment into a file
  d             Remove members from an archive
  e             Extract everything into one folder, dropping stored paths
  f             Replace members that have a newer copy on disk
  i[par]=<str>  Search archived data for text [search options]
  k             Mark an archive so rar refuses to modify it
  l[t[a],b]     Show the members [with details[and service data], names only]
  m[f]          Archive, then delete the originals [keep folders]
  p             Send a member's contents to standard output
  r             Try to fix a damaged archive
  rc            Rebuild absent volumes of a set from its .rev files
  rn            Give members new names
  rr[N]         Append recovery data that can mend damage [amount]
  rv[N]         Write .rev files beside a volume set [how many]
  s[name|-]     Make an archive self-extracting [module], or undo it with -
  t             Decode every member and check its checksum
  u             Add files not yet archived and replace changed ones
  v[t[a],b]     Show members with packed size, ratio and checksum [as l]
  x             Extract, recreating each member's stored folder path

<Switches>
  -             Treat all later arguments as names, never as switches
  @[+]          Stop [or resume] reading names from @listfile arguments
  ad[1,2]       Extract below a folder named after the archive [variants]
  ag[format]    Name the archive after today's date and time [pattern]
  ai            Do not restore the stored file attributes
  am[s,r]       Keep the archive's own name and timestamp [store, apply]
  ap<path>      Place added files under this folder inside the archive
  as            Remove members whose files are no longer on disk
  c-            Do not print archive comments
  cfg-          Ignore the configuration file and RAR environment variable
  cl            Turn names into lower case
  cu            Turn names into upper case
  df            Delete source files once they are archived
  dh            Read files even while another program has them open
  ds            Keep the given order in a solid archive, unsorted
  dw            Overwrite, then delete, source files once archived
  e[+]<attr>    Skip files with these attributes [+ selects only them]
  ed            Leave out folders that hold no files
  ep            Leave folder paths out of names
  ep1           Store names relative to the folder named on the command line
  ep3           Use absolute paths, drive letter and all
  ep4<path>     Remove this leading folder from each name
  f             Only refresh members the archive already has
  hp[password]  Encrypt names and headers as well as contents
  ht[b|c]       Checksum for file data [b BLAKE2sp, c CRC32]
  id[c,d,n,p,q] Silence parts of the output [banner,done,names,percent,most]
  ierr          Print everything on standard error
  ilog[name]    Append error reports to a log [file name]
  inul          Print nothing, error reports included
  isnd[-]       Sound a signal when done [or never]
  iver          Print version and stop
  k             Lock the archive once written
  kb            Keep an extracted file even if its checksum is wrong
  log[f][=name] Record processed names in a list [format][=file]
  m<0..5>       How hard to compress: 0 stores, 1 fastest, 5 smallest
  mc<par>       Fine-tune the compressor [parameters]
  md[x]<n>[kmg] How far back matches may reach [k, m or g units]
  me[par]       Choose encryption options [parameters]
  ms[ext;ext]   Store these extensions uncompressed
  mt<threads>   Worker threads to use
  n<file>       Only process names that also match this mask
  n@            Take extra include masks from standard input
  n@<list>      Take extra include masks from a list file
  o[+|-]        When a file exists: + replaces it, - keeps it
  oh            Archive a hard link as a link, not another copy
  oi[0-4][:min] Store repeats of an identical file once [level][:min size]
  ol[a,-]       Keep symlinks as links [allow absolute targets, skip them]
  om[-|1][=lst] Pass the Mark of the Web to extracted files [off|all][=masks]
  op<path>      Write extracted files under this folder
  or            Pick a new name instead of overwriting a file
  ow            Store or reapply the user and group that own each file
  p[password]   Password to use; asked for when left empty
  qo[-|+]       Quick-open index [- leave out, + always]
  r             Include subfolders too
  r-            Do not descend into subfolders
  r0            Descend into subfolders only for wildcard masks
  rr[N]         Append recovery data that can mend damage [amount]
  rv[N]         Write .rev files beside a volume set [how many]
  s[=<par>]     Pack files as one continuous stream [options]
  sc<chr>[obj]  Text encoding for list, comment and log files [which ones]
  sfx[name]     Build a self-extracting archive [module]
  si[name]      Take the input from standard input [its name]
  sl<size>[u]   Only files smaller than this size [unit]
  sm<size>[u]   Only files larger than this size [unit]
  t             Verify the archive once written
  ta[mcao]<d>   Only files whose time is after <d> YYYYMMDDHHMMSS
  tb[mcao]<d>   Only files whose time is before <d> YYYYMMDDHHMMSS
  tk[<date>]    Leave the archive time alone, or set it [date]
  tl            Date the archive by its newest member
  tn[mcao]<t>   Only files younger than the period <t>
  to[mcao]<t>   Only files at least as old as the period <t>
  ts[m,c,a,p]   Keep file times [m modified, c created, a accessed, p precise]
  u             Add new files and replace changed ones
  v             Split to suit the media, or show every volume when listing
  v<size>[u]    Split into volumes of this size [bBkKmMgGtT unit]
  ver[n]        Work with numbered older versions of files [number]
  vp            Wait for a keypress before starting each volume
  w<path>       Folder for temporary files
  x<file>       Skip names that match this mask
  x@            Take skip masks from standard input
  x@<list>      Take skip masks from a list file
  y             Answer yes to every question
  z[file]       Take the comment from a file [stdin if none]"#;

/// The Windows screen: twelve more switches, and a backslash in the
/// `<path_to_extract>` placeholder.
pub(crate) const HELP_WINDOWS: &str = r#"Usage:     rar <command> -<switch 1> -<switch N> <archive> <files...>
               <@listfiles...> <path_to_extract\>

<Commands>
  a             Put files into an archive, creating it when needed
  c             Attach a comment to an archive
  ch            Apply the given switches to an existing archive
  cw            Save an archive's comment into a file
  d             Remove members from an archive
  e             Extract everything into one folder, dropping stored paths
  f             Replace members that have a newer copy on disk
  i[par]=<str>  Search archived data for text [search options]
  k             Mark an archive so rar refuses to modify it
  l[t[a],b]     Show the members [with details[and service data], names only]
  m[f]          Archive, then delete the originals [keep folders]
  p             Send a member's contents to standard output
  r             Try to fix a damaged archive
  rc            Rebuild absent volumes of a set from its .rev files
  rn            Give members new names
  rr[N]         Append recovery data that can mend damage [amount]
  rv[N]         Write .rev files beside a volume set [how many]
  s[name|-]     Make an archive self-extracting [module], or undo it with -
  t             Decode every member and check its checksum
  u             Add files not yet archived and replace changed ones
  v[t[a],b]     Show members with packed size, ratio and checksum [as l]
  x             Extract, recreating each member's stored folder path

<Switches>
  -             Treat all later arguments as names, never as switches
  @[+]          Stop [or resume] reading names from @listfile arguments
  ac            Reset each file's Archive flag once it is processed
  ad[1,2]       Extract below a folder named after the archive [variants]
  ag[format]    Name the archive after today's date and time [pattern]
  ai            Do not restore the stored file attributes
  am[s,r]       Keep the archive's own name and timestamp [store, apply]
  ao            Only add files whose Archive flag is set
  ap<path>      Place added files under this folder inside the archive
  as            Remove members whose files are no longer on disk
  c-            Do not print archive comments
  cfg-          Ignore the configuration file and RAR environment variable
  cl            Turn names into lower case
  cu            Turn names into upper case
  df            Delete source files once they are archived
  dh            Read files even while another program has them open
  dr            Move deleted source files to the Recycle Bin
  ds            Keep the given order in a solid archive, unsorted
  dw            Overwrite, then delete, source files once archived
  e[+]<attr>    Skip files with these attributes [+ selects only them]
  ed            Leave out folders that hold no files
  ep            Leave folder paths out of names
  ep1           Store names relative to the folder named on the command line
  ep2           Store absolute paths
  ep3           Use absolute paths, drive letter and all
  ep4<path>     Remove this leading folder from each name
  f             Only refresh members the archive already has
  hp[password]  Encrypt names and headers as well as contents
  ht[b|c]       Checksum for file data [b BLAKE2sp, c CRC32]
  id[c,d,n,p,q] Silence parts of the output [banner,done,names,percent,most]
  ieml[addr]    Email the archive when done [address]
  ierr          Print everything on standard error
  ilog[name]    Append error reports to a log [file name]
  inul          Print nothing, error reports included
  ioff[n]       Power the computer off when done [mode]
  isnd[-]       Sound a signal when done [or never]
  iver          Print version and stop
  k             Lock the archive once written
  kb            Keep an extracted file even if its checksum is wrong
  log[f][=name] Record processed names in a list [format][=file]
  m<0..5>       How hard to compress: 0 stores, 1 fastest, 5 smallest
  mc<par>       Fine-tune the compressor [parameters]
  md[x]<n>[kmg] How far back matches may reach [k, m or g units]
  me[par]       Choose encryption options [parameters]
  mlp           Request large-page memory from Windows
  ms[ext;ext]   Store these extensions uncompressed
  mt<threads>   Worker threads to use
  n<file>       Only process names that also match this mask
  n@            Take extra include masks from standard input
  n@<list>      Take extra include masks from a list file
  o[+|-]        When a file exists: + replaces it, - keeps it
  oc            Keep the NTFS compression flag
  oh            Archive a hard link as a link, not another copy
  oi[0-4][:min] Store repeats of an identical file once [level][:min size]
  ol[a,-]       Keep symlinks as links [allow absolute targets, skip them]
  om[-|1][=lst] Pass the Mark of the Web to extracted files [off|all][=masks]
  oni           Permit names that may not work on every system
  op<path>      Write extracted files under this folder
  or            Pick a new name instead of overwriting a file
  os            Include NTFS alternate data streams
  ow            Store or reapply the user and group that own each file
  p[password]   Password to use; asked for when left empty
  qo[-|+]       Quick-open index [- leave out, + always]
  r             Include subfolders too
  r-            Do not descend into subfolders
  r0            Descend into subfolders only for wildcard masks
  ri<P>[:<S>]   Run at priority P (0 normal, 1 low..15 high), S ms pauses
  rr[N]         Append recovery data that can mend damage [amount]
  rv[N]         Write .rev files beside a volume set [how many]
  s[=<par>]     Pack files as one continuous stream [options]
  sc<chr>[obj]  Text encoding for list, comment and log files [which ones]
  sfx[name]     Build a self-extracting archive [module]
  si[name]      Take the input from standard input [its name]
  sl<size>[u]   Only files smaller than this size [unit]
  sm<size>[u]   Only files larger than this size [unit]
  t             Verify the archive once written
  ta[mcao]<d>   Only files whose time is after <d> YYYYMMDDHHMMSS
  tb[mcao]<d>   Only files whose time is before <d> YYYYMMDDHHMMSS
  tk[<date>]    Leave the archive time alone, or set it [date]
  tl            Date the archive by its newest member
  tn[mcao]<t>   Only files younger than the period <t>
  to[mcao]<t>   Only files at least as old as the period <t>
  ts[m,c,a,p]   Keep file times [m modified, c created, a accessed, p precise]
  u             Add new files and replace changed ones
  v             Split to suit the media, or show every volume when listing
  v<size>[u]    Split into volumes of this size [bBkKmMgGtT unit]
  vd            Wipe the disk before writing each volume
  ver[n]        Work with numbered older versions of files [number]
  vp            Wait for a keypress before starting each volume
  w<path>       Folder for temporary files
  x<file>       Skip names that match this mask
  x@            Take skip masks from standard input
  x@<list>      Take skip masks from a list file
  y             Answer yes to every question
  z[file]       Take the comment from a file [stdin if none]"#;

/// The screen for the box this binary is running on.
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
    a c ch cw d e f i[par]=<str> k l[t[a],b] m[f] p r rc rn rr[N] rv[N] \
    s[name|-] t u v[t[a],b] x - @[+] ad[1,2] ag[format] ai am[s,r] ap<path> as \
    c- cfg- cl cu df dh ds dw e[+]<attr> ed ep ep1 ep3 ep4<path> f \
    hp[password] ht[b|c] id[c,d,n,p,q] ierr ilog[name] inul isnd[-] iver k kb \
    log[f][=name] m<0..5> mc<par> md[x]<n>[kmg] me[par] ms[ext;ext] \
    mt<threads> n<file> n@ n@<list> o[+|-] oh oi[0-4][:min] ol[a,-] \
    om[-|1][=lst] op<path> or ow p[password] qo[-|+] r r- r0 rr[N] rv[N] \
    s[=<par>] sc<chr>[obj] sfx[name] si[name] sl<size>[u] sm<size>[u] t \
    ta[mcao]<d> tb[mcao]<d> tk[<date>] tl tn[mcao]<t> to[mcao]<t> ts[m,c,a,p] \
    u v v<size>[u] ver[n] vp w<path> x<file> x@ x@<list> y z[file]";
    const WINDOWS_SPELLINGS: &str = "\
    a c ch cw d e f i[par]=<str> k l[t[a],b] m[f] p r rc rn rr[N] rv[N] \
    s[name|-] t u v[t[a],b] x - @[+] ac ad[1,2] ag[format] ai am[s,r] ao \
    ap<path> as c- cfg- cl cu df dh dr ds dw e[+]<attr> ed ep ep1 ep2 ep3 \
    ep4<path> f hp[password] ht[b|c] id[c,d,n,p,q] ieml[addr] ierr ilog[name] \
    inul ioff[n] isnd[-] iver k kb log[f][=name] m<0..5> mc<par> md[x]<n>[kmg] \
    me[par] mlp ms[ext;ext] mt<threads> n<file> n@ n@<list> o[+|-] oc oh \
    oi[0-4][:min] ol[a,-] om[-|1][=lst] oni op<path> or os ow p[password] \
    qo[-|+] r r- r0 ri<P>[:<S>] rr[N] rv[N] s[=<par>] sc<chr>[obj] sfx[name] \
    si[name] sl<size>[u] sm<size>[u] t ta[mcao]<d> tb[mcao]<d> tk[<date>] tl \
    tn[mcao]<t> to[mcao]<t> ts[m,c,a,p] u v v<size>[u] vd ver[n] vp w<path> \
    x<file> x@ x@<list> y z[file]";

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
                "Usage:     rar <command> -<switch 1> -<switch N> <archive> <files...>\n"
            ));
        }
        let unix = spellings(HELP_UNIX);
        let windows = spellings(HELP_WINDOWS);
        assert_eq!(unix, UNIX_SPELLINGS.split(' ').collect::<Vec<_>>());
        assert_eq!(windows, WINDOWS_SPELLINGS.split(' ').collect::<Vec<_>>());
        // The Windows-only switches are the whole reason there are two
        // constants.
        for spell in [
            "ac",
            "ao",
            "dr",
            "ep2",
            "ieml[addr]",
            "ioff[n]",
            "mlp",
            "oc",
            "oni",
            "os",
            "ri<P>[:<S>]",
            "vd",
        ] {
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
