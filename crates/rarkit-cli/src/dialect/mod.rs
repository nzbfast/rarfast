//! Reference-tool dialects for the `rarfast` front end.
//!
//! `rarfast` is a drop-in for the two reference RAR command-line tools,
//! and which one it is behaving as is decided by `argv[0]` first (a copy
//! or symlink named `unrar` or `rar` behaves as that tool) and by the
//! command letter otherwise. The two command sets overlap only on
//! `e l p t v x`, where the behaviour is the same either way, so the
//! ambiguity is not observable.

pub(crate) mod rar;
pub(crate) mod unrar;

/// Which reference tool this invocation is standing in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// The decoder: `unrar`.
    Unrar,
    /// The creator: `rar` and `winrar`, which share one syntax.
    Rar,
    /// Neither name was used, so the command letter decides.
    Auto,
}

/// Reads the dialect out of the program name.
///
/// The suffix and the case are ignored because Windows invokes
/// `UnRAR.exe` and a Unix symlink is usually bare, and a path is reduced
/// to its file name because a caller may invoke `/usr/local/bin/unrar`.
pub(crate) fn from_argv0(argv0: &str) -> Dialect {
    let name = argv0
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(argv0)
        .to_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    match stem {
        "unrar" => Dialect::Unrar,
        "rar" | "winrar" => Dialect::Rar,
        _ => Dialect::Auto,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_named_unrar_behaves_as_unrar_whatever_its_path() {
        assert_eq!(from_argv0("unrar"), Dialect::Unrar);
        assert_eq!(from_argv0("/usr/local/bin/unrar"), Dialect::Unrar);
        assert_eq!(from_argv0(r"C:\tools\UnRAR.exe"), Dialect::Unrar);
    }

    #[test]
    fn the_creator_names_share_one_dialect() {
        assert_eq!(from_argv0("rar"), Dialect::Rar);
        assert_eq!(from_argv0("winrar.exe"), Dialect::Rar);
    }

    #[test]
    fn its_own_name_leaves_the_command_letter_to_decide() {
        assert_eq!(from_argv0("rarfast"), Dialect::Auto);
        assert_eq!(from_argv0("something-else"), Dialect::Auto);
    }
}
