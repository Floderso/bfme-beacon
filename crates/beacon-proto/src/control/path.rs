//! Validation of names and relative paths received over the control channel
//! (map names, map file paths, game-configuration file paths). Both the server
//! (serving `map_get`, accepting a configuration) and the launcher (writing into
//! the BFME `Maps` folder or a Beacon instance folder) must reject anything that
//! could escape the target directory or alias a Windows device or stream.

/// Maximum length in bytes of a file name or of a whole relative path.
const MAX_LEN: usize = 255;

/// Maximum number of components of a relative path (architecture §8: max depth 2).
pub const MAX_PATH_DEPTH: usize = 2;

/// Maximum number of components of a package file path (`data\movies\x.vp6` has
/// three; the BFME Workshop manifests seen use at most three).
pub const MAX_PACKAGE_PATH_DEPTH: usize = 8;

/// `true` if `name` is a safe single path component on Windows and Unix:
/// non-empty, at most 255 bytes, not `.`/`..`, no separators, no `:` (drive letters,
/// alternate data streams), no `<>"|?*`, no control characters, no trailing dot or
/// space, and not a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0-9`,
/// `LPT0-9`, `CONIN$`, `CONOUT$`, also with an extension).
pub fn is_safe_file_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_LEN || name == "." || name == ".." {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
    }) {
        return false;
    }
    !is_reserved_device_name(name)
}

/// `true` if `path` is a safe relative path: at most 255 bytes and
/// [`MAX_PATH_DEPTH`] components separated by `/` or `\`, every component passing
/// [`is_safe_file_name`]. This rejects absolute paths, UNC paths, drive letters,
/// empty components (`a//b`, trailing separator) and `..`.
pub fn is_safe_rel_path(path: &str) -> bool {
    is_safe_rel_path_depth(path, MAX_PATH_DEPTH)
}

/// `true` if `path` is a safe relative path of a package file (a game-configuration
/// entry): like [`is_safe_rel_path`], but with up to [`MAX_PACKAGE_PATH_DEPTH`]
/// components.
pub fn is_safe_package_path(path: &str) -> bool {
    is_safe_rel_path_depth(path, MAX_PACKAGE_PATH_DEPTH)
}

/// The canonical form of a package file path, as the BFME Workshop launcher writes
/// it to disk: `/` becomes `\`, letters are lower-cased. `None` if the result is
/// not a [safe package path](is_safe_package_path).
pub fn normalize_package_path(path: &str) -> Option<String> {
    let normalized = path.replace('/', "\\").to_lowercase();
    is_safe_package_path(&normalized).then_some(normalized)
}

fn is_safe_rel_path_depth(path: &str, max_depth: usize) -> bool {
    !path.is_empty()
        && path.len() <= MAX_LEN
        && path.split(['/', '\\']).count() <= max_depth
        && path.split(['/', '\\']).all(is_safe_file_name)
}

fn is_reserved_device_name(name: &str) -> bool {
    // Windows maps these names to devices regardless of extension and of trailing
    // spaces before the extension ("nul .txt").
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '¹' | '²' | '³'), None)
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        for ok in [
            "map.map",
            "Helms Deep",
            "map.tga",
            "art",
            ".hidden",
            "a.b.c",
            "COM10",
            "LPTX",
            "console.ini",
            "nul2",
            "Minas Tirith (4)",
            "ümlaut.str",
        ] {
            assert!(is_safe_file_name(ok), "{ok:?}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "c:",
            "file.txt:stream",
            "trailing.",
            "trailing ",
            "CON",
            "con",
            "Con.txt",
            "nul .txt",
            "PRN.map",
            "aux",
            "COM1",
            "com9.ini",
            "LPT0",
            "lpt3.big",
            "COM¹",
            "CONIN$",
            "conout$.log",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "tab\there",
            "nul\0byte",
            "del\u{7f}",
        ] {
            assert!(!is_safe_file_name(bad), "{bad:?}");
        }
        assert!(is_safe_file_name(&"a".repeat(255)));
        assert!(!is_safe_file_name(&"a".repeat(256)));
    }

    #[test]
    fn rel_paths() {
        for ok in ["map.map", "Helms Deep/map.map", "art\\tex.tga", "a/b"] {
            assert!(is_safe_rel_path(ok), "{ok:?}");
        }
        for bad in [
            "",
            "a/b/c",
            "a/b/c/d.ini",
            "a\\b/c",
            "/etc/passwd",
            "\\windows",
            "\\\\server\\share\\x",
            "C:\\x",
            "C:x",
            "../x",
            "a/../../x",
            "a/./b",
            "a//b",
            "a/",
            "a\\",
            "maps/CON/x",
            "maps/x.map:evil",
            "a/b./c",
        ] {
            assert!(!is_safe_rel_path(bad), "{bad:?}");
        }
        let half = "a".repeat(127);
        assert!(is_safe_rel_path(&format!("{half}/{half}")));
        assert!(!is_safe_rel_path(&format!("{half}a/{half}")));
        assert!(is_safe_rel_path(&"a".repeat(255)));
        assert!(!is_safe_rel_path(&"a".repeat(256)));
    }

    #[test]
    fn package_paths() {
        for ok in [
            "_patch106.big",
            "data\\movies\\101_with_alpha.vp6",
            "apt/AptLevel0.big",
            "!!!betapit.big",
            "###saf2.1.big",
            "a/b/c/d/e/f/g/h",
        ] {
            assert!(is_safe_package_path(ok), "{ok:?}");
        }
        for bad in [
            "",
            "a/b/c/d/e/f/g/h/i",
            "..\\x.big",
            "data\\..\\..\\x",
            "C:\\x.big",
            "\\\\server\\share\\x.big",
            "\\x.big",
            "x.big:zone",
            "lang\\nul.big",
            "data\\",
            "x.big.",
        ] {
            assert!(!is_safe_package_path(bad), "{bad:?}");
        }
        assert_eq!(
            normalize_package_path("Data/Movies/Intro.VP6").as_deref(),
            Some("data\\movies\\intro.vp6")
        );
        assert_eq!(normalize_package_path("apt\\AptLevel0.big").as_deref(), Some("apt\\aptlevel0.big"));
        assert_eq!(normalize_package_path("../x"), None);
        assert_eq!(normalize_package_path("CON.big"), None);
    }
}
