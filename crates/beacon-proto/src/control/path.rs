//! Validation of names and relative paths received over the control channel
//! (map names, map file paths). Both the server (serving `map_get`) and the launcher
//! (writing into the BFME `Maps` folder) must reject anything that could escape the
//! target directory or alias a Windows device or stream.

/// Maximum length in bytes of a file name or of a whole relative path.
const MAX_LEN: usize = 255;

/// Maximum number of components of a relative path (architecture §8: max depth 2).
pub const MAX_PATH_DEPTH: usize = 2;

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
    !path.is_empty()
        && path.len() <= MAX_LEN
        && path.split(['/', '\\']).count() <= MAX_PATH_DEPTH
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
}
