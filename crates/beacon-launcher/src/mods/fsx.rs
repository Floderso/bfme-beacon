//! File-system helpers for the store and the instances: read-only attributes,
//! forced deletion (the store's files are read-only, and through hardlinks so
//! are the instances' files), bounded tree walks and free space.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Most directory entries any walk of Beacon's own folders looks at.
pub const MAX_WALK_ENTRIES: usize = 200_000;
/// Deepest folder level of a walk.
pub const MAX_WALK_DEPTH: usize = 16;

/// Sets or clears the read-only attribute.
pub fn set_readonly(path: &Path, readonly: bool) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    let mut perms = meta.permissions();
    if perms.readonly() == readonly {
        return Ok(());
    }
    // Windows: only toggles FILE_ATTRIBUTE_READONLY.
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(readonly);
    fs::set_permissions(path, perms)
}

/// Deletes a file (or a link to a file), clearing the read-only attribute if
/// needed. A missing file is fine.
///
/// For a hardlink the attribute belongs to the shared file: clearing it here
/// also clears it for the store's name (the store protects its files again).
pub fn remove_file_force(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            set_readonly(path, false)?;
            fs::remove_file(path)
        }
        Err(e) => Err(e),
    }
}

/// Deletes a folder tree without following links or junctions (a link is
/// removed, never its target). A missing folder is fine.
pub fn remove_tree(dir: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return remove_link_or_file(dir, &meta);
    }
    let mut stack = vec![(dir.to_path_buf(), false)];
    let mut seen = 0usize;
    while let Some((path, visited)) = stack.pop() {
        if visited {
            fs::remove_dir(&path).or_else(|e| match e.kind() {
                io::ErrorKind::NotFound => Ok(()),
                io::ErrorKind::PermissionDenied => {
                    set_readonly(&path, false)?;
                    fs::remove_dir(&path)
                }
                _ => Err(e),
            })?;
            continue;
        }
        stack.push((path.clone(), true));
        for entry in fs::read_dir(&path)? {
            seen += 1;
            if seen > MAX_WALK_ENTRIES {
                return Err(io::Error::other(format!("{} has too many entries", dir.display())));
            }
            let entry = entry?;
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.is_dir() && !meta.file_type().is_symlink() {
                stack.push((entry.path(), false));
            } else {
                remove_link_or_file(&entry.path(), &meta)?;
            }
        }
    }
    Ok(())
}

fn remove_link_or_file(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    if meta.is_dir() {
        // A directory symlink or junction: remove the link only.
        fs::remove_dir(path)
    } else {
        remove_file_force(path)
    }
}

/// One file found by [`walk_files`].
#[derive(Debug, Clone)]
pub struct WalkedFile {
    /// Absolute path.
    pub path: PathBuf,
    /// Path relative to the walk's root, components joined with `\`, lower case.
    pub rel: String,
    /// File name (original case).
    pub name: String,
    /// Size.
    pub size: u64,
}

/// Every regular file below `root` (links and junctions are not followed),
/// at most `max_entries` entries and `max_depth` levels; `skip` excludes folders.
pub fn walk_files(
    root: &Path,
    max_depth: usize,
    max_entries: usize,
    skip: &dyn Fn(&Path) -> bool,
) -> io::Result<Vec<WalkedFile>> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    let mut seen = 0usize;
    while let Some((dir, prefix, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if depth == 0 => return Err(e),
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > max_entries {
                return Ok(out);
            }
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.to_lowercase()
            } else {
                format!("{prefix}\\{}", name.to_lowercase())
            };
            let path = entry.path();
            if kind.is_dir() {
                if depth < max_depth && !skip(&path) {
                    stack.push((path, rel, depth + 1));
                }
            } else if kind.is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.push(WalkedFile { path, rel, name, size });
            }
        }
    }
    Ok(out)
}

/// Free bytes on the volume of `path` (the nearest existing ancestor); `None`
/// if unknown (not Windows, or the call failed).
pub fn free_space(path: &Path) -> Option<u64> {
    let mut p = Some(path);
    while let Some(dir) = p {
        if dir.exists() {
            return crate::sys::free_space(dir).ok();
        }
        p = dir.parent();
    }
    None
}

/// `true` if two paths start with the same folder (case-insensitive prefix test
/// on the textual paths; used to keep scans out of Beacon's own folders).
pub fn is_inside(path: &Path, dir: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase().replace('/', "\\");
    let d = dir.to_string_lossy().to_lowercase().replace('/', "\\");
    let d = d.trim_end_matches('\\');
    p == d || p.starts_with(&format!("{d}\\"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-fsx-{tag}-{}", std::process::id()));
        let _ = remove_tree(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn read_only_files_are_removed() {
        let d = temp("ro");
        let f = d.join("sub").join("x.big");
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, b"x").unwrap();
        set_readonly(&f, true).unwrap();
        assert!(fs::metadata(&f).unwrap().permissions().readonly());
        remove_file_force(&f).unwrap();
        assert!(!f.exists());
        remove_file_force(&f).unwrap();
        fs::write(&f, b"y").unwrap();
        set_readonly(&f, true).unwrap();
        remove_tree(&d).unwrap();
        assert!(!d.exists());
        remove_tree(&d).unwrap();
    }

    #[test]
    fn walk_is_bounded_and_relative() {
        let d = temp("walk");
        for rel in ["a.big", "Data/INI/X.ini", "deep/1/2/3/4/f.txt", "skip/me.big"] {
            let p = d.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, rel.as_bytes()).unwrap();
        }
        let skip_dir = d.join("skip");
        let mut rels: Vec<String> = walk_files(&d, 3, 1000, &|p| p == skip_dir)
            .unwrap()
            .into_iter()
            .map(|f| f.rel)
            .collect();
        rels.sort();
        assert_eq!(rels, ["a.big", "data\\ini\\x.ini"]);
        let all = walk_files(&d, 16, 1000, &|_| false).unwrap();
        assert_eq!(all.len(), 4);
        assert!(all.iter().any(|f| f.name == "X.ini" && f.size == 14));
        assert!(walk_files(&d, 16, 2, &|_| false).unwrap().len() <= 2);
        remove_tree(&d).unwrap();
    }

    #[test]
    fn inside() {
        assert!(is_inside(Path::new("C:\\A\\b\\c"), Path::new("c:\\a")));
        assert!(is_inside(Path::new("C:\\A"), Path::new("c:\\a\\")));
        assert!(!is_inside(Path::new("C:\\AB"), Path::new("c:\\a")));
    }

    #[cfg(windows)]
    #[test]
    fn free_space_is_known() {
        let d = temp("free");
        assert!(free_space(&d.join("not").join("yet")).unwrap_or(0) > 0);
        remove_tree(&d).unwrap();
    }
}
