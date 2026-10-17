//! BFME's LAN player name: `Network.ini` key `UserName` (spec 04 §4.3, §4.5).
//!
//! The value is "quoted-printable Unicode": the UTF-16LE bytes of the name, each
//! byte written as itself if it is an ASCII letter/digit, else as `_` + two
//! uppercase hex digits (`Floderso` → `F_00l_00o_00d_00e_00r_00s_00o_00`,
//! `Sölron` → `S_00_F6_00l_00r_00o_00n_00`, as written by the game).
//!
//! Editing keeps the file's bytes, line endings and every other line; only the
//! value of `UserName` lines changes (or one line is appended). The original value is
//! backed up once per file in `name-backup.json` and can be restored.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util;

/// File name of BFME's LAN preferences.
pub const NETWORK_INI: &str = "Network.ini";
/// The key of the LAN name.
pub const USER_NAME_KEY: &str = "UserName";
/// Largest preference file handled.
const MAX_INI_LEN: u64 = 1 << 20;
const MAGIC: u8 = b'_';

/// Encodes a name like `UnicodeStringToQuotedPrintable`.
pub fn encode_user_name(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(name.len() * 6);
    for unit in name.encode_utf16() {
        for b in unit.to_le_bytes() {
            if b.is_ascii_alphanumeric() {
                out.push(char::from(b));
            } else {
                out.push(char::from(MAGIC));
                for nibble in [b >> 4, b & 0x0f] {
                    if let Some(&h) = HEX.get(usize::from(nibble)) {
                        out.push(char::from(h));
                    }
                }
            }
        }
    }
    out
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Decodes a `UserName` value like `QuotedPrintableToUnicodeString` (lenient:
/// invalid hex digits count as 0, an odd trailing byte is padded).
pub fn decode_user_name(raw: &str) -> String {
    let src = raw.as_bytes();
    let mut bytes = Vec::with_capacity(src.len());
    let mut i = 0;
    while let Some(&c) = src.get(i) {
        if c == MAGIC {
            match (src.get(i + 1), src.get(i + 2)) {
                (Some(&h), Some(&l)) => {
                    bytes.push((hex_val(h) << 4) | hex_val(l));
                    i += 3;
                }
                _ => {
                    bytes.push(MAGIC);
                    break;
                }
            }
        } else {
            bytes.push(c);
            i += 1;
        }
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|p| u16::from_le_bytes([p.first().copied().unwrap_or(0), p.get(1).copied().unwrap_or(0)]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    b.trim_ascii()
}

/// Splits into lines keeping each line's terminator (`\n` or `\r\n`).
fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split_inclusive(|&b| b == b'\n')
}

/// The key of a line (`None` for lines the game skips: no `=`, empty key).
fn line_key(line: &[u8]) -> Option<&[u8]> {
    let eq = line.iter().position(|&b| b == b'=')?;
    let key = trim_ascii(line.get(..eq)?);
    (!key.is_empty()).then_some(key)
}

/// The value of `key` as the game reads it (last occurrence wins; empty values are
/// skipped like the game does).
pub fn find_value(text: &[u8], key: &str) -> Option<String> {
    let mut found = None;
    for line in lines(text) {
        if line_key(line) == Some(key.as_bytes()) {
            let eq = line.iter().position(|&b| b == b'=').unwrap_or(line.len());
            let value = trim_ascii(line.get(eq + 1..).unwrap_or_default());
            if !value.is_empty() {
                found = Some(String::from_utf8_lossy(value).into_owned());
            }
        }
    }
    found
}

fn uses_crlf(text: &[u8]) -> bool {
    text.is_empty() || text.windows(2).any(|w| w == b"\r\n")
}

/// Sets `key` (all occurrences) to `value`, or appends `key = value`; `None`
/// removes the key's lines. Everything else stays byte-identical.
pub fn set_value(text: &[u8], key: &str, value: Option<&str>) -> Vec<u8> {
    let eol: &[u8] = if uses_crlf(text) { b"\r\n" } else { b"\n" };
    let mut out = Vec::with_capacity(text.len() + 64);
    let mut replaced = false;
    for line in lines(text) {
        if line_key(line) != Some(key.as_bytes()) {
            out.extend_from_slice(line);
            continue;
        }
        replaced = true;
        let Some(value) = value else { continue };
        let ending: &[u8] = if line.ends_with(b"\r\n") {
            b"\r\n"
        } else if line.ends_with(b"\n") {
            b"\n"
        } else {
            b""
        };
        out.extend_from_slice(format!("{key} = {value}").as_bytes());
        out.extend_from_slice(ending);
    }
    if let (false, Some(value)) = (replaced, value) {
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.extend_from_slice(eol);
        }
        out.extend_from_slice(format!("{key} = {value}").as_bytes());
        out.extend_from_slice(eol);
    }
    out
}

/// One backed-up original value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEntry {
    /// The raw (encoded) original value; `None` if the key was absent.
    pub original: Option<String>,
    /// When it was saved (ms since the Unix epoch).
    pub saved_at_ms: u64,
}

/// `name-backup.json`: original values per Network.ini path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameBackup {
    /// Keyed by the Network.ini path.
    pub files: BTreeMap<String, BackupEntry>,
}

impl NameBackup {
    fn load(path: &Path) -> io::Result<Self> {
        match util::read_bounded(path, MAX_INI_LEN) {
            Ok(text) => serde_json::from_slice(&text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        util::write_atomic(path, &json)
    }
}

/// What [`sync_user_name`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameSync {
    /// The file was changed.
    pub changed: bool,
    /// The original value was backed up now (first change of this file).
    pub backed_up: bool,
    /// The name BFME had before (decoded), if any.
    pub previous: Option<String>,
}

/// Errors of the name synchronisation.
#[derive(Debug)]
pub enum NameSyncError {
    /// Reading or writing `path` failed.
    Io(PathBuf, io::Error),
}

impl fmt::Display for NameSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for NameSyncError {}

fn read_ini(path: &Path) -> Result<Vec<u8>, NameSyncError> {
    match util::read_bounded(path, MAX_INI_LEN) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(NameSyncError::Io(path.to_path_buf(), e)),
    }
}

fn backup_key(netini: &Path) -> String {
    netini.to_string_lossy().to_lowercase()
}

/// Sets `UserName` in `netini` to `name`; backs up the original value once in
/// `backup_file` (before the first change).
pub fn sync_user_name(netini: &Path, name: &str, backup_file: &Path) -> Result<NameSync, NameSyncError> {
    let text = read_ini(netini)?;
    let current = find_value(&text, USER_NAME_KEY);
    let desired = encode_user_name(name);
    let previous = current.as_deref().map(decode_user_name);
    if current.as_deref() == Some(desired.as_str()) {
        return Ok(NameSync {
            changed: false,
            backed_up: false,
            previous,
        });
    }
    let io_err = |p: &Path| {
        let p = p.to_path_buf();
        move |e| NameSyncError::Io(p, e)
    };
    let mut backup = NameBackup::load(backup_file).map_err(io_err(backup_file))?;
    let key = backup_key(netini);
    let backed_up = !backup.files.contains_key(&key);
    if backed_up {
        backup.files.insert(
            key,
            BackupEntry {
                original: current,
                saved_at_ms: util::unix_ms(),
            },
        );
        backup.save(backup_file).map_err(io_err(backup_file))?;
    }
    let updated = set_value(&text, USER_NAME_KEY, Some(&desired));
    util::write_atomic(netini, &updated).map_err(io_err(netini))?;
    Ok(NameSync {
        changed: true,
        backed_up,
        previous,
    })
}

/// Restores the backed-up `UserName` of `netini`; `Ok(false)` if there is no
/// backup for this file.
pub fn restore_user_name(netini: &Path, backup_file: &Path) -> Result<bool, NameSyncError> {
    let io_err = |p: &Path| {
        let p = p.to_path_buf();
        move |e| NameSyncError::Io(p, e)
    };
    let mut backup = NameBackup::load(backup_file).map_err(io_err(backup_file))?;
    let Some(entry) = backup.files.remove(&backup_key(netini)) else {
        return Ok(false);
    };
    let text = read_ini(netini)?;
    if !text.is_empty() || entry.original.is_some() {
        let restored = set_value(&text, USER_NAME_KEY, entry.original.as_deref());
        util::write_atomic(netini, &restored).map_err(io_err(netini))?;
    }
    backup.save(backup_file).map_err(io_err(backup_file))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &[u8] = b"Color = 6\r\nMap = maps_5Cmap_20mp_20brown_20lands_5Cmap_20mp_20brownlands_2Emap\r\nNumRemoteIPs = \r\nPlayerTemplate = 6\r\nStartingSupplies = \r\nUserName = F_00l_00o_00d_00e_00r_00s_00o_00\r\n";

    #[test]
    fn encoding_matches_the_game() {
        assert_eq!(encode_user_name("Floderso"), "F_00l_00o_00d_00e_00r_00s_00o_00");
        assert_eq!(encode_user_name("Sölron"), "S_00_F6_00l_00r_00o_00n_00");
        assert_eq!(encode_user_name("a b"), "a_00_20_00b_00");
        assert_eq!(encode_user_name(""), "");
        for name in ["Floderso", "Sölron", "a b!", "Ωμέγα", "x_y", "🙂"] {
            assert_eq!(decode_user_name(&encode_user_name(name)), name);
        }
        // The Generals-style variant without the last high byte also decodes.
        assert_eq!(decode_user_name("B_00o_00b"), "Bob");
        assert_eq!(decode_user_name("ab_"), "\u{6261}_");
        assert_eq!(decode_user_name("_zz_00"), "");
    }

    #[test]
    fn edits_keep_everything_else() {
        assert_eq!(find_value(REAL, "UserName").as_deref(), Some("F_00l_00o_00d_00e_00r_00s_00o_00"));
        assert_eq!(find_value(REAL, "NumRemoteIPs"), None, "empty values are skipped");
        let out = set_value(REAL, "UserName", Some(&encode_user_name("Bob")));
        let expected = String::from_utf8(REAL.to_vec())
            .unwrap()
            .replace("F_00l_00o_00d_00e_00r_00s_00o_00", "B_00o_00b_00");
        assert_eq!(String::from_utf8(out.clone()).unwrap(), expected);
        // Appended with the file's line ending when missing.
        let no_name = b"Color = 6\r\nMap = x";
        assert_eq!(set_value(no_name, "UserName", Some("v")), b"Color = 6\r\nMap = x\r\nUserName = v\r\n");
        assert_eq!(set_value(b"A = 1\n", "UserName", Some("v")), b"A = 1\nUserName = v\n");
        assert_eq!(set_value(b"", "UserName", Some("v")), b"UserName = v\r\n");
        // Every occurrence changes (the game keeps the last one), odd spacing too.
        let twice = b"UserName=a\n  UserName  =  b  \nX = 1\n";
        assert_eq!(set_value(twice, "UserName", Some("c")), b"UserName = c\nUserName = c\nX = 1\n");
        // Removal; keys are case-sensitive like the game's map.
        assert_eq!(set_value(twice, "UserName", None), b"X = 1\n");
        assert_eq!(set_value(b"username = a\n", "UserName", None), b"username = a\n");
        // Non-UTF-8 bytes elsewhere survive.
        let odd = b"K = \xff\xfe\r\nUserName = a\r\n";
        assert_eq!(set_value(odd, "UserName", Some("b")), b"K = \xff\xfe\r\nUserName = b\r\n");
    }

    #[test]
    fn sync_backup_and_restore() {
        let dir = std::env::temp_dir().join(format!("beacon-netini-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join(NETWORK_INI);
        let backup = dir.join("name-backup.json");
        std::fs::write(&ini, REAL).unwrap();
        let r = sync_user_name(&ini, "Gandalf", &backup).unwrap();
        assert_eq!(
            r,
            NameSync { changed: true, backed_up: true, previous: Some("Floderso".into()) }
        );
        assert_eq!(decode_user_name(&find_value(&std::fs::read(&ini).unwrap(), "UserName").unwrap()), "Gandalf");
        let r = sync_user_name(&ini, "Gandalf", &backup).unwrap();
        assert!(!r.changed);
        // A second change keeps the first backup (the user's own name).
        let r = sync_user_name(&ini, "Saruman", &backup).unwrap();
        assert!(r.changed && !r.backed_up);
        assert!(restore_user_name(&ini, &backup).unwrap());
        assert_eq!(std::fs::read(&ini).unwrap(), REAL);
        assert!(!restore_user_name(&ini, &backup).unwrap());
        // A missing file is created and restoring removes the key again.
        let fresh = dir.join("sub").join(NETWORK_INI);
        sync_user_name(&fresh, "Frodo", &backup).unwrap();
        assert_eq!(std::fs::read(&fresh).unwrap(), b"UserName = F_00r_00o_00d_00o_00\r\n");
        assert!(restore_user_name(&fresh, &backup).unwrap());
        assert_eq!(std::fs::read(&fresh).unwrap(), b"");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
