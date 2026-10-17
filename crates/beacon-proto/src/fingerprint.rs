//! Game-data fingerprint and `BEACON_SERIAL` (architecture §8). Feature `control`
//! (BLAKE3 is only a dependency of that feature; the hook only needs
//! [`crate::env::is_valid_serial`]).
//!
//! The launcher hashes every relevant file (the exe that will be launched, every
//! `.big` the engine mounts, loose `Data\` overrides) with BLAKE3, builds a
//! [`FileEntry`] per file, adds [`FileEntry::build_id`] for the Beacon build, and
//! [`combine`] turns the list into one digest that the lobby compares.
//!
//! [`combine`] is deterministic and independent of the input order:
//!
//! 1. every entry is normalised: path with [`normalize_path`], hash hex lowercased;
//! 2. entries are sorted by `(path, size, hash)`;
//! 3. the digest is BLAKE3 in key-derivation mode with context [`CONTEXT`] over
//!    `count` followed by, per entry, `len(path) ‖ path ‖ size ‖ len(hash) ‖ hash`,
//!    all integers u64 little-endian, strings as their UTF-8 bytes;
//! 4. the result is 64 lowercase hex digits.

use serde::{Deserialize, Serialize};

/// BLAKE3 key-derivation context of [`combine`]. Changing it changes every digest.
pub const CONTEXT: &str = "BFME Beacon 2026-10-17 game-data fingerprint v1";

/// Path of the pseudo entry made by [`FileEntry::build_id`]. `<` cannot occur in a
/// real Windows file name, so it never collides with a game file.
pub const BUILD_ID_PATH: &str = "<beacon-build>";

/// Prefix hashed in front of the player name by [`beacon_serial`].
pub const SERIAL_PREFIX: &str = "beacon-serial:";

/// One hashed file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the game directory (normalised: lowercase ASCII, `/`).
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// BLAKE3 of the file content, 64 lowercase hex digits.
    pub blake3_hex: String,
}

impl FileEntry {
    /// An entry with normalised path and lowercased hash.
    pub fn new(path: &str, size: u64, blake3_hex: &str) -> Self {
        Self {
            path: normalize_path(path),
            size,
            blake3_hex: blake3_hex.to_ascii_lowercase(),
        }
    }

    /// An entry for in-memory content (hashes `content`).
    pub fn from_content(path: &str, content: &[u8]) -> Self {
        let size = u64::try_from(content.len()).unwrap_or(u64::MAX);
        Self::new(path, size, &hash_hex(content))
    }

    /// The pseudo entry for the Beacon build id (architecture §8: the fingerprint
    /// includes it): path [`BUILD_ID_PATH`], size 0, hash = BLAKE3 of `build_id`.
    pub fn build_id(build_id: &str) -> Self {
        Self {
            path: BUILD_ID_PATH.to_owned(),
            size: 0,
            blake3_hex: hash_hex(build_id.as_bytes()),
        }
    }

    fn normalized(&self) -> Self {
        Self::new(&self.path, self.size, &self.blake3_hex)
    }
}

/// A complete fingerprint: the sorted, normalised entries and their digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// [`combine`] of `entries`, 64 lowercase hex digits.
    pub digest_hex: String,
    /// Normalised entries sorted by `(path, size, hash)`.
    pub entries: Vec<FileEntry>,
}

impl Fingerprint {
    /// Normalises and sorts `entries` and computes the digest.
    pub fn new(entries: Vec<FileEntry>) -> Self {
        let mut entries: Vec<FileEntry> = entries.iter().map(FileEntry::normalized).collect();
        entries.sort();
        let digest_hex = combine(&entries);
        Self {
            digest_hex,
            entries,
        }
    }

    /// The first 12 hex digits of the digest, for display.
    pub fn short(&self) -> &str {
        self.digest_hex.get(..12).unwrap_or(&self.digest_hex)
    }
}

/// The combined digest of `entries` (see the module documentation). The input order
/// and path spelling (case, `\` vs `/`) do not matter.
pub fn combine(entries: &[FileEntry]) -> String {
    let mut sorted: Vec<FileEntry> = entries.iter().map(FileEntry::normalized).collect();
    sorted.sort();
    let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
    hasher.update(&len_u64(sorted.len()).to_le_bytes());
    for e in &sorted {
        hasher.update(&len_u64(e.path.len()).to_le_bytes());
        hasher.update(e.path.as_bytes());
        hasher.update(&e.size.to_le_bytes());
        hasher.update(&len_u64(e.blake3_hex.len()).to_le_bytes());
        hasher.update(e.blake3_hex.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Normalises a relative path for fingerprinting: `\` → `/`, ASCII lowercase,
/// empty and `.` components removed (so leading `./` or `/` and doubled separators
/// vanish). Non-ASCII characters are kept as they are.
pub fn normalize_path(path: &str) -> String {
    path.split(['/', '\\'])
        .filter(|c| !c.is_empty() && *c != ".")
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("/")
}

/// BLAKE3 of `data` as 64 lowercase hex digits.
pub fn hash_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// `BEACON_SERIAL` for a player (architecture §8): the first 20 characters of the
/// RFC 4648 base32 encoding (alphabet `A-Z2-7`) of `BLAKE3("beacon-serial:" + name)`,
/// the name taken as its UTF-8 bytes without normalisation. Unique per name and
/// stable; always passes [`crate::env::is_valid_serial`].
pub fn beacon_serial(player_name: &str) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let len = crate::env::SERIAL_LEN;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SERIAL_PREFIX.as_bytes());
    hasher.update(player_name.as_bytes());
    let hash = hasher.finalize();

    let mut out = String::with_capacity(len);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in hash.as_bytes() {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 && out.len() < len {
            bits -= 5;
            if let Some(&c) = ALPHABET.get(((acc >> bits) & 0x1f) as usize) {
                out.push(char::from(c));
            }
        }
        if out.len() >= len {
            break;
        }
        acc &= (1 << bits) - 1;
    }
    out
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<FileEntry> {
        vec![
            FileEntry::from_content("lotrbfme.exe", b"exe"),
            FileEntry::from_content("INI.big", b"ini archive"),
            FileEntry::from_content("data\\ini\\weapon.ini", b"loose override"),
            FileEntry::from_content("wsock32.dll", b"hook"),
        ]
    }

    #[test]
    fn hash_hex_is_blake3() {
        // BLAKE3 of the empty input (official test vector).
        assert_eq!(
            hash_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn normalisation() {
        assert_eq!(normalize_path("Data\\INI\\Weapon.ini"), "data/ini/weapon.ini");
        assert_eq!(normalize_path("./a//b/"), "a/b");
        assert_eq!(normalize_path("/A.BIG"), "a.big");
        assert_eq!(normalize_path("Ä/B"), "Ä/b");
        let e = FileEntry::new("A\\B.big", 5, "ABCDEF");
        assert_eq!(e.path, "a/b.big");
        assert_eq!(e.blake3_hex, "abcdef");
    }

    #[test]
    fn combine_is_order_and_spelling_independent() {
        let a = sample();
        let mut b = a.clone();
        b.reverse();
        assert_eq!(combine(&a), combine(&b));
        let mut c = a.clone();
        c[2] = FileEntry {
            path: "DATA/ini/WEAPON.INI".into(),
            size: c[2].size,
            blake3_hex: c[2].blake3_hex.to_uppercase(),
        };
        assert_eq!(combine(&a), combine(&c));
        assert_eq!(Fingerprint::new(b).digest_hex, combine(&a));
    }

    #[test]
    fn combine_is_sensitive_to_every_field() {
        let base = combine(&sample());
        let mut v = sample();
        v[0].size += 1;
        assert_ne!(combine(&v), base);
        let mut v = sample();
        v[1].path.push('x');
        assert_ne!(combine(&v), base);
        let mut v = sample();
        v[3].blake3_hex = hash_hex(b"other hook");
        assert_ne!(combine(&v), base);
        let mut v = sample();
        v.pop();
        assert_ne!(combine(&v), base);
        let mut v = sample();
        v.push(v[0].clone());
        assert_ne!(combine(&v), base, "duplicates count");
        // Field boundaries are unambiguous.
        let x = [FileEntry::new("ab", 1, "c")];
        let y = [FileEntry::new("a", 1, "bc")];
        assert_ne!(combine(&x), combine(&y));
    }

    #[test]
    fn combine_golden() {
        // Frozen (cross-checked with blake3-py following the module docs): any change
        // here breaks compatibility between launcher versions.
        assert_eq!(
            combine(&[]),
            "bbf8bb82df7ab6b8f323a7cd6872f23db17b9a4cdb18dca9c8eca398ebf9914e"
        );
        assert_eq!(
            combine(&sample()),
            "fa8ae66c75eae0fb200caa8d1ccb830b555c6b6d748def450989c42bdf636344"
        );
    }

    #[test]
    fn fingerprint_struct() {
        let f = Fingerprint::new(sample());
        assert_eq!(f.entries.len(), 4);
        assert!(f.entries.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(f.entries[0].path, "data/ini/weapon.ini");
        assert_eq!(f.digest_hex.len(), 64);
        assert_eq!(f.short(), &f.digest_hex[..12]);
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<Fingerprint>(&json).unwrap(), f);
    }

    #[test]
    fn build_id_entry() {
        let e = FileEntry::build_id("0.1.0+abc");
        assert_eq!(e.path, BUILD_ID_PATH);
        assert_eq!(e.size, 0);
        // Cross-checked with blake3-py.
        assert_eq!(
            e.blake3_hex,
            "3d658918ccd4c429def9ffa2ec673d3217a0f4a3c407e5d7c7aa4661006790e8"
        );
        assert_eq!(e.normalized(), e);
        let mut with_build = sample();
        with_build.push(e);
        assert_ne!(combine(&with_build), combine(&sample()));
        let mut other_build = sample();
        other_build.push(FileEntry::build_id("0.1.1"));
        assert_ne!(combine(&with_build), combine(&other_build));
    }

    #[test]
    fn beacon_serial_golden() {
        // Cross-checked: base64.b32encode(blake3(b"beacon-serial:" + name))[:20].
        for (name, serial) in [
            ("Frodo", "C7WPNOD7VATDD6CPVLMV"),
            ("frodo", "W7OMWHQNHVVARRJELXMF"),
            ("", "COYIP5V5U5R4F5E3YQOH"),
            ("Sam Gamgee", "NIY366QYGOY5YNUF2KWY"),
            ("\u{c9}owyn", "SVCKKA6CRBNHNKZXFVWO"),
        ] {
            assert_eq!(beacon_serial(name), serial, "{name:?}");
            assert!(crate::env::is_valid_serial(serial));
        }
        for i in 0..500 {
            let s = beacon_serial(&format!("player{i}"));
            assert!(crate::env::is_valid_serial(&s), "{s}");
            assert!(s.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
        }
    }
}
