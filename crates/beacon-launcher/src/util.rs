//! Small helpers: time stamps, atomic file replacement, bounded reads, wiping
//! secrets.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch (0 before 1970).
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Civil UTC date and time `(year, month, day, hour, minute, second)` of a Unix
/// time in seconds (Howard Hinnant's `civil_from_days`).
pub fn civil_utc(unix_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = i64::try_from(unix_secs / 86_400).unwrap_or(0);
    let secs = unix_secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let to_u32 = |v: i64| u32::try_from(v).unwrap_or(0);
    let secs = u32::try_from(secs).unwrap_or(0);
    (year, to_u32(month), to_u32(day), secs / 3600, (secs / 60) % 60, secs % 60)
}

/// A file-name friendly UTC time stamp, e.g. `20261017T153012Z`.
pub fn utc_stamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_utc(secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// Reads a whole file of at most `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is too large ({len} > {max} bytes)", path.display()),
        ));
    }
    let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(max.saturating_add(1)).read_to_end(&mut data)?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file grew while reading"));
    }
    Ok(data)
}

/// A unique temporary path next to `target` (same directory, so a rename is atomic).
pub fn temp_sibling(target: &Path, tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    let n = N.fetch_add(1, Ordering::Relaxed);
    target.with_file_name(format!(".{name}.{tag}-{}-{n}", std::process::id()))
}

/// Writes `data` to a temporary sibling, flushes it to disk and renames it over
/// `path` (atomic replacement on the same volume). The temporary file is removed
/// on failure.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let tmp = temp_sibling(path, "tmp");
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Overwrites a buffer with zeros in a way the optimiser keeps (best effort for
/// secrets that are about to be dropped).
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(&*buf);
}

/// Wipes a string's bytes and empties it.
pub fn wipe_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    wipe(&mut bytes);
}

/// A random `u32` (local token); falls back to time-derived bits if the OS RNG
/// fails, which only weakens a loopback-only token.
pub fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_ok() {
        u32::from_le_bytes(b)
    } else {
        let t = unix_ms();
        (t as u32) ^ ((t >> 32) as u32) ^ std::process::id().rotate_left(16)
    }
}

/// 32 random bytes as hex (handover token).
pub fn random_hex_token() -> io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(crate::sys::hex(&b))
}

/// Constant-time comparison of two byte strings of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_utc(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_utc(951_782_400), (2000, 2, 29, 0, 0, 0));
        // 2026-10-17T15:30:12Z
        assert_eq!(civil_utc(1_792_251_012), (2026, 10, 17, 15, 30, 12));
        assert_eq!(
            utc_stamp(UNIX_EPOCH + Duration::from_secs(1_792_251_012)),
            "20261017T153012Z"
        );
    }

    #[test]
    fn atomic_write_and_bounded_read() {
        let dir = std::env::temp_dir().join(format!("beacon-util-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let p = dir.join("sub").join("f.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two!").unwrap();
        assert_eq!(read_bounded(&p, 4).unwrap(), b"two!");
        assert!(read_bounded(&p, 3).is_err());
        let leftovers: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(leftovers.len(), 1, "no temporary files left behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wiping_and_comparison() {
        let mut s = String::from("secret");
        wipe_string(&mut s);
        assert!(s.is_empty());
        let mut b = [1u8; 4];
        wipe(&mut b);
        assert_eq!(b, [0; 4]);
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert_ne!(random_hex_token().unwrap(), random_hex_token().unwrap());
    }
}
