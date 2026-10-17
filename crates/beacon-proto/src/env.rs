//! Environment contract between the launcher and the game hook (architecture §4.3).
//!
//! The launcher starts `lotrbfme.exe` with these variables; the hook reads them in
//! `DllMain` and stays a pure pass-through unless [`AGENT_PORT`] is set. The parse
//! helpers never allocate.
//!
//! | Variable | Format | Helpers |
//! |---|---|---|
//! | `BEACON_AGENT_PORT` | agent's loopback UDP port, decimal (arms the hook) | [`parse_agent_port`] |
//! | `BEACON_LOCAL_TOKEN` | u32, hex; must appear in every hook→agent frame | [`format_token`], [`parse_token`] |
//! | `BEACON_VIP` | the player's vIP, dotted quad | [`parse_vip`] |
//! | `BEACON_SERIAL` | 20 chars `[A-Z0-9]`, returned for the `ergc` registry read | [`is_valid_serial`]; derived by `fingerprint::beacon_serial` (feature `control`) |
//! | `BEACON_PATCHES` | optional comma list of in-memory patch ids | [`patch_ids`] |
//! | `BEACON_MULTI` | `1` = test mode (bypass single-instance guards) | [`is_enabled`] |
//! | `BEACON_USERDIR` | absolute user-data dir for this instance (test mode) | – |
//! | `BEACON_LOG` | optional log file path | – |

use std::net::Ipv4Addr;

/// Agent's loopback UDP port (decimal); its presence arms the hook.
pub const AGENT_PORT: &str = "BEACON_AGENT_PORT";
/// Local token (u32 hex) carried in every hook→agent frame.
pub const LOCAL_TOKEN: &str = "BEACON_LOCAL_TOKEN";
/// The player's virtual IPv4 (dotted quad).
pub const VIP: &str = "BEACON_VIP";
/// 20-character serial returned for the `ergc` registry value.
pub const SERIAL: &str = "BEACON_SERIAL";
/// Optional comma-separated list of in-memory patch ids.
pub const PATCHES: &str = "BEACON_PATCHES";
/// Test mode: `1` bypasses the single-instance and Miles mutexes.
pub const MULTI: &str = "BEACON_MULTI";
/// Test mode: absolute user-data base directory of this instance.
pub const USERDIR: &str = "BEACON_USERDIR";
/// Optional log file path.
pub const LOG: &str = "BEACON_LOG";

/// Length of [`SERIAL`].
pub const SERIAL_LEN: usize = 20;

/// Formats a local token for [`LOCAL_TOKEN`]: 8 lowercase hex digits, no prefix.
pub fn format_token(token: u32) -> String {
    format!("{token:08x}")
}

/// Parses a [`LOCAL_TOKEN`] value: 1–8 hex digits (either case), optional `0x`
/// prefix, surrounding whitespace ignored.
pub fn parse_token(s: &str) -> Option<u32> {
    let s = s.trim();
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// Parses [`AGENT_PORT`]: a decimal port `1..=65535` (whitespace ignored).
pub fn parse_agent_port(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&p| p != 0)
}

/// Parses [`VIP`]: a dotted quad that is an assignable player vIP
/// ([`crate::net::is_assignable`]).
pub fn parse_vip(s: &str) -> Option<Ipv4Addr> {
    s.trim()
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|&ip| crate::net::is_assignable(ip))
}

/// `true` if `s` is a well-formed [`SERIAL`]: exactly 20 characters `A-Z` / `0-9`.
pub fn is_valid_serial(s: &str) -> bool {
    s.len() == SERIAL_LEN && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// The patch ids of a [`PATCHES`] value: comma-separated, trimmed, empty entries
/// skipped.
pub fn patch_ids(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|id| !id.is_empty())
}

/// `true` if a flag variable such as [`MULTI`] is set to `1`.
pub fn is_enabled(value: &str) -> bool {
    value.trim() == "1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip() {
        for t in [0u32, 1, 0xdead_beef, u32::MAX, 0x0012_3456] {
            let s = format_token(t);
            assert_eq!(s.len(), 8);
            assert_eq!(parse_token(&s), Some(t));
        }
        assert_eq!(format_token(0x1234), "00001234");
    }

    #[test]
    fn token_parse_variants() {
        assert_eq!(parse_token("DEADBEEF"), Some(0xdead_beef));
        assert_eq!(parse_token("0xdeadbeef"), Some(0xdead_beef));
        assert_eq!(parse_token(" 0X1f \n"), Some(0x1f));
        assert_eq!(parse_token("7"), Some(7));
        for bad in ["", "0x", "123456789", "+1", "-1", "12g4", "0x+1", "１２", "0x0x1"] {
            assert_eq!(parse_token(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn agent_port() {
        assert_eq!(parse_agent_port("54321"), Some(54321));
        assert_eq!(parse_agent_port(" 1\r\n"), Some(1));
        assert_eq!(parse_agent_port("65535"), Some(65535));
        for bad in ["", "0", "65536", "-1", "+80", "80a", "0x50", "123456", "８０"] {
            assert_eq!(parse_agent_port(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn vip() {
        assert_eq!(parse_vip("198.18.0.2"), Some(Ipv4Addr::new(198, 18, 0, 2)));
        assert_eq!(parse_vip(" 198.18.0.254\n"), Some(Ipv4Addr::new(198, 18, 0, 254)));
        for bad in ["", "198.18.0.1", "198.18.0.255", "198.18.0.0", "10.88.0.2", "198.18.0", "x"] {
            assert_eq!(parse_vip(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn serial_and_flags() {
        assert!(is_valid_serial("ABCDEFGHIJ0123456789"));
        assert!(!is_valid_serial("ABCDEFGHIJ012345678"));
        assert!(!is_valid_serial("ABCDEFGHIJ0123456789X"));
        assert!(!is_valid_serial("abcdefghij0123456789"));
        assert!(!is_valid_serial("ABCDEFGHIJ012345678-"));
        assert!(!is_valid_serial("ÄBCDEFGHIJ012345678"));
        assert_eq!(patch_ids("031, 033,,042 ").collect::<Vec<_>>(), ["031", "033", "042"]);
        assert_eq!(patch_ids("").count(), 0);
        assert!(is_enabled("1") && is_enabled(" 1\n"));
        assert!(!is_enabled("0") && !is_enabled("") && !is_enabled("true"));
    }
}
