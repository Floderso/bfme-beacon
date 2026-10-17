//! Lowercase hex for the secrets stored in the config file (salt, PSK).

/// Encodes `bytes` as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Decodes exactly `N` bytes from `2 * N` hex digits (either case, surrounding
/// whitespace ignored). `None` for any other length or a non-hex digit.
pub fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.trim();
    if text.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (slot, &[hi, lo]) in out.iter_mut().zip(pairs) {
        let hi = char::from(hi).to_digit(16)?;
        let lo = char::from(lo).to_digit(16)?;
        *slot = u8::try_from((hi << 4) | lo).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = [0x00, 0x01, 0x7f, 0x80, 0xab, 0xff];
        let hex = encode(&bytes);
        assert_eq!(hex, "00017f80abff");
        assert_eq!(decode::<6>(&hex), Some(bytes));
        assert_eq!(decode::<6>(" 00017F80ABFF\n"), Some(bytes));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode::<2>("abc"), None);
        assert_eq!(decode::<2>("abcdef"), None);
        assert_eq!(decode::<2>("zz00"), None);
        assert_eq!(decode::<2>("+1ff"), None);
        assert_eq!(decode::<1>("é"), None);
        assert_eq!(decode::<0>(""), Some([]));
    }
}
