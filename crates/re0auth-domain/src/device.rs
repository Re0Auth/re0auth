//! RFC 8628 user-code helpers.

use re0auth_api::{Random, Unix};

pub const USER_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn normalize_user_code(raw: &str) -> String {
    raw.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

pub fn format_user_code(raw: &str) -> String {
    let normalized = normalize_user_code(raw);
    if normalized.len() == 8 {
        format!("{}-{}", &normalized[..4], &normalized[4..])
    } else {
        normalized
    }
}

pub fn generate_user_code(random: &dyn Random) -> String {
    let bytes = random.bytes(8);
    let raw: String = bytes
        .iter()
        .map(|byte| USER_CODE_ALPHABET[(byte & 31) as usize] as char)
        .collect();
    format_user_code(&raw)
}

pub fn device_code_ttl(_now: Unix) -> Unix {
    10 * 60
}

pub fn device_poll_interval() -> u32 {
    5
}

pub fn device_attempt_window() -> Unix {
    15 * 60
}

pub fn device_attempt_limit() -> usize {
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_normalize_and_format() {
        assert_eq!(normalize_user_code(" abcd-efgh "), "ABCDEFGH");
        assert_eq!(format_user_code("abcdefgh"), "ABCD-EFGH");
        assert_eq!(format_user_code("abc"), "ABC");
    }

    #[test]
    fn generated_user_codes_are_eight_chars() {
        struct Fixed;
        impl Random for Fixed {
            fn bytes(&self, len: usize) -> Vec<u8> {
                vec![0; len]
            }
        }
        assert_eq!(generate_user_code(&Fixed), "AAAA-AAAA");
    }
}
