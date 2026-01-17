use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for Stripe access key detection
/// Matches standard (sk_live) and restricted (rk_live) keys
static STRIPE_KEY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:r|s)k_live_[0-9a-zA-Z]{24}").expect("Invalid regex pattern"));

/// Detects all Stripe access keys in a string
///
/// # Arguments
/// * `secret` - The string to check for Stripe access key patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_stripe_keys(secret: &str) -> Vec<(String, String)> {
    let mut keys = Vec::new();

    for key_match in STRIPE_KEY_PATTERN.find_iter(secret) {
        keys.push((
            "Stripe Access Key".to_string(),
            key_match.as_str().to_string(),
        ));
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_stripe_secret_key() {
        let key = "sk_live_1234567890abcdefghijklmn";
        let result = detect_stripe_keys(key);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "Stripe Access Key");
        assert_eq!(value, key);
    }

    #[test]
    fn test_valid_stripe_restricted_key() {
        let key = "rk_live_1234567890abcdefghijklmn";
        let result = detect_stripe_keys(key);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, key);
    }

    #[test]
    fn test_valid_stripe_key_in_code() {
        let key = "sk_live_1234567890abcdefghijklmn";
        let code = format!("STRIPE_KEY = '{key}'");
        let result = detect_stripe_keys(&code);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_multiple_stripe_keys() {
        let key1 = "sk_live_1234567890abcdefghijklmn";
        let key2 = "rk_live_1234567890abcdefghijklmn";
        let content = format!("{key1} {key2}");
        let results = detect_stripe_keys(&content);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_invalid_stripe_key_prefix() {
        let key = "sk_test_1234567890abcdefghijklmn";
        assert!(detect_stripe_keys(key).is_empty());
    }

    #[test]
    fn test_invalid_stripe_key_length() {
        let key = "sk_live_1234567890abcdefghijk";
        assert!(detect_stripe_keys(key).is_empty());
    }
}
