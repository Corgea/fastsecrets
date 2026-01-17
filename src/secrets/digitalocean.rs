use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for DigitalOcean API key detection
static DIGITALOCEAN_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b").expect("Invalid regex pattern")
});

/// Detects all DigitalOcean API keys in a string
///
/// # Arguments
/// * `secret` - The string to check for DigitalOcean key patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_digitalocean_keys(secret: &str) -> Vec<(String, String)> {
    let mut keys = Vec::new();

    for key_match in DIGITALOCEAN_KEY_PATTERN.find_iter(secret) {
        keys.push((
            "DigitalOcean API Key".to_string(),
            key_match.as_str().to_string(),
        ));
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_key(prefix: &str) -> String {
        format!("{prefix}_v1_{}", "a".repeat(64))
    }

    #[test]
    fn test_valid_digitalocean_key() {
        let key = build_key("dop");
        let result = detect_digitalocean_keys(&key);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "DigitalOcean API Key");
        assert_eq!(value, &key);
    }

    #[test]
    fn test_valid_digitalocean_key_in_code() {
        let key = build_key("doo");
        let code = format!("DO_KEY = '{key}'");
        let result = detect_digitalocean_keys(&code);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, key);
    }

    #[test]
    fn test_multiple_digitalocean_keys() {
        let key1 = build_key("dop");
        let key2 = build_key("dor");
        let content = format!("{key1} {key2}");
        let results = detect_digitalocean_keys(&content);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_invalid_digitalocean_key_prefix() {
        let key = build_key("don");
        assert!(detect_digitalocean_keys(&key).is_empty());
    }

    #[test]
    fn test_invalid_digitalocean_key_length() {
        let key = format!("dop_v1_{}", "a".repeat(63));
        assert!(detect_digitalocean_keys(&key).is_empty());
    }

    #[test]
    fn test_invalid_digitalocean_key_characters() {
        let key = format!("dop_v1_{}", "A".repeat(64));
        assert!(detect_digitalocean_keys(&key).is_empty());
    }
}
