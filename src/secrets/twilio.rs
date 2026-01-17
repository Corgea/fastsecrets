use once_cell::sync::Lazy;
use regex::Regex;

/// Regex patterns for Twilio API key detection
static TWILIO_KEY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\bAC[a-z0-9]{32}\b").expect("Invalid regex pattern"),
        Regex::new(r"\bSK[a-z0-9]{32}\b").expect("Invalid regex pattern"),
    ]
});

/// Detects all Twilio API keys in a string
///
/// # Arguments
/// * `secret` - The string to check for Twilio API key patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_twilio_keys(secret: &str) -> Vec<(String, String)> {
    let mut keys = Vec::new();

    for pattern in TWILIO_KEY_PATTERNS.iter() {
        for key_match in pattern.find_iter(secret) {
            keys.push(("Twilio API Key".to_string(), key_match.as_str().to_string()));
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_twilio_account_sid() {
        let key = format!("AC{}", "a".repeat(32));
        let result = detect_twilio_keys(&key);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "Twilio API Key");
        assert_eq!(value, &key);
    }

    #[test]
    fn test_valid_twilio_api_key_sid() {
        let key = format!("SK{}", "1".repeat(32));
        let result = detect_twilio_keys(&key);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, key);
    }

    #[test]
    fn test_valid_twilio_key_in_code() {
        let key = format!("AC{}", "b".repeat(32));
        let code = format!("TWILIO_KEY = '{key}'");
        let result = detect_twilio_keys(&code);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, key);
    }

    #[test]
    fn test_multiple_twilio_keys() {
        let key1 = format!("AC{}", "a".repeat(32));
        let key2 = format!("SK{}", "b".repeat(32));
        let content = format!("{key1} {key2}");
        let results = detect_twilio_keys(&content);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_invalid_twilio_key_prefix() {
        let key = format!("AX{}", "a".repeat(32));
        assert!(detect_twilio_keys(&key).is_empty());
    }

    #[test]
    fn test_invalid_twilio_key_length() {
        let key = format!("AC{}", "a".repeat(31));
        assert!(detect_twilio_keys(&key).is_empty());
    }

    #[test]
    fn test_invalid_twilio_key_characters() {
        let key = format!("AC{}", "A".repeat(32));
        assert!(detect_twilio_keys(&key).is_empty());
    }
}
