use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for Anthropic API key detection
/// Format: sk-ant-[101 characters of alphanumeric, underscore, or hyphen]
/// Total length: 108 characters (7 for "sk-ant-" + 101 for the key portion)
/// Examples:
/// - sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
static ANTHROPIC_TOKEN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bsk-ant-[a-zA-Z0-9_-]{101}\b").expect("Invalid regex pattern"));

/// Detects all Anthropic API keys in a string
///
/// # Arguments
/// * `secret` - The string to check for Anthropic API key patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_anthropic_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    // Use find_iter to find all matches
    for token_match in ANTHROPIC_TOKEN_PATTERN.find_iter(secret) {
        tokens.push((
            "Anthropic API Key".to_string(),
            token_match.as_str().to_string(),
        ));
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_anthropic_token() {
        // Valid Anthropic API key: sk-ant- (7 chars) + 101 chars = 108 total
        let valid_key = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY";
        assert_eq!(
            valid_key.len(),
            108,
            "Test key must be exactly 108 characters"
        );
        let result = detect_anthropic_tokens(valid_key);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "Anthropic API Key");
        assert_eq!(value, valid_key);
    }

    #[test]
    fn test_valid_anthropic_token_in_code() {
        // Token embedded in code
        let code = "ANTHROPIC_API_KEY = 'sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY'";
        let result = detect_anthropic_tokens(code);
        assert!(!result.is_empty());
        let (_, value) = result.first().unwrap();
        assert!(value.starts_with("sk-ant-"));
        assert_eq!(value.len(), 108);
    }

    #[test]
    fn test_valid_anthropic_token_in_json() {
        // Token in JSON
        let json = r#"{"api_key": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY"}"#;
        let result = detect_anthropic_tokens(json);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_multiple_anthropic_tokens() {
        // Multiple tokens in one string
        let multi = "key1=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY and key2=sk-ant-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJK";
        let results = detect_anthropic_tokens(multi);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "Anthropic API Key");
        assert_eq!(results[1].0, "Anthropic API Key");
    }

    #[test]
    fn test_invalid_anthropic_token_too_short() {
        // Missing characters (only 100 chars after sk-ant- instead of 101)
        let too_short = "sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLm";
        assert!(detect_anthropic_tokens(too_short).is_empty());
    }

    #[test]
    fn test_invalid_anthropic_token_too_long() {
        // Too many characters (102 chars after sk-ant- instead of 101)
        let too_long = "sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLmNo";
        assert!(detect_anthropic_tokens(too_long).is_empty());
    }

    #[test]
    fn test_invalid_anthropic_token_wrong_prefix() {
        // Wrong prefix
        let wrong_prefix = "sk-api-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLmN";
        assert!(detect_anthropic_tokens(wrong_prefix).is_empty());
    }

    #[test]
    fn test_invalid_anthropic_token_invalid_chars() {
        // Contains invalid characters (@ and !)
        let invalid_chars = "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ@123456789!-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-aBcDeFgHiJkLmN";
        assert!(detect_anthropic_tokens(invalid_chars).is_empty());
    }

    #[test]
    fn test_not_a_token() {
        assert!(detect_anthropic_tokens("not_a_token").is_empty());
        assert!(detect_anthropic_tokens("").is_empty());
        assert!(detect_anthropic_tokens("sk-ant-").is_empty());
    }
}
