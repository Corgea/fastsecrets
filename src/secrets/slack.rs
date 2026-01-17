use once_cell::sync::Lazy;
use regex::Regex;

/// Regex patterns for Slack token and webhook detection
static SLACK_TOKEN_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+").expect("Invalid regex pattern"),
        Regex::new(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        )
        .expect("Invalid regex pattern"),
    ]
});

/// Detects all Slack tokens and webhooks in a string
///
/// # Arguments
/// * `secret` - The string to check for Slack token patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_slack_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    for pattern in SLACK_TOKEN_PATTERNS.iter() {
        for token_match in pattern.find_iter(secret) {
            tokens.push(("Slack Token".to_string(), token_match.as_str().to_string()));
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_slack_token() {
        let token = "xoxb-1234567890-123456789012-abcdef123456";
        let result = detect_slack_tokens(token);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "Slack Token");
        assert_eq!(value, token);
    }

    #[test]
    fn test_valid_slack_token_in_code() {
        let token = "xoxa-1234567890-123456789012-abcdef123456";
        let code = format!("SLACK_TOKEN = '{token}'");
        let result = detect_slack_tokens(&code);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_slack_webhook() {
        let webhook = "https://hooks.slack.com/services/TABCDE123/BABCDE123/abcdef123456";
        let result = detect_slack_tokens(webhook);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, webhook);
    }

    #[test]
    fn test_multiple_slack_tokens() {
        let token1 = "xoxb-1234567890-123456789012-abcdef123456";
        let token2 = "https://hooks.slack.com/services/T123/B456/abcdef";
        let content = format!("{token1} {token2}");
        let results = detect_slack_tokens(&content);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_invalid_slack_token_prefix() {
        let token = "xoxc-1234567890-123456789012-abcdef123456";
        assert!(detect_slack_tokens(token).is_empty());
    }
}
