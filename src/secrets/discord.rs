use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for Discord bot token detection
/// Format: [M|N|O] + 23-25 chars + '.' + 6 chars + '.' + 27 chars
static DISCORD_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}")
        .expect("Invalid regex pattern")
});

/// Detects all Discord bot tokens in a string
///
/// # Arguments
/// * `secret` - The string to check for Discord bot token patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_discord_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    for token_match in DISCORD_TOKEN_PATTERN.find_iter(secret) {
        tokens.push((
            "Discord Bot Token".to_string(),
            token_match.as_str().to_string(),
        ));
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_discord_token() {
        let token = format!("M{}.{}.{}", "a".repeat(23), "b".repeat(6), "c".repeat(27));
        let result = detect_discord_tokens(&token);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "Discord Bot Token");
        assert_eq!(value, &token);
    }

    #[test]
    fn test_valid_discord_token_in_code() {
        let token = format!("N{}.{}.{}", "a".repeat(25), "b".repeat(6), "c".repeat(27));
        let code = format!("DISCORD_TOKEN = '{token}'");
        let result = detect_discord_tokens(&code);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_multiple_discord_tokens() {
        let token1 = format!("M{}.{}.{}", "a".repeat(23), "b".repeat(6), "c".repeat(27));
        let token2 = format!("O{}.{}.{}", "d".repeat(24), "e".repeat(6), "f".repeat(27));
        let content = format!("{token1} and {token2}");
        let results = detect_discord_tokens(&content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "Discord Bot Token");
        assert_eq!(results[1].0, "Discord Bot Token");
    }

    #[test]
    fn test_invalid_discord_token_prefix() {
        let token = format!("A{}.{}.{}", "a".repeat(23), "b".repeat(6), "c".repeat(27));
        assert!(detect_discord_tokens(&token).is_empty());
    }

    #[test]
    fn test_invalid_discord_token_segment_length() {
        let token = format!("M{}.{}.{}", "a".repeat(23), "b".repeat(5), "c".repeat(27));
        assert!(detect_discord_tokens(&token).is_empty());
    }
}
