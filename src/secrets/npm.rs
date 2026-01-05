use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for NPM authToken detection
/// Matches npmrc authToken patterns like:
/// - //registry.npmjs.org/:_authToken=npm_xxxx
/// - //registry.npmjs.org/:_authToken=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (UUID format)
/// ref. https://stackoverflow.com/questions/53099434/using-auth-tokens-in-npmrc
static NPM_AUTH_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//[^\s]+/:_authToken=\s*((npm_[A-Za-z0-9]+)|([A-Fa-f0-9-]{36}))")
        .expect("Invalid regex pattern")
});

/// Detects all NPM auth tokens in a string
///
/// # Arguments
/// * `secret` - The string to check for NPM token patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_npm_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    for captures in NPM_AUTH_TOKEN_PATTERN.captures_iter(secret) {
        if let Some(token) = captures.get(1) {
            tokens.push(("NPM Token".to_string(), token.as_str().to_string()));
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_npm_token_npm_format() {
        // npm_xxx format token
        let result = detect_npm_tokens("//registry.npmjs.org/:_authToken=npm_abcdefg123456789");
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "NPM Token");
        assert_eq!(value, "npm_abcdefg123456789");
    }

    #[test]
    fn test_valid_npm_token_uuid_format() {
        // UUID format token (36 characters including hyphens)
        let result = detect_npm_tokens(
            "//registry.npmjs.org/:_authToken=12345678-1234-1234-1234-123456789abc",
        );
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "NPM Token");
        assert_eq!(value, "12345678-1234-1234-1234-123456789abc");
    }

    #[test]
    fn test_valid_npm_token_with_space_after_equals() {
        // With space after equals sign
        let result = detect_npm_tokens("//registry.npmjs.org/:_authToken= npm_token123");
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, "npm_token123");
    }

    #[test]
    fn test_valid_npm_token_custom_registry() {
        // Custom registry URL
        let result = detect_npm_tokens("//npm.mycompany.com/:_authToken=npm_customtoken123");
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, "npm_customtoken123");
    }

    #[test]
    fn test_valid_npm_token_in_npmrc_file() {
        // Full .npmrc line
        let npmrc_content = "@myorg:registry=https://npm.mycompany.com/\n//npm.mycompany.com/:_authToken=npm_abcd1234efgh5678";
        let result = detect_npm_tokens(npmrc_content);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, "npm_abcd1234efgh5678");
    }

    #[test]
    fn test_multiple_npm_tokens() {
        let content =
            "//registry.npmjs.org/:_authToken=npm_token1\n//npm.company.com/:_authToken=npm_token2";
        let results = detect_npm_tokens(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, "npm_token1");
        assert_eq!(results[1].1, "npm_token2");
    }

    #[test]
    fn test_invalid_npm_token() {
        // Missing the // prefix
        assert!(detect_npm_tokens("registry.npmjs.org/:_authToken=npm_token123").is_empty());

        // Missing :_authToken=
        assert!(detect_npm_tokens("//registry.npmjs.org/npm_token123").is_empty());

        // Token doesn't match expected formats
        assert!(detect_npm_tokens("//registry.npmjs.org/:_authToken=invalid").is_empty());

        // Not an NPM token at all
        assert!(detect_npm_tokens("not_a_token").is_empty());
        assert!(detect_npm_tokens("").is_empty());
    }

    #[test]
    fn test_uuid_format_must_be_36_chars() {
        // Too short UUID
        assert!(
            detect_npm_tokens("//registry.npmjs.org/:_authToken=12345678-1234-1234").is_empty()
        );

        // Valid 36 char UUID
        let result = detect_npm_tokens(
            "//registry.npmjs.org/:_authToken=ABCDEF01-2345-6789-ABCD-EF0123456789",
        );
        assert!(!result.is_empty());
    }
}
