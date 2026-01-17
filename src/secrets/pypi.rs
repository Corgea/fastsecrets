use once_cell::sync::Lazy;
use regex::Regex;

/// Regex patterns for PyPI token detection
/// Matches both pypi.org and test.pypi.org token formats
static PYPI_TOKEN_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}").expect("Invalid regex pattern"),
        Regex::new(r"pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9-_]{70,}")
            .expect("Invalid regex pattern"),
    ]
});

/// Detects all PyPI tokens in a string
///
/// # Arguments
/// * `secret` - The string to check for PyPI token patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_pypi_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    for pattern in PYPI_TOKEN_PATTERNS.iter() {
        for token_match in pattern.find_iter(secret) {
            tokens.push(("PyPI Token".to_string(), token_match.as_str().to_string()));
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_token(prefix: &str) -> String {
        format!("{prefix}{}", "a".repeat(70))
    }

    #[test]
    fn test_valid_pypi_token() {
        let token = build_token("pypi-AgEIcHlwaS5vcmc");
        let result = detect_pypi_tokens(&token);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "PyPI Token");
        assert_eq!(value, &token);
    }

    #[test]
    fn test_valid_test_pypi_token() {
        let token = build_token("pypi-AgENdGVzdC5weXBpLm9yZw");
        let result = detect_pypi_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_pypi_token_in_code() {
        let token = build_token("pypi-AgEIcHlwaS5vcmc");
        let code = format!("PYPI_TOKEN = '{token}'");
        let result = detect_pypi_tokens(&code);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_multiple_pypi_tokens() {
        let token1 = build_token("pypi-AgEIcHlwaS5vcmc");
        let token2 = build_token("pypi-AgENdGVzdC5weXBpLm9yZw");
        let content = format!("{token1} {token2}");
        let results = detect_pypi_tokens(&content);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_invalid_pypi_token_prefix() {
        let token = build_token("pypi-AgEIcHlwaS5vcmz");
        assert!(detect_pypi_tokens(&token).is_empty());
    }

    #[test]
    fn test_invalid_pypi_token_too_short() {
        let token = format!("pypi-AgEIcHlwaS5vcmc{}", "a".repeat(69));
        assert!(detect_pypi_tokens(&token).is_empty());
    }
}
