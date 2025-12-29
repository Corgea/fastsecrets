use regex::Regex;
use once_cell::sync::Lazy;

/// Regex pattern for OpenAI API token detection
/// Format: sk-[optional project name with alnum/-/_]*[20 alnum]T3BlbkFJ[20 alnum]
/// Examples:
/// - Legacy: sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkL
/// - Project-based: sk-proj-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkL
static OPENAI_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"sk-[A-Za-z0-9\-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}").expect("Invalid regex pattern")
});

/// Detects if a string is an OpenAI API token
///
/// OpenAI tokens have two formats:
/// 1. Legacy user API keys: sk-[20 alnum]T3BlbkFJ[20 alnum]
/// 2. Project-based API keys: sk-[project-name]-[20 alnum]T3BlbkFJ[20 alnum]
///
/// # Arguments
/// * `secret` - The string to check for OpenAI token pattern
///
/// # Returns
/// * `Option<(String, String)>` - None if no match, Some((secret_type, value)) if match found
pub fn detect_openai_token(secret: &str) -> Option<(String, String)> {
    if let Some(token_match) = OPENAI_TOKEN_PATTERN.find(secret) {
        Some((
            "OpenAI Token".to_string(),
            token_match.as_str().to_string(),
        ))
    } else {
        None
    }
}

/// Detects all OpenAI API tokens in a string
///
/// # Arguments
/// * `secret` - The string to check for OpenAI token patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_openai_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    // Use find_iter to find all matches
    for token_match in OPENAI_TOKEN_PATTERN.find_iter(secret) {
        tokens.push((
            "OpenAI Token".to_string(),
            token_match.as_str().to_string(),
        ));
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_openai_token_legacy() {
        // Legacy format: sk-[20 alnum]T3BlbkFJ[20 alnum] (total 51 chars)
        let result = detect_openai_token("sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "OpenAI Token");
        assert_eq!(value, "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");
    }

    #[test]
    fn test_valid_openai_token_project_based() {
        // Project-based format: sk-proj-[20 alnum]T3BlbkFJ[20 alnum]
        let result = detect_openai_token("sk-proj-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "OpenAI Token");
        assert_eq!(value, "sk-proj-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");

        // With underscores
        let result = detect_openai_token("sk-my_project-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "sk-my_project-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");
    }

    #[test]
    fn test_valid_openai_token_in_code() {
        // Token embedded in code
        let result = detect_openai_token("openai.api_key = 'sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN'");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN");
    }

    #[test]
    fn test_invalid_openai_token() {
        // Missing T3BlbkFJ
        assert!(detect_openai_token("sk-aBcDeFgHiJkLmNoPqRsTabcdefghiJkLmNoPqRsT").is_none());

        // Wrong prefix
        assert!(detect_openai_token("pk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkL").is_none());

        // Too short after T3BlbkFJ
        assert!(detect_openai_token("sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZ").is_none());

        // Not a token at all
        assert!(detect_openai_token("not_a_token").is_none());
        assert!(detect_openai_token("").is_none());
    }
}
