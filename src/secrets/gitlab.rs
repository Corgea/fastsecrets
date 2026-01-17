use once_cell::sync::Lazy;
use regex::Regex;

/// Regex patterns for GitLab token detection
static GITLAB_TOKEN_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?:^|[^A-Za-z0-9_])((glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50})")
            .expect("Invalid regex pattern"),
        Regex::new(r"(?:^|[^A-Za-z0-9_])(GR1348941[A-Za-z0-9_\-]{20,50})")
            .expect("Invalid regex pattern"),
        Regex::new(r"(?:^|[^A-Za-z0-9_])(glcbt-([0-9a-fA-F]{2}_)?[A-Za-z0-9_\-]{20,50})")
            .expect("Invalid regex pattern"),
        Regex::new(r"(?:^|[^A-Za-z0-9_])(glimt-[A-Za-z0-9_\-]{25})")
            .expect("Invalid regex pattern"),
        Regex::new(r"(?:^|[^A-Za-z0-9_])(glptt-[A-Za-z0-9_\-]{40})")
            .expect("Invalid regex pattern"),
        Regex::new(r"(?:^|[^A-Za-z0-9_])(glagent-[A-Za-z0-9_\-]{50,1024})")
            .expect("Invalid regex pattern"),
        Regex::new(r"(?:^|[^A-Za-z0-9_])(gloas-[A-Za-z0-9_\-]{64})")
            .expect("Invalid regex pattern"),
    ]
});

/// Detects all GitLab tokens in a string
///
/// # Arguments
/// * `secret` - The string to check for GitLab token patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_gitlab_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    for pattern in GITLAB_TOKEN_PATTERNS.iter() {
        for token_match in pattern.captures_iter(secret) {
            if let Some(token) = token_match.get(1) {
                tokens.push(("GitLab Token".to_string(), token.as_str().to_string()));
            }
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_gitlab_personal_access_token() {
        let token = format!("glpat-{}", "a".repeat(20));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "GitLab Token");
        assert_eq!(value, &token);
    }

    #[test]
    fn test_valid_gitlab_runner_registration_token() {
        let token = format!("GR1348941{}", "b".repeat(20));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_gitlab_cicd_token_partitioned() {
        let token = format!("glcbt-1f_{}", "c".repeat(20));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_gitlab_incoming_mail_token() {
        let token = format!("glimt-{}", "d".repeat(25));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_gitlab_trigger_token() {
        let token = format!("glptt-{}", "e".repeat(40));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_gitlab_agent_token() {
        let token = format!("glagent-{}", "f".repeat(50));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_gitlab_oauth_secret() {
        let token = format!("gloas-{}", "g".repeat(64));
        let result = detect_gitlab_tokens(&token);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_valid_gitlab_token_in_code() {
        let token = format!("glrt-{}", "h".repeat(20));
        let code = format!("GITLAB_TOKEN = '{token}'");
        let result = detect_gitlab_tokens(&code);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().1, token);
    }

    #[test]
    fn test_invalid_gitlab_token_prefix() {
        let token = format!("glpatx-{}", "a".repeat(20));
        assert!(detect_gitlab_tokens(&token).is_empty());
    }

    #[test]
    fn test_invalid_gitlab_token_length() {
        let token = format!("glpat-{}", "a".repeat(19));
        assert!(detect_gitlab_tokens(&token).is_empty());
    }
}
