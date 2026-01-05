use once_cell::sync::Lazy;
use regex::Regex;

/// RFC 3986 Section 2.2 reserved characters that should not appear in username/password
/// Combined: reserved + sub-delimiters = :/?#[]@!'()*+,;=
///
/// Pattern matches Basic Auth credentials in URIs:
/// - ://username:password@host
/// - Captures the password portion
static BASIC_AUTH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Characters that should NOT appear in username/password components:
    // Reserved: :/?#[]@
    // Sub-delimiters: !'()*+,;=
    // Plus whitespace
    // The character class excludes these characters
    Regex::new(r"://[^:/?#\[\]@!'()*+,;=\s]+:([^:/?#\[\]@!'()*+,;=\s]+)@")
        .expect("Invalid regex pattern")
});

/// Detects Basic Auth credentials in a URI string
///
/// Matches patterns like:
/// - https://user:password@example.com
/// - ftp://admin:secret123@server.local
/// - mongodb://dbuser:dbpass@localhost:27017
///
/// # Arguments
/// * `content` - The string to check for Basic Auth credentials
///
/// # Returns
/// * `Option<(String, String)>` - None if no match, Some((secret_type, password)) if match found
pub fn detect_basic_auth(content: &str) -> Option<(String, String)> {
    if let Some(captures) = BASIC_AUTH_PATTERN.captures(content) {
        if let Some(password_match) = captures.get(1) {
            return Some((
                "Basic Auth Credentials".to_string(),
                password_match.as_str().to_string(),
            ));
        }
    }
    None
}

/// Detects all Basic Auth credentials in a string
///
/// # Arguments
/// * `content` - The string to check for Basic Auth credential patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, password) pairs found
pub fn detect_basic_auth_credentials(content: &str) -> Vec<(String, String)> {
    let mut secrets = Vec::new();

    for captures in BASIC_AUTH_PATTERN.captures_iter(content) {
        if let Some(password_match) = captures.get(1) {
            secrets.push((
                "Basic Auth Credentials".to_string(),
                password_match.as_str().to_string(),
            ));
        }
    }

    secrets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth_https() {
        let result = detect_basic_auth("https://user:password123@example.com");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Basic Auth Credentials");
        assert_eq!(value, "password123");
    }

    #[test]
    fn test_basic_auth_http() {
        let result = detect_basic_auth("http://admin:supersecret@localhost:8080/api");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Basic Auth Credentials");
        assert_eq!(value, "supersecret");
    }

    #[test]
    fn test_basic_auth_ftp() {
        let result = detect_basic_auth("ftp://ftpuser:ftppass@files.example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "ftppass");
    }

    #[test]
    fn test_basic_auth_mongodb() {
        let result = detect_basic_auth("mongodb://dbuser:dbpassword@localhost:27017/mydb");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "dbpassword");
    }

    #[test]
    fn test_basic_auth_redis() {
        let result = detect_basic_auth("redis://default:redispass@redis.example.com:6379");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "redispass");
    }

    #[test]
    fn test_basic_auth_in_code() {
        let code = r#"DATABASE_URL = "postgresql://postgres:secretpass@db.example.com:5432/production""#;
        let result = detect_basic_auth(code);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "secretpass");
    }

    #[test]
    fn test_basic_auth_multiple() {
        let content = "url1=https://user1:pass1@host1.com url2=https://user2:pass2@host2.com";
        let results = detect_basic_auth_credentials(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, "pass1");
        assert_eq!(results[1].1, "pass2");
    }

    #[test]
    fn test_no_basic_auth_without_password() {
        // URL without password should not match
        assert!(detect_basic_auth("https://user@example.com").is_none());
    }

    #[test]
    fn test_no_basic_auth_without_credentials() {
        // URL without credentials should not match
        assert!(detect_basic_auth("https://example.com").is_none());
    }

    #[test]
    fn test_no_basic_auth_plain_text() {
        // Plain text should not match
        assert!(detect_basic_auth("user:password").is_none());
        assert!(detect_basic_auth("not a url at all").is_none());
    }

    #[test]
    fn test_basic_auth_complex_password() {
        // Password with allowed special characters
        let result = detect_basic_auth("https://user:p4ssw0rd-with_special.chars@example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "p4ssw0rd-with_special.chars");
    }

    #[test]
    fn test_basic_auth_empty_string() {
        assert!(detect_basic_auth("").is_none());
    }
}
