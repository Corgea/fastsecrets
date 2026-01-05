use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for JWT detection
/// Format: header.payload.signature where each part is base64url encoded
/// Minimum lengths to avoid false positives: header (20+), payload (20+), signature (20+)
static JWT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})\b")
        .expect("Invalid regex pattern")
});

/// Validates if a potential JWT token has valid structure
///
/// Checks:
/// 1. Exactly 3 parts separated by dots
/// 2. Header can be base64url decoded and is valid JSON
/// 3. Payload can be base64url decoded and is valid JSON
/// 4. Header contains "alg" field (required by JWT spec)
///
/// # Arguments
/// * `token` - The potential JWT token to validate
///
/// # Returns
/// * `bool` - true if valid JWT structure, false otherwise
fn is_valid_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();

    // Must have exactly 3 parts
    if parts.len() != 3 {
        return false;
    }

    let header = parts[0];
    let payload = parts[1];

    // Validate header
    if let Some(header_json) = base64_decode_urlsafe(header) {
        if let Ok(header_value) = serde_json::from_str::<serde_json::Value>(&header_json) {
            // Header must be an object and contain "alg" field
            if !header_value.is_object() {
                return false;
            }
            if !header_value.get("alg").is_some() {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    // Validate payload
    if let Some(payload_json) = base64_decode_urlsafe(payload) {
        // Payload must be valid JSON (object or array)
        if serde_json::from_str::<serde_json::Value>(&payload_json).is_err() {
            return false;
        }
    } else {
        return false;
    }

    // Signature part doesn't need validation beyond being base64url
    // (we can't verify cryptographic validity without the secret key)

    true
}

/// Decodes a base64url encoded string
///
/// # Arguments
/// * `input` - The base64url encoded string
///
/// # Returns
/// * `Option<String>` - The decoded string if successful, None otherwise
fn base64_decode_urlsafe(input: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    match URL_SAFE_NO_PAD.decode(input) {
        Ok(bytes) => String::from_utf8(bytes).ok(),
        Err(_) => None,
    }
}

/// Detects all JWT tokens in a string
///
/// # Arguments
/// * `secret` - The string to check for JWT patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_jwt_tokens(secret: &str) -> Vec<(String, String)> {
    let mut tokens = Vec::new();

    // Use find_iter to find all matches
    for token_match in JWT_PATTERN.find_iter(secret) {
        let token = token_match.as_str();
        if is_valid_jwt(token) {
            tokens.push(("JWT Token".to_string(), token.to_string()));
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_jwt_token() {
        // Valid JWT: HS256 algorithm
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let result = detect_jwt_tokens(jwt);
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "JWT Token");
        assert_eq!(value, jwt);
    }

    #[test]
    fn test_valid_jwt_token_rs256() {
        // Valid JWT: RS256 algorithm
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"sub":"user123","name":"Alice","admin":true}
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkFsaWNlIiwiYWRtaW4iOnRydWV9.dGVzdC1zaWduYXR1cmUtZm9yLXJzMjU2LWFsZ29yaXRobS10aGlzLWlzLWEtbG9uZy1zaWduYXR1cmU";

        let result = detect_jwt_tokens(jwt);
        assert!(!result.is_empty());
        assert_eq!(result.first().unwrap().0, "JWT Token");
    }

    #[test]
    fn test_valid_jwt_in_code() {
        // JWT embedded in code
        let code = r#"const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";"#;

        let result = detect_jwt_tokens(code);
        assert!(!result.is_empty());
        let (_, value) = result.first().unwrap();
        assert!(value.starts_with("eyJ"));
        assert_eq!(value.split('.').count(), 3);
    }

    #[test]
    fn test_valid_jwt_in_header() {
        // JWT in HTTP Authorization header
        let header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let result = detect_jwt_tokens(header);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_multiple_jwt_tokens() {
        // Multiple JWTs in one string
        let multi = "token1=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and token2=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkFsaWNlIiwiYWRtaW4iOnRydWV9.dGVzdC1zaWduYXR1cmUtZm9yLXJzMjU2LWFsZ29yaXRobS10aGlzLWlzLWEtbG9uZy1zaWduYXR1cmU";

        let results = detect_jwt_tokens(multi);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "JWT Token");
        assert_eq!(results[1].0, "JWT Token");
    }

    #[test]
    fn test_invalid_jwt_not_three_parts() {
        // Only two parts
        let invalid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        assert!(detect_jwt_tokens(invalid).is_empty());

        // Four parts
        let invalid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature.extra";
        assert!(detect_jwt_tokens(invalid).is_empty());
    }

    #[test]
    fn test_invalid_jwt_bad_base64() {
        // Invalid base64 in header
        let invalid = "not-base64!@#.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(detect_jwt_tokens(invalid).is_empty());
    }

    #[test]
    fn test_invalid_jwt_not_json() {
        // Valid base64 but not JSON in header
        // "notjson" in base64url
        let invalid = "bm90anNvbg.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(detect_jwt_tokens(invalid).is_empty());
    }

    #[test]
    fn test_invalid_jwt_missing_alg() {
        // Valid JSON but missing "alg" field in header
        // Header: {"typ":"JWT"} (missing "alg")
        let invalid = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(detect_jwt_tokens(invalid).is_empty());
    }

    #[test]
    fn test_invalid_jwt_header_not_object() {
        // Header is JSON array instead of object
        // Header: ["alg","HS256"]
        let invalid = "WyJhbGciLCJIUzI1NiJd.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(detect_jwt_tokens(invalid).is_empty());
    }

    #[test]
    fn test_invalid_jwt_too_short() {
        // Parts are too short (less than 20 chars each)
        let invalid = "abc.def.ghi";
        assert!(detect_jwt_tokens(invalid).is_empty());
    }

    #[test]
    fn test_not_a_token() {
        assert!(detect_jwt_tokens("not_a_token").is_empty());
        assert!(detect_jwt_tokens("").is_empty());
        assert!(detect_jwt_tokens("just.two.dots.no.jwt").is_empty());
    }

    #[test]
    fn test_base64_decode() {
        // Test the base64 decode helper
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let decoded = base64_decode_urlsafe(header);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), r#"{"alg":"HS256","typ":"JWT"}"#);
    }
}
