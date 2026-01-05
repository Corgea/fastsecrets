use once_cell::sync::Lazy;
use regex::Regex;

/// Regex patterns for private key detection
/// These patterns detect common private key headers/markers
static PRIVATE_KEY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"BEGIN DSA PRIVATE KEY").expect("Invalid regex pattern"),
        Regex::new(r"BEGIN EC PRIVATE KEY").expect("Invalid regex pattern"),
        Regex::new(r"BEGIN OPENSSH PRIVATE KEY").expect("Invalid regex pattern"),
        Regex::new(r"BEGIN PGP PRIVATE KEY BLOCK").expect("Invalid regex pattern"),
        Regex::new(r"BEGIN PRIVATE KEY").expect("Invalid regex pattern"),
        Regex::new(r"BEGIN RSA PRIVATE KEY").expect("Invalid regex pattern"),
        Regex::new(r"BEGIN SSH2 ENCRYPTED PRIVATE KEY").expect("Invalid regex pattern"),
        Regex::new(r"PuTTY-User-Key-File-2").expect("Invalid regex pattern"),
    ]
});

/// Detects all private key markers in a string
///
/// # Arguments
/// * `secret` - The string to check for private key markers
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_private_keys(secret: &str) -> Vec<(String, String)> {
    let mut keys = Vec::new();

    for pattern in PRIVATE_KEY_PATTERNS.iter() {
        for key_match in pattern.find_iter(secret) {
            keys.push(("Private Key".to_string(), key_match.as_str().to_string()));
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_private_key_in_code() {
        let code = r#"
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
        "#;
        let result = detect_private_keys(code);
        assert!(!result.is_empty());
        let (_, value) = result.first().unwrap();
        assert_eq!(value, "BEGIN RSA PRIVATE KEY");
    }

    #[test]
    fn test_detect_multiple_private_keys() {
        let multi = "Key1: -----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\nKey2: -----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----";
        let results = detect_private_keys(multi);
        assert_eq!(results.len(), 2);

        // Check that both are "Private Key" type
        assert!(results.iter().all(|(t, _)| t == "Private Key"));

        // Check that we found both key types (order may vary)
        let values: Vec<&str> = results.iter().map(|(_, v)| v.as_str()).collect();
        assert!(values.contains(&"BEGIN RSA PRIVATE KEY"));
        assert!(values.contains(&"BEGIN EC PRIVATE KEY"));
    }

    #[test]
    fn test_no_private_key() {
        assert!(detect_private_keys("not_a_private_key").is_empty());
        assert!(detect_private_keys("").is_empty());
        assert!(detect_private_keys("BEGIN PUBLIC KEY").is_empty());
        assert!(detect_private_keys("ssh-rsa AAAAB3NzaC1yc2EA...").is_empty());
    }

    #[test]
    fn test_case_sensitive() {
        // Should not match lowercase versions
        assert!(detect_private_keys("begin rsa private key").is_empty());
        assert!(detect_private_keys("Begin Rsa Private Key").is_empty());
    }
}
