use regex::Regex;
use once_cell::sync::Lazy;

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

/// Detects if a string contains a private key marker
///
/// Private keys are detected by checking for specific header strings:
/// - BEGIN DSA PRIVATE KEY
/// - BEGIN EC PRIVATE KEY
/// - BEGIN OPENSSH PRIVATE KEY
/// - BEGIN PGP PRIVATE KEY BLOCK
/// - BEGIN PRIVATE KEY
/// - BEGIN RSA PRIVATE KEY
/// - BEGIN SSH2 ENCRYPTED PRIVATE KEY
/// - PuTTY-User-Key-File-2
///
/// # Arguments
/// * `secret` - The string to check for private key markers
///
/// # Returns
/// * `Option<(String, String)>` - None if no match, Some((secret_type, value)) if match found
pub fn detect_private_key(secret: &str) -> Option<(String, String)> {
    for pattern in PRIVATE_KEY_PATTERNS.iter() {
        if let Some(key_match) = pattern.find(secret) {
            return Some((
                "Private Key".to_string(),
                key_match.as_str().to_string(),
            ));
        }
    }
    None
}

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
            keys.push((
                "Private Key".to_string(),
                key_match.as_str().to_string(),
            ));
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_rsa_private_key() {
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN RSA PRIVATE KEY");
    }

    #[test]
    fn test_detect_ec_private_key() {
        let key = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGl...\n-----END EC PRIVATE KEY-----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN EC PRIVATE KEY");
    }

    #[test]
    fn test_detect_dsa_private_key() {
        let key = "-----BEGIN DSA PRIVATE KEY-----\nMIIBugIBAAKBgQC...\n-----END DSA PRIVATE KEY-----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN DSA PRIVATE KEY");
    }

    #[test]
    fn test_detect_openssh_private_key() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...\n-----END OPENSSH PRIVATE KEY-----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN OPENSSH PRIVATE KEY");
    }

    #[test]
    fn test_detect_pgp_private_key() {
        let key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v1\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN PGP PRIVATE KEY BLOCK");
    }

    #[test]
    fn test_detect_generic_private_key() {
        let key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw...\n-----END PRIVATE KEY-----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN PRIVATE KEY");
    }

    #[test]
    fn test_detect_ssh2_encrypted_private_key() {
        let key = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: \"rsa-key-20240101\"\nP2/56wAAA...\n---- END SSH2 ENCRYPTED PRIVATE KEY ----";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "BEGIN SSH2 ENCRYPTED PRIVATE KEY");
    }

    #[test]
    fn test_detect_putty_private_key() {
        let key = "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: imported-openssh-key\nPublic-Lines: 6\nAAAAB3Nza...";
        let result = detect_private_key(key);
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "Private Key");
        assert_eq!(value, "PuTTY-User-Key-File-2");
    }

    #[test]
    fn test_detect_private_key_in_code() {
        let code = r#"
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
        "#;
        let result = detect_private_key(code);
        assert!(result.is_some());
        let (_, value) = result.unwrap();
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
        assert!(detect_private_key("not_a_private_key").is_none());
        assert!(detect_private_key("").is_none());
        assert!(detect_private_key("BEGIN PUBLIC KEY").is_none());
        assert!(detect_private_key("ssh-rsa AAAAB3NzaC1yc2EA...").is_none());
    }

    #[test]
    fn test_case_sensitive() {
        // Should not match lowercase versions
        assert!(detect_private_key("begin rsa private key").is_none());
        assert!(detect_private_key("Begin Rsa Private Key").is_none());
    }
}
