use once_cell::sync::Lazy;
use regex::Regex;

/// Regex pattern for AWS Access Key ID detection
/// Matches multiple AWS Access Key types:
/// - A3T[A-Z0-9] (AWS STS service account)
/// - ABIA (AWS STS service specific)
/// - ACCA (Context-specific credential)
/// - AKIA (Long-term credentials)
/// - ASIA (Temporary credentials)
/// All followed by 16 alphanumeric characters (uppercase and digits only)
/// Total length: 20 characters
static AWS_ACCESS_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}\b")
        .expect("Invalid regex pattern")
});

/// Regex pattern for AWS Secret Access Key detection
/// Format: 40 characters from [a-zA-Z0-9+/=] preceded by =, comma, or (
/// Optimized to avoid backtracking - quote validation done in code
/// Pattern captures: (1) optional quote, (2) the 40-char key, (3) optional quote after
static AWS_SECRET_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:=|,|\()\s*(['"]?)([a-zA-Z0-9+/=]{40})(['"]?)\)?(?:\s|$|[,)\n])"#)
        .expect("Invalid regex pattern")
});

/// Detects if a string contains an AWS Access Key ID
///
/// Supports multiple AWS Access Key types:
/// - A3T[A-Z0-9] (AWS STS service account)
/// - ABIA (AWS STS service specific)
/// - ACCA (Context-specific credential)
/// - AKIA (Long-term credentials)
/// - ASIA (Temporary credentials)
///
/// # Arguments
/// * `secret` - The string to check for AWS Access Key pattern
///
/// # Returns
/// * `Option<(String, String)>` - None if no match, Some((secret_type, value)) if match found
pub fn detect_aws_access_key(secret: &str) -> Option<(String, String)> {
    if let Some(key_match) = AWS_ACCESS_KEY_PATTERN.find(secret) {
        Some((
            "AWS Access Key ID".to_string(),
            key_match.as_str().to_string(),
        ))
    } else {
        None
    }
}

/// Detects all AWS Secret Access Keys in a string
///
/// # Arguments
/// * `content` - The string to check for AWS Secret Key patterns
///
/// # Returns
/// * `Vec<(String, String)>` - List of all (secret_type, value) pairs found
pub fn detect_aws_secret_keys(content: &str) -> Vec<(String, String)> {
    let mut secrets = Vec::new();

    // Use captures_iter to find all matches
    for captures in AWS_SECRET_KEY_PATTERN.captures_iter(content) {
        // Group 1: optional opening quote, Group 2: 40-char key, Group 3: optional closing quote
        let opening_quote = captures.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(secret_match) = captures.get(2) {
            let closing_quote = captures.get(3).map(|m| m.as_str()).unwrap_or("");

            // Validate that quotes match (both empty, or both the same quote character)
            if opening_quote == closing_quote {
                secrets.push((
                    "AWS Secret Access Key".to_string(),
                    secret_match.as_str().to_string(),
                ));
            }
        }
    }

    secrets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_aws_access_key() {
        // AKIA - Long-term credentials
        assert!(detect_aws_access_key("AKIAIOSFODNN7EXAMPLE").is_some());
        assert!(detect_aws_access_key("AKIA0000000000000000").is_some());

        let result = detect_aws_access_key("AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(result.0, "AWS Access Key ID");
        assert_eq!(result.1, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_valid_aws_access_key_asia() {
        // ASIA - Temporary credentials
        let result = detect_aws_access_key("ASIAIOSFODNN7EXAMPLE");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "AWS Access Key ID");
        assert_eq!(value, "ASIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_valid_aws_access_key_abia() {
        // ABIA - AWS STS service specific
        let result = detect_aws_access_key("ABIAIOSFODNN7EXAMPLE");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "AWS Access Key ID");
        assert_eq!(value, "ABIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_valid_aws_access_key_acca() {
        // ACCA - Context-specific credential
        let result = detect_aws_access_key("ACCAIOSFODNN7EXAMPLE");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "AWS Access Key ID");
        assert_eq!(value, "ACCAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_valid_aws_access_key_a3t() {
        // A3T[A-Z0-9] - AWS STS service account
        let result = detect_aws_access_key("A3T0IOSFODNN7EXAMPLE");
        assert!(result.is_some());
        let (secret_type, value) = result.unwrap();
        assert_eq!(secret_type, "AWS Access Key ID");
        assert_eq!(value, "A3T0IOSFODNN7EXAMPLE");

        // Test with letter after A3T
        let result = detect_aws_access_key("A3TZIOSFODNN7EXAMPLE");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "A3TZIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_valid_aws_access_key_in_code() {
        // Test that keys are detected when embedded in code
        let result = detect_aws_access_key("aws_access_key_id='AKIAIOSFODNN7EXAMPLE'");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "AKIAIOSFODNN7EXAMPLE");

        let result = detect_aws_access_key("export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE");
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "ASIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_invalid_aws_access_key() {
        assert!(detect_aws_access_key("AKIAIOSFODNN7EXAMPL").is_none()); // Too short
        assert!(detect_aws_access_key("AKIAIOSFODNN7EXAMPLE1").is_none()); // Too long
        assert!(detect_aws_access_key("AKIA00000000000000a").is_none()); // Lowercase not allowed
        assert!(detect_aws_access_key("not_a_secret_key").is_none());
        assert!(detect_aws_access_key("sk_test_4eC39HqLyjWDarjtT1zdp7dc").is_none()); // Stripe key
        assert!(detect_aws_access_key("").is_none()); // Empty string
    }

    #[test]
    fn test_valid_aws_secret_key() {
        // Test with double quotes
        let result = detect_aws_secret_keys(
            r#"secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#,
        );
        assert!(!result.is_empty());
        let (secret_type, value) = result.first().unwrap();
        assert_eq!(secret_type, "AWS Secret Access Key");
        assert_eq!(value, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        // Test with single quotes
        let result = detect_aws_secret_keys(
            r"some_function('AKIA...', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')",
        );
        assert!(!result.is_empty());
        assert_eq!(
            result.first().unwrap().1,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );

        // Test without quotes
        let result = detect_aws_secret_keys(
            "credentials(AKIA..., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)",
        );
        assert!(!result.is_empty());
        assert_eq!(
            result.first().unwrap().1,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );

        // Test with comma separator
        let result = detect_aws_secret_keys(
            r#"aws_credentials("key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")"#,
        );
        assert!(!result.is_empty());
        assert_eq!(
            result.first().unwrap().1,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }

    #[test]
    fn test_invalid_aws_secret_key() {
        // Too short (39 chars)
        assert!(
            detect_aws_secret_keys(r#"secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE""#)
                .is_empty()
        );

        // Too long (41 chars)
        assert!(
            detect_aws_secret_keys(r#"secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1""#)
                .is_empty()
        );

        // Invalid characters
        assert!(
            detect_aws_secret_keys(r#"secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE$""#)
                .is_empty()
        );

        // No preceding context
        assert!(detect_aws_secret_keys("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").is_empty());

        // Mismatched quotes
        assert!(
            detect_aws_secret_keys(r#"secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"#)
                .is_empty()
        );
    }
}
