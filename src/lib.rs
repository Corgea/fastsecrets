use pyo3::prelude::*;

mod secrets {
    pub mod anthropic;
    pub mod aws;
    pub mod jwt;
    pub mod openai;
}

/// Secret class representing a detected secret
#[pyclass]
#[derive(Clone)]
pub struct Secret {
    #[pyo3(get)]
    pub secret_type: String,
    #[pyo3(get)]
    pub value: String,
}

#[pymethods]
impl Secret {
    /// Returns a string representation of the Secret
    fn __repr__(&self) -> String {
        format!("Secret(secret_type='{}', value='{}')", self.secret_type, self.value)
    }

    /// Returns a string representation of the Secret
    fn __str__(&self) -> String {
        format!("Secret: {} ({})", self.value, self.secret_type)
    }
}

/// Detects all secret keys in a given string
///
/// This function runs each detector in parallel using separate threads for optimal performance.
///
/// Supports detection of:
/// - AWS Access Key IDs (AKIA, ASIA, ABIA, ACCA, A3T*)
/// - AWS Secret Access Keys (40 character keys with context)
/// - OpenAI API Tokens (sk-...)
/// - Anthropic API Keys (sk-ant-...)
/// - JWT Tokens (validated JSON Web Tokens)
/// - More detectors can be added here in the future
///
/// # Arguments
/// * `py` - Python context (used to release GIL during computation)
/// * `secret` - The string to check for secret patterns
///
/// # Returns
/// * `Vec<Secret>` - List of all secrets found (empty list if none detected)
#[pyfunction]
fn detect(py: Python<'_>, secret: &str) -> PyResult<Vec<Secret>> {
    // Convert to owned String for thread safety
    let secret_owned = secret.to_string();

    // Release the GIL and run detectors in parallel
    let all_results = py.detach(|| {
        // Get the number of available CPUs to limit concurrent threads
        let max_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4); // Default to 4 if we can't determine CPU count

        // Collect all detector tasks as closures
        let mut detector_tasks: Vec<Box<dyn FnOnce() -> Vec<(String, String)> + Send>> = vec![];

        // AWS Access Key ID detector
        detector_tasks.push(Box::new({
            let s = secret_owned.clone();
            move || {
                let mut results = Vec::new();
                if let Some((secret_type, value)) = secrets::aws::detect_aws_access_key(&s) {
                    results.push((secret_type, value));
                }
                results
            }
        }));

        // AWS Secret Access Key detector
        detector_tasks.push(Box::new({
            let s = secret_owned.clone();
            move || secrets::aws::detect_aws_secret_keys(&s)
        }));

        // OpenAI token detector
        detector_tasks.push(Box::new({
            let s = secret_owned.clone();
            move || secrets::openai::detect_openai_tokens(&s)
        }));

        // Anthropic API key detector
        detector_tasks.push(Box::new({
            let s = secret_owned.clone();
            move || secrets::anthropic::detect_anthropic_tokens(&s)
        }));

        // JWT token detector
        detector_tasks.push(Box::new({
            let s = secret_owned.clone();
            move || secrets::jwt::detect_jwt_tokens(&s)
        }));

        // Future detectors can be added here
        // detector_tasks.push(Box::new({
        //     let s = secret_owned.clone();
        //     move || secrets::stripe::detect_stripe_keys(&s)
        // }));

        // Process detector tasks in batches based on CPU count
        let mut all_secrets = Vec::new();
        let mut task_iter = detector_tasks.into_iter();

        loop {
            // Take up to max_threads tasks
            let batch: Vec<_> = task_iter.by_ref().take(max_threads).collect();
            if batch.is_empty() {
                break;
            }

            // Spawn threads for this batch
            let handles: Vec<_> = batch
                .into_iter()
                .map(|task| std::thread::spawn(task))
                .collect();

            // Wait for this batch to complete and collect results
            for handle in handles {
                match handle.join() {
                    Ok(secrets) => all_secrets.extend(secrets),
                    Err(_) => {
                        // Thread panicked, skip its results
                        // In production, you might want to log this
                    }
                }
            }
        }

        all_secrets
    });

    // Convert (String, String) tuples to Secret objects
    let found_secrets = all_results
        .into_iter()
        .map(|(secret_type, value)| Secret { secret_type, value })
        .collect();

    Ok(found_secrets)
}

/// A Python module implemented in Rust.
#[pymodule]
fn fastsecrets(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_class::<Secret>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_multiple_secrets_in_different_strings() {
        // Each string should detect a different type of secret
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let aws_secret = r#"secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#;
        let openai = "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN";
        let anthropic = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY";

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result1 = detect(py, aws_key).unwrap();
            assert_eq!(result1.len(), 1);
            assert_eq!(result1[0].secret_type, "AWS Access Key ID");

            let result2 = detect(py, aws_secret).unwrap();
            assert_eq!(result2.len(), 1);
            assert_eq!(result2[0].secret_type, "AWS Secret Access Key");

            let result3 = detect(py, openai).unwrap();
            assert_eq!(result3.len(), 1);
            assert_eq!(result3[0].secret_type, "OpenAI Token");

            let result4 = detect(py, anthropic).unwrap();
            assert_eq!(result4.len(), 1);
            assert_eq!(result4[0].secret_type, "Anthropic API Key");
        });
    }

    #[test]
    fn test_detect_all_matches_when_multiple_in_same_string() {
        // When multiple secrets are in the same string, detect() returns all of them
        let multi_secret = r#"secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" and key = sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"#;

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = detect(py, multi_secret).unwrap();
            assert_eq!(result.len(), 2);

            // Should detect both secrets
            let types: Vec<&str> = result.iter().map(|s| s.secret_type.as_str()).collect();
            assert!(types.contains(&"AWS Secret Access Key"));
            assert!(types.contains(&"OpenAI Token"));
        });
    }

    #[test]
    fn test_detect_line_by_line_scanning() {
        // Simulates scanning a file line by line
        let lines = vec![
            "# Configuration file",
            "AKIAIOSFODNN7EXAMPLE",  // AWS key on its own line
            r#"AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#,
            "OPENAI_KEY = sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN",
            "ANTHROPIC_KEY = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY",
            "NOT_A_SECRET = hello_world",
        ];

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut found_secrets = Vec::new();
            for line in lines {
                let secrets = detect(py, line).unwrap();
                for secret in secrets {
                    found_secrets.push(secret.secret_type.clone());
                }
            }

            // Should find all four types
            assert_eq!(found_secrets.len(), 4);
            assert!(found_secrets.contains(&"AWS Access Key ID".to_string()));
            assert!(found_secrets.contains(&"AWS Secret Access Key".to_string()));
            assert!(found_secrets.contains(&"OpenAI Token".to_string()));
            assert!(found_secrets.contains(&"Anthropic API Key".to_string()));
        });
    }

    #[test]
    fn test_no_false_positives_with_similar_patterns() {
        // Ensure similar-looking strings don't trigger false positives
        let non_secrets = vec![
            "AKIA123456789",  // Too short for AWS key
            "sk-project-name-only",  // Missing T3BlbkFJ
            "secret = \"short_value\"",  // Too short for AWS secret
            "",
            "completely_normal_text",
        ];

        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            for non_secret in non_secrets {
                let result = detect(py, non_secret).unwrap();
                assert!(result.is_empty(), "False positive for: {}", non_secret);
            }
        });
    }
}
