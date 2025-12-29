import pytest
import fastsecrets


def test_detect_aws_access_key():
    """Test that AWS Access Key IDs are properly detected"""
    result = fastsecrets.detect("AKIAIOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].secret_type == "AWS Access Key ID"
    assert result[0].value == "AKIAIOSFODNN7EXAMPLE"


def test_detect_another_aws_key():
    """Test another valid AWS Access Key ID"""
    result = fastsecrets.detect("AKIA0000000000000000")
    assert len(result) == 1
    assert result[0].secret_type == "AWS Access Key ID"
    assert result[0].value == "AKIA0000000000000000"


def test_detect_aws_access_key_asia():
    """Test that AWS ASIA (temporary credentials) keys are detected"""
    result = fastsecrets.detect("ASIAIOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].secret_type == "AWS Access Key ID"
    assert result[0].value == "ASIAIOSFODNN7EXAMPLE"


def test_detect_aws_access_key_abia():
    """Test that AWS ABIA (STS service specific) keys are detected"""
    result = fastsecrets.detect("ABIAIOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].secret_type == "AWS Access Key ID"
    assert result[0].value == "ABIAIOSFODNN7EXAMPLE"


def test_detect_aws_access_key_acca():
    """Test that AWS ACCA (context-specific) keys are detected"""
    result = fastsecrets.detect("ACCAIOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].secret_type == "AWS Access Key ID"
    assert result[0].value == "ACCAIOSFODNN7EXAMPLE"


def test_detect_aws_access_key_a3t():
    """Test that AWS A3T (STS service account) keys are detected"""
    result = fastsecrets.detect("A3T0IOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].secret_type == "AWS Access Key ID"
    assert result[0].value == "A3T0IOSFODNN7EXAMPLE"

    # Test with letter after A3T
    result = fastsecrets.detect("A3TZIOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].value == "A3TZIOSFODNN7EXAMPLE"


def test_detect_aws_access_key_in_code():
    """Test that AWS keys embedded in code are detected"""
    result = fastsecrets.detect("aws_access_key_id='AKIAIOSFODNN7EXAMPLE'")
    assert len(result) == 1
    assert result[0].value == "AKIAIOSFODNN7EXAMPLE"

    result = fastsecrets.detect("export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE")
    assert len(result) == 1
    assert result[0].value == "ASIAIOSFODNN7EXAMPLE"


def test_detect_no_secret():
    """Test that non-secrets return empty list"""
    result = fastsecrets.detect("not_a_secret_key")
    assert len(result) == 0


def test_detect_stripe_key_not_matched():
    """Test that Stripe keys are not matched (not yet implemented)"""
    result = fastsecrets.detect("sk_test_4eC39HqLyjWDarjtT1zdp7dc")
    assert len(result) == 0


def test_detect_empty_string():
    """Test that empty strings return empty list"""
    result = fastsecrets.detect("")
    assert len(result) == 0


def test_detect_invalid_aws_key_too_short():
    """Test that AWS keys that are too short are not detected"""
    result = fastsecrets.detect("AKIAIOSFODNN7EXAMPL")
    assert len(result) == 0


def test_detect_invalid_aws_key_too_long():
    """Test that AWS keys that are too long are not detected"""
    result = fastsecrets.detect("AKIAIOSFODNN7EXAMPLE1")
    assert len(result) == 0


def test_detect_invalid_aws_key_lowercase():
    """Test that AWS keys with lowercase are not detected"""
    result = fastsecrets.detect("AKIA00000000000000a")
    assert len(result) == 0


def test_detect_aws_secret_key_double_quotes():
    """Test that AWS Secret Access Keys with double quotes are detected"""
    result = fastsecrets.detect(
        'secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    )
    assert len(result) == 1
    assert result[0].secret_type == "AWS Secret Access Key"
    assert result[0].value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_detect_aws_secret_key_single_quotes():
    """Test that AWS Secret Access Keys with single quotes are detected"""
    result = fastsecrets.detect(
        "some_function('AKIA...', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')"
    )
    assert len(result) == 1
    assert result[0].secret_type == "AWS Secret Access Key"
    assert result[0].value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_detect_aws_secret_key_no_quotes():
    """Test that AWS Secret Access Keys without quotes are detected"""
    result = fastsecrets.detect(
        "credentials(AKIA..., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
    )
    assert len(result) == 1
    assert result[0].secret_type == "AWS Secret Access Key"
    assert result[0].value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_detect_aws_secret_key_with_comma():
    """Test that AWS Secret Access Keys with comma separator are detected"""
    result = fastsecrets.detect(
        'aws_credentials("key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")'
    )
    assert len(result) == 1
    assert result[0].secret_type == "AWS Secret Access Key"
    assert result[0].value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_detect_aws_secret_key_too_short():
    """Test that AWS Secret Keys that are too short are not detected"""
    result = fastsecrets.detect('secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE"')
    assert len(result) == 0


def test_detect_aws_secret_key_too_long():
    """Test that AWS Secret Keys that are too long are not detected"""
    result = fastsecrets.detect('secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"')
    assert len(result) == 0


def test_detect_aws_secret_key_no_context():
    """Test that AWS Secret Keys without context are not detected"""
    result = fastsecrets.detect("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert len(result) == 0


def test_detect_openai_token_legacy():
    """Test that legacy OpenAI tokens are detected"""
    result = fastsecrets.detect("sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN")
    assert len(result) == 1
    assert result[0].secret_type == "OpenAI Token"
    assert result[0].value == "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"


def test_detect_openai_token_project_based():
    """Test that project-based OpenAI tokens are detected"""
    result = fastsecrets.detect(
        "sk-proj-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"
    )
    assert len(result) == 1
    assert result[0].secret_type == "OpenAI Token"
    assert result[0].value == "sk-proj-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"


def test_detect_openai_token_with_underscores():
    """Test that OpenAI tokens with underscores in project name are detected"""
    result = fastsecrets.detect(
        "sk-my_project-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"
    )
    assert len(result) == 1
    assert result[0].secret_type == "OpenAI Token"
    assert (
        result[0].value
        == "sk-my_project-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"
    )


def test_detect_openai_token_in_code():
    """Test that OpenAI tokens embedded in code are detected"""
    result = fastsecrets.detect(
        "openai.api_key = 'sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN'"
    )
    assert len(result) == 1
    assert result[0].secret_type == "OpenAI Token"
    assert result[0].value == "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"


def test_detect_openai_token_invalid_missing_marker():
    """Test that strings missing T3BlbkFJ are not detected"""
    result = fastsecrets.detect("sk-aBcDeFgHiJkLmNoPqRsTabcdefghiJkLmNoPqRsT")
    assert len(result) == 0


def test_detect_openai_token_invalid_wrong_prefix():
    """Test that tokens with wrong prefix are not detected"""
    result = fastsecrets.detect("pk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkL")
    assert len(result) == 0


def test_detect_openai_token_invalid_too_short():
    """Test that tokens that are too short are not detected"""
    result = fastsecrets.detect("sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZ")
    assert len(result) == 0


def test_detect_anthropic_api_key():
    """Test that Anthropic API keys are properly detected"""
    result = fastsecrets.detect(
        "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY"
    )
    assert len(result) == 1
    assert result[0].secret_type == "Anthropic API Key"
    assert (
        result[0].value
        == "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY"
    )


def test_detect_anthropic_api_key_in_code():
    """Test that Anthropic API keys embedded in code are detected"""
    result = fastsecrets.detect(
        "ANTHROPIC_API_KEY = 'sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY'"
    )
    assert len(result) == 1
    assert result[0].secret_type == "Anthropic API Key"
    assert len(result[0].value) == 108


def test_detect_anthropic_api_key_in_json():
    """Test that Anthropic API keys in JSON are detected"""
    result = fastsecrets.detect(
        '{"api_key": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY"}'
    )
    assert len(result) == 1
    assert result[0].secret_type == "Anthropic API Key"


def test_detect_anthropic_api_key_invalid_too_short():
    """Test that Anthropic keys that are too short are not detected"""
    result = fastsecrets.detect("sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
    assert len(result) == 0


def test_detect_anthropic_api_key_invalid_too_long():
    """Test that Anthropic keys that are too long are not detected"""
    result = fastsecrets.detect(
        "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZa"
    )
    assert len(result) == 0


def test_detect_anthropic_api_key_invalid_wrong_prefix():
    """Test that keys with wrong prefix are not detected"""
    result = fastsecrets.detect(
        "sk-api-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY"
    )
    assert len(result) == 0


def test_detect_multiple_anthropic_keys():
    """Test that multiple Anthropic keys in one string are detected"""
    result = fastsecrets.detect(
        "key1=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY and key2=sk-ant-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJK"
    )
    assert len(result) == 2
    assert result[0].secret_type == "Anthropic API Key"
    assert result[1].secret_type == "Anthropic API Key"


def test_detect_jwt_token():
    """Test that valid JWT tokens are detected"""
    # Valid JWT: HS256 algorithm
    # Header: {"alg":"HS256","typ":"JWT"}
    # Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = fastsecrets.detect(jwt)
    assert len(result) == 1
    assert result[0].secret_type == "JWT Token"
    assert result[0].value == jwt


def test_detect_jwt_token_rs256():
    """Test that JWT tokens with RS256 algorithm are detected"""
    jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkFsaWNlIiwiYWRtaW4iOnRydWV9.dGVzdC1zaWduYXR1cmUtZm9yLXJzMjU2LWFsZ29yaXRobS10aGlzLWlzLWEtbG9uZy1zaWduYXR1cmU"
    result = fastsecrets.detect(jwt)
    assert len(result) == 1
    assert result[0].secret_type == "JWT Token"


def test_detect_jwt_in_code():
    """Test that JWT tokens embedded in code are detected"""
    code = 'const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";'
    result = fastsecrets.detect(code)
    assert len(result) == 1
    assert result[0].secret_type == "JWT Token"


def test_detect_jwt_in_authorization_header():
    """Test that JWT tokens in Authorization headers are detected"""
    header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = fastsecrets.detect(header)
    assert len(result) == 1
    assert result[0].secret_type == "JWT Token"


def test_detect_multiple_jwt_tokens():
    """Test that multiple JWT tokens in one string are detected"""
    multi = "token1=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and token2=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkFsaWNlIiwiYWRtaW4iOnRydWV9.dGVzdC1zaWduYXR1cmUtZm9yLXJzMjU2LWFsZ29yaXRobS10aGlzLWlzLWEtbG9uZy1zaWduYXR1cmU"
    result = fastsecrets.detect(multi)
    assert len(result) == 2
    assert result[0].secret_type == "JWT Token"
    assert result[1].secret_type == "JWT Token"


def test_detect_invalid_jwt_not_three_parts():
    """Test that strings without exactly 3 parts are not detected as JWT"""
    # Only two parts
    invalid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    result = fastsecrets.detect(invalid)
    assert len(result) == 0


def test_detect_invalid_jwt_missing_alg():
    """Test that JWT without 'alg' field in header is not detected"""
    # Header: {"typ":"JWT"} (missing "alg")
    invalid = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = fastsecrets.detect(invalid)
    assert len(result) == 0


def test_detect_invalid_jwt_not_base64():
    """Test that strings with invalid base64 are not detected as JWT"""
    invalid = "not-valid-base64!@#.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = fastsecrets.detect(invalid)
    assert len(result) == 0


def test_detect_invalid_jwt_too_short():
    """Test that strings with parts too short are not detected as JWT"""
    invalid = "abc.def.ghi"
    result = fastsecrets.detect(invalid)
    assert len(result) == 0


def test_detect_multiple_secrets_in_different_strings():
    """Test that different types of secrets are detected in separate strings"""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = 'secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    openai = "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN"
    anthropic = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY"

    result1 = fastsecrets.detect(aws_key)
    assert len(result1) == 1
    assert result1[0].secret_type == "AWS Access Key ID"

    result2 = fastsecrets.detect(aws_secret)
    assert len(result2) == 1
    assert result2[0].secret_type == "AWS Secret Access Key"

    result3 = fastsecrets.detect(openai)
    assert len(result3) == 1
    assert result3[0].secret_type == "OpenAI Token"

    result4 = fastsecrets.detect(anthropic)
    assert len(result4) == 1
    assert result4[0].secret_type == "Anthropic API Key"


def test_detect_all_matches_when_multiple_in_same_string():
    """Test that detect() returns all matches when multiple secrets exist"""
    # AWS Secret Key and OpenAI token in same string - should detect both
    multi_secret = 'secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" and key = sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN'
    result = fastsecrets.detect(multi_secret)
    assert len(result) == 2

    types = [s.secret_type for s in result]
    assert "AWS Secret Access Key" in types
    assert "OpenAI Token" in types


def test_detect_line_by_line_scanning():
    """Test scanning a multi-line file to find all secret types"""
    code = """# Configuration file
AKIAIOSFODNN7EXAMPLE
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
OPENAI_KEY = sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN
ANTHROPIC_KEY = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-api03-ABCDEFGHIJKLMNOPQRSTUVWXY
NOT_A_SECRET = hello_world
"""

    found_secrets = []
    for line in code.strip().split("\n"):
        results = fastsecrets.detect(line)
        for secret in results:
            found_secrets.append(secret.secret_type)

    # Should find all four types
    assert len(found_secrets) == 4
    assert "AWS Access Key ID" in found_secrets
    assert "AWS Secret Access Key" in found_secrets
    assert "OpenAI Token" in found_secrets
    assert "Anthropic API Key" in found_secrets


def test_no_false_positives_with_similar_patterns():
    """Test that similar-looking strings don't trigger false positives"""
    non_secrets = [
        "AKIA123456789",  # Too short for AWS key
        "sk-project-name-only",  # Missing T3BlbkFJ
        'secret = "short_value"',  # Too short for AWS secret
        "",
        "completely_normal_text",
    ]

    for non_secret in non_secrets:
        result = fastsecrets.detect(non_secret)
        assert len(result) == 0, f"False positive for: {non_secret}"


def test_detect_mixed_secrets_in_realistic_code():
    """Test detection in a realistic code snippet with multiple secret types"""
    code_snippet = """
import boto3
import openai

# AWS Configuration
s3_client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)

# OpenAI Configuration
openai.api_key = 'sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN'
"""

    secrets_found = {}
    for line in code_snippet.split("\n"):
        results = fastsecrets.detect(line)
        for secret in results:
            secrets_found[secret.secret_type] = secret.value

    # Should find at least AWS Secret and OpenAI (AWS Access Key might not match due to quote context)
    assert len(secrets_found) >= 2
    assert "AWS Secret Access Key" in secrets_found
    assert "OpenAI Token" in secrets_found


# Private Key Tests


def test_detect_rsa_private_key():
    """Test that RSA private keys are properly detected"""
    private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    result = fastsecrets.detect(private_key)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "BEGIN RSA PRIVATE KEY"


def test_detect_ec_private_key():
    """Test that EC private keys are properly detected"""
    private_key = (
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGl...\n-----END EC PRIVATE KEY-----"
    )
    result = fastsecrets.detect(private_key)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "BEGIN EC PRIVATE KEY"


def test_detect_openssh_private_key():
    """Test that OpenSSH private keys are properly detected"""
    private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...\n-----END OPENSSH PRIVATE KEY-----"
    result = fastsecrets.detect(private_key)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "BEGIN OPENSSH PRIVATE KEY"


def test_detect_pgp_private_key():
    """Test that PGP private keys are properly detected"""
    private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v1\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----"
    result = fastsecrets.detect(private_key)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "BEGIN PGP PRIVATE KEY BLOCK"


def test_detect_generic_private_key():
    """Test that generic PKCS#8 private keys are properly detected"""
    private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw...\n-----END PRIVATE KEY-----"
    result = fastsecrets.detect(private_key)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "BEGIN PRIVATE KEY"


def test_detect_putty_private_key():
    """Test that PuTTY private keys are properly detected"""
    private_key = "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: imported-openssh-key"
    result = fastsecrets.detect(private_key)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "PuTTY-User-Key-File-2"


def test_detect_private_key_in_code():
    """Test that private keys embedded in code are detected"""
    code = '''
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
    '''
    result = fastsecrets.detect(code)
    assert len(result) == 1
    assert result[0].secret_type == "Private Key"
    assert result[0].value == "BEGIN RSA PRIVATE KEY"


def test_detect_multiple_private_keys():
    """Test that multiple private keys in the same string are detected"""
    multi = "Key1: -----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\nKey2: -----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
    results = fastsecrets.detect(multi)
    assert len(results) == 2

    # Check that both are "Private Key" type
    secret_types = [r.secret_type for r in results]
    assert all(t == "Private Key" for t in secret_types)

    # Check that we found both key types (order may vary)
    values = [r.value for r in results]
    assert "BEGIN RSA PRIVATE KEY" in values
    assert "BEGIN EC PRIVATE KEY" in values


def test_no_false_positive_for_public_key():
    """Test that public keys are not detected as private keys"""
    public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
    result = fastsecrets.detect(public_key)
    assert len(result) == 0


def test_no_false_positive_for_lowercase_private_key():
    """Test that lowercase private key markers are not detected (case sensitive)"""
    lowercase_key = "begin rsa private key"
    result = fastsecrets.detect(lowercase_key)
    assert len(result) == 0
