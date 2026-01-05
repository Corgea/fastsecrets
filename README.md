# fastsecrets

Simple and fast secret detection. Scan strings and files for secret keys, API tokens, and credentials.

## Features

- **High Performance**: Regex matching powered by Rust with parallel processing
- **Multiple Secret Types**: Detects various types of credentials and keys
- **Easy Integration**: Simple Python API with both programmatic and CLI interfaces

### Supported Secret Types

- **AWS Credentials**
  - AWS Access Key IDs (AKIA, ASIA, ABIA, ACCA, A3T*)
  - AWS Secret Access Keys (40 character keys with context)
- **API Keys**
  - OpenAI API Tokens (sk-...)
  - Anthropic API Keys (sk-ant-...)
- **Private Keys**
  - RSA Private Keys
  - EC Private Keys
  - DSA Private Keys
  - OpenSSH Private Keys
  - PGP Private Keys
  - SSH2 Private Keys
  - PuTTY Private Keys
- **JWT Tokens**
  - Valid JSON Web Tokens with proper structure
- **Basic Auth Credentials**
- **NPM Tokens**

## Installation

```bash
pip install fastsecrets
```

## Usage

### Python API

```python
from fastsecrets import detect

# Scan a single string
secrets = detect("AKIAIOSFODNN7EXAMPLE")
for secret in secrets:
    print(f"Found {secret.secret_type}: {secret.value}")

# Scan multiple strings
test_strings = [
    "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN",
    "AKIAIOSFODNN7EXAMPLE",
    "not_a_secret_key"
]

for test_string in test_strings:
    results = detect(test_string)
    if results:
        for secret in results:
            print(f"Secret type: {secret.secret_type}")
            print(f"Secret value: {secret.value}")
    else:
        print("No secrets found")
    
# detect only specific types
results = detect("some string", secret_types=["openai", "anthropic"]) 
```

### Command Line Interface

Scan files for secrets:

```bash
fastsecrets --file path/to/your/file.txt
```

The CLI will:
- Scan the file line by line
- Print any secrets found with line numbers
- Exit with code 1 if secrets are found (useful for CI/CD pipelines)
- Exit with code 0 if no secrets are found

Example output:
```
config.txt:5: [AWS Access Key ID] AKIAIOSFODNN7EXAMPLE
config.txt:12: [OpenAI Token] sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN
```


## Development

### Prerequisites

- Rust (latest stable)
- Python 3.8+
- `uv` for Python package management

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/fastsecrets.git
cd fastsecrets

# Install dependencies
uv pip install -e ".[tests]"

# Build the Rust extension
maturin develop
```

### Running Tests

```bash
# Run Python tests
pytest python/tests/

# Run Rust tests
cargo test
```

### Adding New Secret Detectors

1. Create a new detector module in `src/secrets/` (e.g., `src/secrets/stripe.rs`)
2. Implement the detection function with regex patterns
3. Add the detector to `src/lib.rs` in the parallel detection pipeline
4. Add tests in both Rust and Python
