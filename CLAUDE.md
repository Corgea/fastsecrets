This project is designed to search a string for secret keys. All the regular expressions are ran in rust for speed. 

## Directory Structure:
- `python` folder: Contains the Python bindings for the Rust library.
- `src` folder: Contains the Rust source code for the secret detection logic.

## Guidelines:
- use `uv` for managing python
- add tests for new functionality

## Installation:
```bash
pip install fastsecrets
```

## Usage:
```python

from fastsecrets import detect

secrets = [
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "AKIAIOSFODNN7EXAMPLE",
    "not_a_secret_key"
]

for secret in secrets:
    results = detect(line)
    for secret in results:
        print(secret.secret_type)
        print(f"Secret key found: {secret.value} of type {secret.secret_type}")
    
# Detect only specific types
results = detect("some string", secret_types=["aws", "anthropic"])
```
