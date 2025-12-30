"""Tests for the CLI interface."""

import subprocess
import tempfile
from pathlib import Path


def test_cli_detects_secrets_in_file():
    """Test that the CLI detects secrets in a file."""
    # Create a temporary file with secrets
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("# Configuration\n")
        f.write("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        f.write("API_KEY = 'sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN'\n")
        f.write("NOT_SECRET = 'just a regular string'\n")
        temp_file = f.name

    try:
        # Run the CLI
        result = subprocess.run(
            ["uv", "run", "python", "-m", "fastsecrets", "--file", temp_file],
            capture_output=True,
            text=True
        )

        # Should exit with code 1 when secrets are found
        assert result.returncode == 1

        # Check that output contains the detected secrets
        assert "AWS Access Key ID" in result.stdout
        assert "OpenAI Token" in result.stdout
        assert "AKIAIOSFODNN7EXAMPLE" in result.stdout
        assert "sk-aBcDeFgHiJkLmNoPqRsTT3BlbkFJuVwXyZaBcDeFgHiJkLmN" in result.stdout

        # Check that line numbers are included
        assert ":2:" in result.stdout  # AWS key on line 2
        assert ":3:" in result.stdout  # OpenAI key on line 3
    finally:
        # Clean up
        Path(temp_file).unlink()


def test_cli_no_secrets():
    """Test that the CLI exits cleanly when no secrets are found."""
    # Create a temporary file without secrets
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("# Just a normal file\n")
        f.write("print('Hello, world!')\n")
        f.write("x = 42\n")
        temp_file = f.name

    try:
        # Run the CLI
        result = subprocess.run(
            ["uv", "run", "python", "-m", "fastsecrets", "--file", temp_file],
            capture_output=True,
            text=True
        )

        # Should exit with code 0 when no secrets are found
        assert result.returncode == 0

        # Output should be empty
        assert result.stdout == ""
    finally:
        # Clean up
        Path(temp_file).unlink()


def test_cli_file_not_found():
    """Test that the CLI handles missing files gracefully."""
    result = subprocess.run(
        ["uv", "run", "python", "-m", "fastsecrets", "--file", "/nonexistent/file.py"],
        capture_output=True,
        text=True
    )

    # Should exit with error code
    assert result.returncode == 1

    # Should print error message
    assert "Error: File not found" in result.stderr


def test_cli_requires_file_argument():
    """Test that the CLI requires the --file argument."""
    result = subprocess.run(
        ["uv", "run", "python", "-m", "fastsecrets"],
        capture_output=True,
        text=True
    )

    # Should exit with error code
    assert result.returncode != 0

    # Should mention the required argument
    assert "--file" in result.stderr or "required" in result.stderr.lower()
