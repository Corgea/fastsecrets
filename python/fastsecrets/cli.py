"""Command-line interface for fastsecrets."""

import argparse
import sys
from pathlib import Path
from fastsecrets import detect


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Scan files for secret keys and tokens",
        prog="fastsecrets"
    )
    parser.add_argument(
        "--file",
        type=str,
        required=True,
        help="Path to the file to scan for secrets"
    )

    args = parser.parse_args()

    # Check if file exists
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    if not file_path.is_file():
        print(f"Error: Path is not a file: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Read file line by line and detect secrets
    found_secrets = False
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                results = detect(line)
                for secret in results:
                    found_secrets = True
                    print(f"{args.file}:{line_num}: [{secret.secret_type}] {secret.value}")
    except UnicodeDecodeError:
        print(f"Error: Unable to read file as UTF-8: {args.file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Exit with code 1 if secrets were found (useful for CI/CD)
    if found_secrets:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
