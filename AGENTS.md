This project is designed to search a string for secret keys. All the regular expressions are ran in rust for speed. 

## Directory Structure:
- `python` folder: Contains the Python bindings for the Rust library.
- `src` folder: Contains the Rust source code for the secret detection logic.

## Guidelines:
- use `uv` for managing python
- add tests for new functionality

## Commands
- Run rust tests: `cargo test`
- Run python tests: `uv run pytest`
