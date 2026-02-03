# ReDoS Linter

A simple linter to detect Regular Expression Denial of Service (ReDoS) vulnerabilities in Python code.

## How it works

This linter uses `tree-sitter` to parse Python code and extract regular expression patterns. It then uses `recheck` to check if the regex is vulnerable to ReDoS attacks.

## Usage

1.  Install dependencies:

    ```bash
    npm install
    ```

2.  Run the linter:

    ```bash
    RECHECK_BACKEND=pure node index.js <file1.py> <file2.py> ...
    ```

    The linter will print any vulnerable regexes it finds, along with the file they were found in.
