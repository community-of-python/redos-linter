# ReDoS Linter

A Python linter that detects Regular Expression Denial of Service (ReDoS) vulnerabilities in your code. ReDoS attacks occur when malicious input causes exponential backtracking in regular expressions, leading to denial of service.

## Features

- Scans Python files for string literals that look like regular expressions
- Detects vulnerable regex patterns using the [recheck](https://github.com/makenowjust-labs/recheck) engine
- Provides detailed attack vectors when vulnerabilities are found
- Supports both file and directory scanning
- Clean, colored output for better readability
- Support for ignore comments to exclude specific regexes from analysis

## Installation

```bash
pip install redos-linter
```

## Usage

### Command Line

Check specific files or directories:

```bash
# Check a single file
redos-linter myfile.py

# Check multiple files
redos-linter file1.py file2.py

# Check a directory (recursively scans all .py files)
redos-linter src/

# Check multiple directories
redos-linter src/ tests/
```

### Python Module

You can also run it as a Python module:

```bash
python -m redos_linter src/
```

## Exit status

Both `redos-linter` and `python -m redos_linter` return:

- `0` when every checked regex is safe, or no regexes are found.
- `1` when vulnerabilities are found, with locations, patterns, and source context in the output.
- `2` when the checker fails, returns an incomplete or invalid response, or cannot classify every regex.

Invalid arguments also return `2`. File access and Python parsing errors terminate with a nonzero status.
Starting with version 0.3.2, findings fail the command; CI users who want an advisory check should configure their job to allow failure.

## Output

The linter provides clear output indicating:

- ✅ **Safe**: No ReDoS vulnerabilities detected
- ❌ **Vulnerable**: ReDoS vulnerability found with attack vector details

When vulnerabilities are detected, the output includes:
- The vulnerable regular expression
- File location (line and column)
- Source code context
- Attack string that can trigger the ReDoS
- Pump strings for the attack

## Examples of Vulnerable Patterns

```python
import re

# Exponential backtracking due to nested quantifiers
vulnerable_1 = re.compile(r"^(a+)+$")

# Exponential backtracking due to overlapping quantifiers
vulnerable_2 = re.compile(r"(a|aa)+")

# Complex nested pattern
vulnerable_3 = re.compile(r"([a-z]+)+$")

# Real-world example
vulnerable_4 = re.compile(r"^(name|email|phone),([a-zA-Z0-9_]+,)*([a-zA-Z0-9_]+)$")
```

## Examples of Safe Patterns

```python
import re

# Simple safe regex
safe_1 = re.compile(r"^[a-zA-Z0-9_]+$")

# Email pattern (properly structured)
safe_2 = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

# Non-overlapping alternation
safe_3 = re.compile(r"^(cat|dog)$")
```

## Ignoring Specific Regexes

You can exclude specific regexes from analysis by adding `# redos-linter: ignore` on the same line:

```python
import re

# This vulnerable regex will be ignored
vulnerable = re.compile(r"(a+)+")  # redos-linter: ignore

# This vulnerable regex will be detected
also_vulnerable = re.compile(r"([a-z]+)+$")
```

This is useful when:
- You've reviewed a regex and determined it's safe despite being flagged
- You want to temporarily ignore a warning while working on a fix
- You have a regex that's intentionally complex for a specific reason

## Development

Install in development mode:

```bash
# Clone the repository
git clone <repository-url>
cd redos-linter

# Install in development mode
uv sync

# Run tests
uv run pytest

# Run linter on test file
uv run python -m redos_linter tests/test.py
```

## Test Structure

The tests are organized as follows:
- `test_attack_string_limit.py` - Tests for attack string length limiting
- `test_ignore_comments.py` - Tests for ignore comments functionality
- `test_integration.py` - Integration tests for the command-line interface
- `test_main_function.py` - Tests for the main linter functionality
- `test_regex_extractor.py` - Tests for regex extraction from Python source code
- `test.py` - Sample Python file with various regex patterns for testing

## How It Works

1. **AST Analysis**: Scans string literals containing regex metacharacters that form valid Python regex syntax, including patterns in assignments, containers, and nested calls. Direct literal pattern arguments to `re` and `regex` APIs (including imported aliases) are checked even when invalid, so malformed explicit patterns still fail. Literal membership comparisons, file modes, glob arguments, and subjects/replacements in recognized regex calls are treated as text. Message f-string fragments are skipped; complete fragments in explicit regex arguments and nested calls inside f-string expressions or format specifications are still checked. Structurally incomplete dynamic fragments, such as `[` or `)`, are not submitted as standalone patterns. Other invalid fragments, such as `*`, still fail.
2. **ReDoS Detection**: Uses the recheck engine to analyze each potential regex for potential exponential backtracking. Leading global Python multiline (`(?m)`) and dotall (`(?s)`) modes are translated to checker flags while reports retain the original pattern. Other unsupported syntax or flags still produce an unclassified result and exit status `2`, with the pattern, location and engine reason in diagnostics. The linter does not evaluate dynamically constructed patterns: every explicit regex f-string with interpolation emits a partial-analysis warning, even if its fragments are safe. Exit status `0` covers only analyzed static patterns and does not establish safety of the assembled runtime pattern.
3. **Attack Generation**: When vulnerabilities are found, generates specific attack strings that demonstrate the issue
4. **Reporting**: Provides clear, actionable output with source context and attack vectors

## Requirements

- Python 3.10+
- Deno runtime (automatically managed via the deno Python package)
