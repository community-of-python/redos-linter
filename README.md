# ReDoS Linter

A Python linter that detects Regular Expression Denial of Service (ReDoS) vulnerabilities in your code. ReDoS attacks occur when malicious input causes exponential backtracking in regular expressions, leading to denial of service.

## Features

- Scans Python files for regular expressions
- Detects vulnerable regex patterns using the [recheck](https://github.com/makenowjust-labs/recheck) engine
- Provides detailed attack vectors when vulnerabilities are found
- Supports both file and directory scanning
- Clean, colored output for better readability

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
uv run python -m src.redos_linter test.py
```

## How It Works

1. **AST Analysis**: Extracts all regular expression literals from Python source code using AST parsing
2. **ReDoS Detection**: Uses the recheck engine to analyze each regex for potential exponential backtracking
3. **Attack Generation**: When vulnerabilities are found, generates specific attack strings that demonstrate the issue
4. **Reporting**: Provides clear, actionable output with source context and attack vectors

## Requirements

- Python 3.10+
- Deno runtime (automatically managed via the deno Python package)
