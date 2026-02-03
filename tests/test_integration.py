import os
import subprocess
import sys
from pathlib import Path


def test_help_command() -> None:
    """Test that the command line interface shows help."""
    result = subprocess.run(
        [sys.executable, "-m", "src.redos_linter", "--help"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )

    # Should show help
    assert result.returncode == 0
    assert "ReDoS Linter" in result.stdout


def test_run_on_existing_test_file() -> None:
    """Test running on the existing test.py file."""
    test_file = Path(__file__).parent.parent / "test.py"

    # Run the linter
    result = subprocess.run(
        [sys.executable, "-m", "src.redos_linter", str(test_file)],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
        cwd=str(Path(__file__).parent.parent),
    )

    # Should succeed
    assert result.returncode == 0

    # Should find vulnerabilities in test.py
    assert "VULNERABLE" in result.stdout
    assert "Found" in result.stdout
    assert "vulnerable" in result.stdout


def test_run_on_safe_file() -> None:
    """Test running on a file with only safe patterns."""
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("""
import re

# All safe patterns
email = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")
simple = re.compile(r"^[a-z]+$")
choices = re.compile(r"^(cat|dog|bird)$")
numbers = re.compile(r"^\\d+$")
""")
        temp_path = f.name

    try:
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", temp_path],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"},
            cwd=str(Path(__file__).parent.parent),
        )

        # Should succeed
        assert result.returncode == 0

        # Should not find vulnerabilities
        assert "VULNERABLE" not in result.stdout
    finally:
        os.unlink(temp_path)
