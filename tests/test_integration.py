import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("source", "vulnerable_count"),
    [
        (
            """
assert 'schedule: "*/10 * * * *"' in content
assert 'schedule: "0 2 * * *"' in content
""",
            0,
        ),
        ("""assert re.compile('schedule: "0 2 * * *"') in patterns""", 1),
    ],
)
def test_cron_text_and_regex_membership_checks(tmp_path: Path, source: str, vulnerable_count: int) -> None:
    """Skip literal membership text while still analyzing nested regex calls."""
    test_file = tmp_path / "membership.py"
    test_file.write_text(source)

    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "redos_linter", str(test_file)],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
        check=False,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.count("VULNERABLE:") == vulnerable_count
    if vulnerable_count == 0:
        assert "No vulnerable regexes found." in result.stdout
    else:
        assert 'Pattern: schedule: "0 2 * * *"' in result.stdout


def test_help_command() -> None:
    """Test that the command line interface shows help."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "redos_linter", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent.parent,  # Project root
        check=False,
    )

    # Should show help
    assert result.returncode == 0
    assert "ReDoS Linter" in result.stdout


def test_run_on_existing_test_file() -> None:
    """Test running on the existing test.py file."""
    test_file = Path(__file__).parent / "test.py"

    # Run the linter
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "redos_linter", str(test_file)],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
        cwd=Path(__file__).parent.parent.parent,  # Project root
        check=False,
    )

    # Should succeed
    assert result.returncode == 0

    # Should find vulnerabilities in test.py
    assert "VULNERABLE" in result.stdout, result.stderr
    assert "Found" in result.stdout, result.stderr
    assert "vulnerable" in result.stdout, result.stderr


def test_run_on_safe_file() -> None:
    """Test running on a file with only safe patterns."""
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
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "redos_linter", temp_path],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"},
            cwd=Path(__file__).parent.parent.parent,  # Project root
            check=False,
        )

        # Should succeed
        assert result.returncode == 0

        # Should not find vulnerabilities
        assert "VULNERABLE" not in result.stdout
    finally:
        Path(temp_path).unlink()
