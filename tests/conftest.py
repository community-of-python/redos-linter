import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def sample_vulnerable_file() -> Generator[str, None, None]:
    """Create a temporary file with vulnerable regex patterns."""
    content = """
import re

# Vulnerable patterns
v1 = re.compile(r"(a+)+")  # nested quantifiers
v2 = re.compile(r"([a-z]+)+$")  # nested quantifiers with end anchor

# Safe patterns
s1 = re.compile(r"^[a-zA-Z0-9_]+$")  # simple character class
s2 = re.compile(r"^a+$")  # simple quantifier without nesting
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    Path(temp_path).unlink()


@pytest.fixture
def sample_safe_file() -> Generator[str, None, None]:
    """Create a temporary file with only safe regex patterns."""
    content = """
import re

# All safe patterns
email = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")
simple = re.compile(r"^[a-z]+$")
choices = re.compile(r"^(cat|dog|bird)$")
numbers = re.compile(r"^\\d+$")
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    Path(temp_path).unlink()


@pytest.fixture
def temp_directory() -> Generator[Path, None, None]:
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create various test files
        (tmp_path / "vulnerable.py").write_text("""
import re
bad = re.compile(r"(a+)+")
""")

        (tmp_path / "safe.py").write_text("""
import re
good = re.compile(r"^[a-z]+$")
""")

        (tmp_path / "empty.py").write_text("")

        # Create subdirectory
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.py").write_text("""
import re
nested_bad = re.compile(r"([a-z]+)+$")
""")

        # Create directories to be ignored
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "ignore.py").write_text("import re")

        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "also_ignore.py").write_text("import re")

        yield tmp_path
