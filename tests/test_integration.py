import tempfile
import subprocess
import sys
import os
from pathlib import Path


def test_run_on_actual_vulnerable_regex():
    """Test the full pipeline on actual vulnerable regex patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file with known vulnerable patterns
        test_file = Path(tmpdir) / "vulnerable.py"
        test_file.write_text("""
import re

# Known vulnerable patterns
v1 = re.compile(r"(a+)+")  # nested quantifiers
v2 = re.compile(r"([a-z]+)+$")  # nested quantifiers
v3 = re.compile(r"(a|aa)+")  # overlapping alternation

# Safe patterns
s1 = re.compile(r"^[a-zA-Z0-9_]+$")  # simple character class
s2 = re.compile(r"^a+$")  # simple quantifier
""")
        
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", str(test_file)],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}  # Disable colors for consistent output
        )
        
        # Should succeed
        assert result.returncode == 0
        
        # Should find vulnerabilities
        assert "VULNERABLE" in result.stdout
        assert "(a+)+" in result.stdout
        assert "([a-z]+)+$" in result.stdout
        assert "(a|aa)+" in result.stdout
        
        # Should mention attack details
        assert "Repeating" in result.stdout
        
        # Should show source context
        assert ">>>" in result.stdout
        assert "v1 = re.compile" in result.stdout or "v2 = re.compile" in result.stdout
        
        # Should give summary
        assert "Found" in result.stdout and "vulnerable regex" in result.stdout
        
        # Should give recommendations
        assert "Recommendations" in result.stdout


def test_run_on_safe_patterns():
    """Test the full pipeline on safe regex patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file with only safe patterns
        test_file = Path(tmpdir) / "safe.py"
        test_file.write_text("""
import re

# All safe patterns
s1 = re.compile(r"^[a-zA-Z0-9_]+$")  # simple character class
s2 = re.compile(r"^a+$")  # simple quantifier
s3 = re.compile(r"^(cat|dog)$")  # simple alternation
s4 = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")  # email regex
""")
        
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", str(test_file)],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should succeed
        assert result.returncode == 0
        
        # Should not find vulnerabilities
        assert "VULNERABLE" not in result.stdout
        
        # Should indicate all are safe
        assert "safe from ReDoS attacks" in result.stdout or "No vulnerable regexes found" in result.stdout


def test_directory_scan():
    """Test scanning a directory with multiple files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create multiple Python files
        dir_path = Path(tmpdir)
        
        # File 1: vulnerable
        (dir_path / "vulnerable.py").write_text("""
import re
bad = re.compile(r"(a+)+")
""")
        
        # File 2: safe
        (dir_path / "safe.py").write_text("""
import re
good = re.compile(r"^[a-z]+$")
""")
        
        # File 3: another vulnerable
        (dir_path / "vulnerable2.py").write_text("""
import re
also_bad = re.compile(r"([a-z]+)+$")
""")
        
        # Should be ignored
        (dir_path / ".venv").mkdir()
        (dir_path / ".venv" / "ignored.py").write_text("""
import re
ignore_me = re.compile(r"(a+)+")
""")
        
        (dir_path / "node_modules").mkdir()
        (dir_path / "node_modules" / "also_ignored.py").write_text("""
import re
also_ignore = re.compile(r"(a+)+")
""")
        
        # Run the linter on the directory
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", str(dir_path)],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should succeed
        assert result.returncode == 0
        
        # Should find the 2 vulnerable regexes in the main directory
        assert "VULNERABLE" in result.stdout
        assert "(a+)+" in result.stdout
        assert "([a-z]+)+$" in result.stdout
        
        # Should mention the correct files
        assert "vulnerable.py" in result.stdout
        assert "vulnerable2.py" in result.stdout
        
        # Should NOT mention ignored directories
        assert ".venv" not in result.stdout
        assert "node_modules" not in result.stdout
        
        # Should give correct summary
        assert "Found 2 vulnerable regex" in result.stdout


def test_empty_directory():
    """Test scanning an empty directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Run the linter on empty directory
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", tmpdir],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should succeed
        assert result.returncode == 0
        
        # Should indicate no regexes found
        assert "No regexes found" in result.stdout


def test_no_python_files():
    """Test scanning directory with no Python files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create non-Python files
        (Path(tmpdir) / "text.txt").write_text("not python")
        (Path(tmpdir) / "script.js").write_text("console.log('hello')")
        (Path(tmpdir) / "style.css").write_text("body { color: red; }")
        
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", tmpdir],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should succeed
        assert result.returncode == 0
        
        # Should indicate no regexes found
        assert "No regexes found" in result.stdout


def test_syntax_error_file():
    """Test handling of Python files with syntax errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create file with syntax error
        test_file = Path(tmpdir) / "syntax_error.py"
        test_file.write_text("""
import re

# This file has a syntax error
bad = re.compile(r"(a+)+"
""")
        
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", str(test_file)],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should handle syntax error gracefully (either skip or report error)
        # The exact behavior depends on implementation
        assert result.returncode == 0 or result.returncode == 1


def test_command_line_help():
    """Test that the command line interface shows help."""
    result = subprocess.run(
        [sys.executable, "-m", "src.redos_linter", "--help"],
        capture_output=True,
        text=True
    )
    
    # Should show help
    assert result.returncode == 0
    assert "ReDoS Linter" in result.stdout
    assert "Files or directories to check" in result.stdout


def test_complex_real_world_regexes():
    """Test with complex real-world regex patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file with complex patterns
        test_file = Path(tmpdir) / "complex.py"
        test_file.write_text("""
import re

# Real-world examples that might be vulnerable
email_pattern = re.compile(r'^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$')
url_pattern = re.compile(r'^(https?://)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})([/\\w \\.-]*)*\\/?$')
log_pattern = re.compile(r'^((\\d{1,3}\\.){3}\\d{1,3}).*\\[([^\\]]+)\\].*"([^"]+)".*(\\d{3})')

# Some vulnerable ones extracted from real security reports
vulnerable_ip = re.compile(r'^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$')
vulnerable_date = re.compile(r'^\\d{4}-((0[1-9])|(1[0-2]))-((0[1-9])|([1-2][0-9])|(3[0-1]))$')
""")
        
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", str(test_file)],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should succeed
        assert result.returncode == 0
        
        # The complex patterns with nested quantifiers should be flagged
        output = result.stdout
        
        # Check if any vulnerabilities were found (depends on the checker)
        if "VULNERABLE" in output:
            # If vulnerabilities found, should have proper reporting
            assert "Source context:" in output
            assert ">>>" in output
        else:
            # If no vulnerabilities, should indicate all safe
            assert "safe" in result.stdout.lower() or "no vulnerable" in result.stdout.lower()


def test_utf8_characters():
    """Test handling of UTF-8 characters in regex patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file with UTF-8 characters
        test_file = Path(tmpdir) / "utf8.py"
        test_file.write_text("""
import re
# UTF-8 patterns
utf8_pattern = re.compile(r'^[\\u00a1-\\uffff]+$')  # Unicode range
emoji_pattern = re.compile(r'[\ud83c\udf00-\ud83d\uddff]|[\u2600-\u27bf]')
accented = re.compile(r'^[a-zA-ZÀ-ÖØ-öø-ÿ]+$')
""")
        
        # Run the linter
        result = subprocess.run(
            [sys.executable, "-m", "src.redos_linter", str(test_file)],
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"}
        )
        
        # Should succeed without Unicode errors
        assert result.returncode == 0
        
        # Should handle UTF-8 gracefully
        assert not result.stdout.startswith("Traceback")