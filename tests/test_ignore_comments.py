"""Tests for ignore comments functionality."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from redos_linter import main


class TestIgnoreComments:
    """Test cases for ignore comments functionality."""

    def test_ignore_comment_prevents_detection(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that regexes with ignore comments are not detected."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

# This should be detected
vulnerable1 = re.compile(r"(a+)+")

# This should be ignored
vulnerable2 = re.compile(r"(a|aa)+")  # redos-linter: ignore

# This should also be detected
vulnerable3 = re.compile(r"([a-z]+)+$")
""")

        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])

        # Mock the deno subprocess call to return results for the non-ignored regexes
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps(
            [
                {
                    "regex": "(a+)+",
                    "filePath": str(test_file),
                    "line": 5,
                    "col": 19,
                    "sourceLines": [
                        "   3: ",
                        "   4: # This should be detected",
                        '>>> 5: vulnerable1 = re.compile(r"(a+)+")',
                        "   6: ",
                        "   7: # This should be ignored",
                    ],
                    "status": "vulnerable",
                    "attack": {
                        "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u0000",
                        "base": 31,
                        "pumps": [{"pump": "a", "prefix": "a", "bias": 0}],
                    },
                },
                {
                    "regex": "([a-z]+)+$",
                    "filePath": str(test_file),
                    "line": 11,
                    "col": 19,
                    "sourceLines": [
                        "   9: ",
                        "  10: # This should also be detected",
                        '>>> 11: vulnerable3 = re.compile(r"([a-z]+)+$")',
                        "  12: ",
                    ],
                    "status": "vulnerable",
                    "attack": {
                        "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u0000a",
                        "base": 31,
                        "pumps": [{"pump": "a", "prefix": "a", "bias": 0}],
                    },
                },
            ]
        )
        mock_result.stderr = b""
        mock_result.returncode = 0

        with (
            patch("subprocess.run", return_value=mock_result),
            patch("sys.stdout") as mock_stdout,
        ):
            main()

        # Check that only the non-ignored regexes were reported
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        
        # Verify that "VULNERABLE" is in the output
        assert "VULNERABLE" in output
        
        # Verify that vulnerable1 (line 5) is reported
        assert "test.py:5:" in output
        assert "(a+)+" in output
        
        # Verify that vulnerable3 (line 11) is reported
        assert "test.py:11:" in output
        assert "([a-z]+)+$" in output
        
        # Verify that vulnerable2 (the ignored one) is NOT reported
        assert "test.py:8:" not in output
        assert "(a|aa)+" not in output
        
        # Should report 2 vulnerable regexes
        assert "Found 2 vulnerable regexes" in output

    def test_ignore_comment_with_safe_regex(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that safe regexes with ignore comments are also ignored."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

# This safe regex should be ignored
safe = re.compile(r"^[a-zA-Z0-9_]+$")  # redos-linter: ignore
""")

        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])

        # Mock the deno subprocess call to return no results (all ignored or safe)
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([])
        mock_result.stderr = b""
        mock_result.returncode = 0

        with (
            patch("subprocess.run", return_value=mock_result),
            patch("sys.stdout") as mock_stdout,
        ):
            main()

        # Check that no vulnerabilities were reported
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        
        # Should report no vulnerable regexes
        assert "No vulnerable regexes found" in output or "All" in output and "appear safe" in output