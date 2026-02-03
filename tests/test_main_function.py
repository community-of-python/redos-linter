import json
import subprocess
import tempfile
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from src.redos_linter import main, get_deno_path


class TestMainFunction:
    def test_no_files_to_check(self, tmp_path, monkeypatch):
        """Test when no Python files are found."""
        monkeypatch.setattr("sys.argv", ["redos-linter", str(tmp_path)])
        
        # Create empty directory
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        with patch("sys.stdout") as mock_stdout:
            main()
            
        # Should print "No regexes found" message
        mock_stdout.write.assert_called()
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "No regexes found" in output or "No vulnerable regexes found" in output

    def test_single_vulnerable_file(self, tmp_path, monkeypatch):
        """Test with a single file containing a vulnerable regex."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

vulnerable = re.compile(r"(a+)+")
""")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])
        
        # Mock the deno subprocess call to return a vulnerable result
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([{
            "regex": "(a+)+",
            "filePath": str(test_file),
            "line": 4,
            "col": 18,
            "sourceLines": [
                "   2: ",
                "   3: import re",
                ">>> 4: vulnerable = re.compile(r\"(a+)+\")",
                "   5: ",
            ],
            "status": "vulnerable",
            "attack": {
                "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u0000",
                "base": 31,
                "pumps": [{"pump": "a", "prefix": "a", "bias": 0}]
            }
        }])
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stdout") as mock_stdout:
                main()
        
        # Check that vulnerable regex was reported
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "VULNERABLE" in output
        assert "(a+)+" in output
        assert "Repeating \"a\"" in output

    def test_safe_regex_only(self, tmp_path, monkeypatch):
        """Test with only safe regexes."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

safe = re.compile(r"^[a-zA-Z0-9]+$")
""")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])
        
        # Mock the deno subprocess call to return safe results
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([{
            "regex": "^[a-zA-Z0-9]+$",
            "filePath": str(test_file),
            "line": 4,
            "col": 14,
            "sourceLines": [
                "   2: ",
                "   3: import re",
                ">>> 4: safe = re.compile(r\"^[a-zA-Z0-9]+$\")",
                "   5: ",
            ],
            "status": "safe",
            "attack": None
        }])
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stdout") as mock_stdout:
                main()
        
        # Check that no vulnerabilities were reported
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "VULNERABLE" not in output
        assert "appear safe" in output or "No vulnerable regexes found" in output

    def test_mixed_safe_and_vulnerable(self, tmp_path, monkeypatch):
        """Test with both safe and vulnerable regexes."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

safe1 = re.compile(r"^[a-z]+$")
vulnerable = re.compile(r"(a+)+")
safe2 = re.compile(r"^[A-Z]+$")
""")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])
        
        # Mock the deno subprocess call to return mixed results
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([
            {
                "regex": "^[a-z]+$",
                "filePath": str(test_file),
                "line": 4,
                "col": 12,
                "sourceLines": [">>> 4: safe1 = re.compile(r\"^[a-z]+$\")"],
                "status": "safe",
                "attack": None
            },
            {
                "regex": "(a+)+",
                "filePath": str(test_file),
                "line": 5,
                "col": 18,
                "sourceLines": [">>> 5: vulnerable = re.compile(r\"(a+)+$\")"],
                "status": "vulnerable",
                "attack": {
                    "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u0000",
                    "base": 31,
                    "pumps": [{"pump": "a", "prefix": "a", "bias": 0}]
                }
            },
            {
                "regex": "^[A-Z]+$",
                "filePath": str(test_file),
                "line": 6,
                "col": 12,
                "sourceLines": [">>> 6: safe2 = re.compile(r\"^[A-Z]+$\")"],
                "status": "safe",
                "attack": None
            }
        ])
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stdout") as mock_stdout:
                main()
        
        # Check that only the vulnerable regex was reported
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "VULNERABLE" in output
        assert "(a+)+" in output
        assert "Found 1 vulnerable regex" in output

    def test_directory_scan(self, tmp_path, monkeypatch):
        """Test scanning a directory with multiple Python files."""
        # Create multiple Python files
        (tmp_path / "file1.py").write_text("import re\nr1 = re.compile(r'(a+)+')")
        (tmp_path / "file2.py").write_text("import re\nr2 = re.compile(r'^(test)+$')")
        (tmp_path / "not_python.txt").write_text("not a python file")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "should_be_ignored.py").write_text("import re\nr3 = re.compile(r'ignored')")
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "also_ignored.py").write_text("import re\nr4 = re.compile(r'also ignored')")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(tmp_path)])
        
        # Mock the deno subprocess call
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([
            {
                "regex": "(a+)+",
                "filePath": str(tmp_path / "file1.py"),
                "line": 2,
                "col": 14,
                "sourceLines": [">>> 2: r1 = re.compile(r'(a+)+')"],
                "status": "vulnerable",
                "attack": {
                    "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u0000",
                    "base": 31,
                    "pumps": [{"pump": "a", "prefix": "a", "bias": 0}]
                }
            },
            {
                "regex": "^(test)+$",
                "filePath": str(tmp_path / "file2.py"),
                "line": 2,
                "col": 14,
                "sourceLines": [">>> 2: r2 = re.compile(r'^(test)+$')"],
                "status": "vulnerable",
                "attack": {
                    "string": "test" * 31 + "\u0000",
                    "base": 31,
                    "pumps": [{"pump": "test", "prefix": "test", "bias": 0}]
                }
            }
        ])
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stdout") as mock_stdout:
                main()
        
        # Check that both files were scanned but .venv and node_modules were ignored
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "file1.py" in output
        assert "file2.py" in output
        assert "Found 2 vulnerable regexes" in output

    def test_json_decode_error(self, tmp_path, monkeypatch):
        """Test handling of invalid JSON from the checker."""
        test_file = tmp_path / "test.py"
        test_file.write_text("import re\nr = re.compile(r'test')")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])
        
        # Mock the deno subprocess call to return invalid JSON
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = "invalid json output"
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stderr") as mock_stderr:
                main()
        
        # Should print error message
        mock_stderr.write.assert_called()
        calls = [str(call) for call in mock_stderr.write.call_args_list]
        output = "".join(calls)
        assert "Error" in output
        assert "Invalid response" in output

    def test_subprocess_error(self, tmp_path, monkeypatch):
        """Test handling of subprocess errors."""
        test_file = tmp_path / "test.py"
        test_file.write_text("import re\nr = re.compile(r'test')")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])
        
        # Mock the deno subprocess call to return an error
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = ""
        mock_result.stderr = b"Something went wrong"
        mock_result.returncode = 1
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stderr") as mock_stderr:
                main()
        
        # Should print error message
        mock_stderr.write.assert_called()
        calls = [str(call) for call in mock_stderr.write.call_args_list]
        output = "".join(calls)
        assert "Error" in output
        assert "Something went wrong" in output

    def test_multiple_paths(self, tmp_path, monkeypatch):
        """Test scanning multiple file/directory paths."""
        file1 = tmp_path / "file1.py"
        file1.write_text("import re\nr1 = re.compile(r'(a+)+')")
        
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        file2 = subdir / "file2.py"
        file2.write_text("import re\nr2 = re.compile(r'^(test)+$')")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(file1), str(subdir)])
        
        # Mock the deno subprocess call
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([
            {
                "regex": "(a+)+",
                "filePath": str(file1),
                "line": 2,
                "col": 14,
                "sourceLines": [">>> 2: r1 = re.compile(r'(a+)+')"],
                "status": "vulnerable",
                "attack": {
                    "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u0000",
                    "base": 31,
                    "pumps": [{"pump": "a", "prefix": "a", "bias": 0}]
                }
            },
            {
                "regex": "^(test)+$",
                "filePath": str(file2),
                "line": 2,
                "col": 14,
                "sourceLines": [">>> 2: r2 = re.compile(r'^(test)+$')"],
                "status": "vulnerable",
                "attack": {
                    "string": "test" * 31 + "\u0000",
                    "base": 31,
                    "pumps": [{"pump": "test", "prefix": "test", "bias": 0}]
                }
            }
        ])
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stdout") as mock_stdout:
                main()
        
        # Should check both paths
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "file1.py" in output
        assert "file2.py" in output

    def test_color_output_disabled(self, tmp_path, monkeypatch):
        """Test that colors are disabled when NO_COLOR is set."""
        test_file = tmp_path / "test.py"
        test_file.write_text("import re\nr = re.compile(r'^(test)+$')")
        
        monkeypatch.setattr("sys.argv", ["redos-linter", str(test_file)])
        monkeypatch.setenv("NO_COLOR", "1")
        
        # Mock the deno subprocess call
        mock_result = MagicMock()
        mock_result.stdout.decode.return_value = json.dumps([{
            "regex": "^(test)+$",
            "filePath": str(test_file),
            "line": 2,
            "col": 14,
            "sourceLines": [">>> 2: r = re.compile(r'^(test)+$')"],
            "status": "vulnerable",
            "attack": {
                "string": "test" * 31 + "\u0000",
                "base": 31,
                "pumps": [{"pump": "test", "prefix": "test", "bias": 0}]
            }
        }])
        mock_result.stderr = b""
        mock_result.returncode = 0
        
        with patch("subprocess.run", return_value=mock_result):
            with patch("sys.stdout") as mock_stdout:
                main()
        
        # Check no ANSI color codes are in output
        calls = [str(call) for call in mock_stdout.write.call_args_list]
        output = "".join(calls)
        assert "\033[" not in output  # ANSI escape sequence


class TestDenoPath:
    def test_get_deno_path_exists(self):
        """Test that get_deno_path can find deno when it exists."""
        # This test will only pass if deno is installed in the expected location
        try:
            path = get_deno_path()
            assert path is not None
            assert os.path.exists(path)
        except FileNotFoundError:
            pytest.skip("Deno not installed in expected location")

    def test_get_deno_path_not_found(self):
        """Test that get_deno_path raises FileNotFoundError when deno is not found."""
        with patch("sys.executable", "/nonexistent/python"):
            with patch("deno.__file__", "/nonexistent/deno/__init__.py"):
                with pytest.raises(FileNotFoundError):
                    get_deno_path()