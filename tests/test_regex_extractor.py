import ast
import pytest
from src.redos_linter import extract_regexes_from_file, get_source_context


class TestRegexExtractor:
    def test_extract_simple_regex(self, tmp_path):
        """Test extracting a simple regex from a Python file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

pattern = re.compile(r"test.*")
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 1
        assert regexes[0]['regex'] == "test.*"
        assert regexes[0]['line'] == 4
        assert 'source_lines' in regexes[0]

    def test_extract_multiple_regexes(self, tmp_path):
        """Test extracting multiple regexes from a Python file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

r1 = re.compile(r"pattern1")
r2 = re.search(r"pattern2", text)
r3 = re.match(r"pattern3", text)
r4 = re.findall(r"pattern4", text)
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 4
        patterns = [r['regex'] for r in regexes]
        assert "pattern1" in patterns
        assert "pattern2" in patterns
        assert "pattern3" in patterns
        assert "pattern4" in patterns

    def test_extract_all_re_functions(self, tmp_path):
        """Test extracting from all supported re module functions."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

r1 = re.compile(r"test")
r2 = re.search(r"test", s)
r3 = re.match(r"test", s)
r4 = re.fullmatch(r"test", s)
r5 = re.split(r"test", s)
r6 = re.findall(r"test", s)
r7 = re.finditer(r"test", s)
r8 = re.sub(r"test", "replace", s)
r9 = re.subn(r"test", "replace", s)
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 9

    def test_ignore_non_string_constants(self, tmp_path):
        """Test that non-string regex patterns are ignored."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

pattern = "not a re call"
variable = r"raw string but not re call"
r1 = re.compile(variable)  # Should be ignored - not a constant
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 0

    def test_ignore_non_re_calls(self, tmp_path):
        """Test that non-re module calls are ignored."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re
import other_module

r1 = other_module.compile(r"test")  # Should be ignored
r2 = re.compile(r"test")  # Should be extracted
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 1
        assert regexes[0]['regex'] == "test"

    def test_nested_quantifiers_detection(self, tmp_path):
        """Test that regexes with nested quantifiers are extracted."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

# Various vulnerable patterns
r1 = re.compile(r"(a+)+")  # nested quantifiers
r2 = re.compile(r"(a*)*")  # nested quantifiers
r3 = re.compile(r"(a?)+")  # nested quantifiers
r4 = re.compile(r"^[a-zA-Z]+$")  # safe pattern
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 4
        patterns = [r['regex'] for r in regexes]
        assert "(a+)+" in patterns
        assert "(a*)*" in patterns
        assert "(a?)+" in patterns
        assert "^[a-zA-Z]+$" in patterns

    def test_source_context_generation(self):
        """Test that source context is correctly generated."""
        lines = [
            "line 1",
            "line 2",
            "line 3",  # target line
            "line 4",
            "line 5"
        ]
        context = get_source_context(lines, 3, context=2)
        
        assert len(context) == 5
        assert ">>>   3: line 3" in context
        assert "    2: line 2" in context
        assert "    4: line 4" in context

    def test_source_context_at_beginning(self):
        """Test source context when target line is near the beginning."""
        lines = [
            "line 1",
            "line 2",  # target line
            "line 3",
            "line 4"
        ]
        context = get_source_context(lines, 2, context=2)
        
        assert len(context) == 4
        assert ">>>   2: line 2" in context

    def test_source_context_at_end(self):
        """Test source context when target line is near the end."""
        lines = [
            "line 1",
            "line 2", 
            "line 3",  # target line
        ]
        context = get_source_context(lines, 3, context=2)
        
        assert len(context) == 3
        assert ">>>   3: line 3" in context

    def test_column_tracking(self, tmp_path):
        """Test that column positions are correctly tracked."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

x = re.compile(r"test")
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 1
        # Column should point to the start of the string argument
        assert regexes[0]['col'] > 0

    def test_raw_strings(self, tmp_path):
        """Test that raw strings are correctly handled."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

r1 = re.compile(r"raw\\string")
r2 = re.compile("normal\\string")
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 2
        assert regexes[0]['regex'] == "raw\\\\string"
        assert regexes[1]['regex'] == "normal\\\\string"

    def test_empty_file(self, tmp_path):
        """Test handling of empty Python files."""
        test_file = tmp_path / "empty.py"
        test_file.write_text("")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 0

    def test_syntax_error_handling(self, tmp_path):
        """Test that files with syntax errors are handled gracefully."""
        test_file = tmp_path / "syntax_error.py"
        test_file.write_text("""
import re

# This has a syntax error
re.compile(r"test"
""")
        # Should raise SyntaxError which should be handled by the caller
        with pytest.raises(SyntaxError):
            extract_regexes_from_file(str(test_file))