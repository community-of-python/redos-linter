from pathlib import Path

import pytest

from redos_linter import extract_regexes_from_file, get_source_context


REGEX_EXTRACT_LINE = 4
REGEX_EXTRACT_COUNT_4 = 4
REGEX_EXTRACT_COUNT_9 = 9
REGEX_EXTRACT_COUNT_3 = 3
REGEX_EXTRACT_COUNT_5 = 5
REGEX_EXTRACT_COUNT_1 = 1
REGEX_EXTRACT_COUNT_2 = 2


class TestRegexExtractor:
    def test_extract_simple_regex(self, tmp_path: Path) -> None:
        """Test extracting a simple regex from a Python file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import re

pattern = "test.*"
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 1
        assert regexes[0]["regex"] == "test.*"
        assert regexes[0]["line"] == REGEX_EXTRACT_LINE
        assert "source_lines" in regexes[0]

    def test_extract_multiple_regexes(self, tmp_path: Path) -> None:
        """Test extracting multiple regexes from a Python file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
# Simple strings that look like regexes
pattern1 = "a+b+"
pattern2 = ".*test.*"
""")
        regexes = extract_regexes_from_file(str(test_file))
        # Only strings that look like regexes should be detected
        assert len(regexes) == REGEX_EXTRACT_COUNT_2
        patterns = [r["regex"] for r in regexes]
        assert "a+b+" in patterns
        assert ".*test.*" in patterns

    def test_extract_all_re_functions(self, tmp_path: Path) -> None:
        """Test that regex-like strings are detected regardless of context."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
# These should be detected as they look like regexes
vuln_pattern = "(a+)+"
safe_pattern = "a+b+"
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == REGEX_EXTRACT_COUNT_2

    def test_ignore_non_string_constants(self, tmp_path: Path) -> None:
        """Test that non-regex strings are ignored."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
# These should NOT be detected as they don't look like regexes
name = "John Doe"
message = "Hello world"
number = "123"
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 0

    @pytest.mark.parametrize(
        "literal",
        ["*/10 * * * *", "0 2 * * *", 'schedule: "*/10 * * * *"', 'schedule: "0 2 * * *"'],
    )
    @pytest.mark.parametrize("operator", ["in", "not in"])
    def test_ignore_literal_membership_checks(self, tmp_path: Path, literal: str, operator: str) -> None:
        """Cron text in membership checks is not interpreted as a regex."""
        test_file = tmp_path / "test.py"
        test_file.write_text(f"assert {literal!r} {operator} content\n")

        assert extract_regexes_from_file(str(test_file)) == []

    @pytest.mark.parametrize(
        "source",
        [
            'assert value in "0 2 * * *"',
            'assert "0 2 * * *" in content in documents',
            'assert value in "0 2 * * *" not in content',
            'found = "0 2 * * *" in content',
        ],
    )
    def test_ignore_membership_literals_in_other_positions(self, tmp_path: Path, source: str) -> None:
        """Literal needles and haystacks are also text in chained comparisons."""
        test_file = tmp_path / "test.py"
        test_file.write_text(source)

        assert extract_regexes_from_file(str(test_file)) == []

    @pytest.mark.parametrize(
        "source",
        [
            'pattern = "0 2 * * *"',
            'compiled = re.compile("0 2 * * *")',
            'assert re.search("0 2 * * *", content)',
            'assert re.compile("0 2 * * *") in patterns',
            'assert "text" not in re.findall("0 2 * * *", content)',
            'assert (pattern := "0 2 * * *") in patterns',
            'assert value in ["0 2 * * *"]',
            'assert "0 2 * * *" == pattern in patterns',
        ],
    )
    def test_preserve_potential_regexes_around_membership_checks(self, tmp_path: Path, source: str) -> None:
        """Keep scanning calls, assignments, containers, and unrelated comparisons."""
        test_file = tmp_path / "test.py"
        test_file.write_text(source)

        regexes = extract_regexes_from_file(str(test_file))

        assert [regex["regex"] for regex in regexes] == ["0 2 * * *"]

    def test_ignore_non_re_calls(self, tmp_path: Path) -> None:
        """Test that normal strings are ignored."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
# These should NOT be detected
normal_string = "This is just text"
another_string = "No regex patterns here"
# This SHOULD be detected
regex_string = "a+b+"
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 1
        assert regexes[0]["regex"] == "a+b+"

    def test_nested_quantifiers_detection(self, tmp_path: Path) -> None:
        """Test that regexes with nested quantifiers are extracted."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
# Various patterns - only those that look like regexes should be detected
vuln1 = "(a+)+"
vuln2 = "(a*)*"
vuln3 = "(a?)+"
safe_pattern = "^[a-zA-Z]+$"
# These should NOT be detected
normal_text = "This is normal text"
""")
        regexes = extract_regexes_from_file(str(test_file))
        # All 4 regex-like patterns should be detected
        assert len(regexes) == REGEX_EXTRACT_COUNT_4
        patterns = [r["regex"] for r in regexes]
        assert "(a+)+" in patterns
        assert "(a*)*" in patterns
        assert "(a?)+" in patterns
        assert "^[a-zA-Z]+$" in patterns

    def test_source_context_generation(self) -> None:
        """Test that source context is correctly generated."""
        lines = [
            "line 1",
            "line 2",
            "line 3",  # target line
            "line 4",
            "line 5",
        ]
        context = get_source_context(lines, 3, context=2)

        assert len(context) == REGEX_EXTRACT_COUNT_5
        assert ">>>   3: line 3" in context
        assert "      2: line 2" in context
        assert "      4: line 4" in context

    def test_source_context_at_beginning(self) -> None:
        """Test source context when target line is near the beginning."""
        lines = [
            "line 1",
            "line 2",  # target line
            "line 3",
            "line 4",
        ]
        context = get_source_context(lines, 2, context=2)

        assert len(context) == REGEX_EXTRACT_COUNT_4
        assert ">>>   2: line 2" in context

    def test_source_context_at_end(self) -> None:
        """Test source context when target line is near the end."""
        lines = [
            "line 1",
            "line 2",
            "line 3",  # target line
        ]
        context = get_source_context(lines, 3, context=2)

        assert len(context) == REGEX_EXTRACT_COUNT_3
        assert ">>>   3: line 3" in context

    def test_column_tracking(self, tmp_path: Path) -> None:
        """Test that column positions are correctly tracked."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
pattern = "test.*"
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == REGEX_EXTRACT_COUNT_1
        # Column should point to the start of the string
        assert regexes[0]["col"] > 0

    def test_raw_strings(self, tmp_path: Path) -> None:
        """Test that different string types are extracted."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
pattern1 = "a+b+"           # Simple string
pattern2 = ".*test.*"       # String with regex chars
pattern3 = "(a|b)*"         # Complex regex
""")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == REGEX_EXTRACT_COUNT_3  # Should extract all 3 regex-like patterns
        for r in regexes:
            assert "regex" in r
            assert "line" in r
            assert "source_lines" in r

    def test_empty_file(self, tmp_path: Path) -> None:
        """Test handling of empty Python files."""
        test_file = tmp_path / "empty.py"
        test_file.write_text("")
        regexes = extract_regexes_from_file(str(test_file))
        assert len(regexes) == 0

    def test_syntax_error_handling(self, tmp_path: Path) -> None:
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
