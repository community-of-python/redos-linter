import sys
from pathlib import Path

import pytest

from redos_linter import check_regexes_with_deno, collect_all_regexes, extract_regexes_from_file, main


@pytest.mark.parametrize(
    "source",
    [
        'configuration = "items: ["',
        'configuration = "schema: example\\nitems: ["',
        'message = f"items[{name}].entries[{index}]"',
        'message = f"prefix({value}): text"',
        'path.open("r+b")',
        'open("file.txt", "r+b")',
        'path.glob("*.txt")',
        'path.rglob("(a+)+")',
        're.escape("(a+)+")',
    ],
)
def test_literal_text_is_not_a_regex(tmp_path: Path, source: str) -> None:
    path = tmp_path / "example.py"
    path.write_text(source)

    assert extract_regexes_from_file(str(path)) == []


@pytest.mark.parametrize("source", ['re.search("plain", "(a+)+")', 're.sub("plain", "(a+)+", "subject")'])
def test_regex_call_subjects_and_replacements_are_text(tmp_path: Path, source: str) -> None:
    path = tmp_path / "example.py"
    path.write_text(source)

    assert [item["regex"] for item in extract_regexes_from_file(str(path))] == ["plain"]


@pytest.mark.parametrize(
    "source",
    [
        'pattern = "(a+)+"',
        'patterns = ["(a+)+"]',
        'pattern = f"(a+)+"',
        'path.glob(re.compile("(a+)+"))',
        "message = f\"{re.compile('(a+)+')}\"",
        'import re as expressions\nexpressions.compile("(a+)+")',
        'from re import compile as compile_pattern\ncompile_pattern("(a+)+")',
        'from regex import search\nsearch(pattern="(a+)+", string="subject")',
    ],
)
def test_preserve_standalone_and_nested_regexes(tmp_path: Path, source: str) -> None:
    path = tmp_path / "example.py"
    path.write_text(source)

    assert [item["regex"] for item in extract_regexes_from_file(str(path))] == ["(a+)+"]


@pytest.mark.parametrize(
    "source",
    [
        're.compile("*")',
        're.search(pattern="*", string="subject")',
        'import re as expressions\nexpressions.compile("*")',
        'from re import compile as compile_pattern\ncompile_pattern("*")',
    ],
)
def test_invalid_explicit_regexes_still_reach_checker(tmp_path: Path, source: str) -> None:
    path = tmp_path / "example.py"
    path.write_text(source)

    assert [item["regex"] for item in extract_regexes_from_file(str(path))] == ["*"]


@pytest.mark.parametrize("count", [1, 8])
@pytest.mark.parametrize("pattern", ["(?m)^prefix$", "(?s)^a.b$", "(?m)(?s)^a.b$"])
def test_global_modes_are_checked_in_inline_and_worker_paths(tmp_path: Path, count: int, pattern: str) -> None:
    path = tmp_path / "example.py"
    path.write_text(f"pattern = {pattern!r}\n" * count)

    results = check_regexes_with_deno(collect_all_regexes([str(path)]))

    assert results is not None
    assert len(results) == count
    assert all(result["status"] == "safe" for result in results)
    assert all(result["regex"] == pattern for result in results)


@pytest.mark.parametrize("count", [1, 8])
def test_global_modes_preserve_vulnerability_detection(tmp_path: Path, count: int) -> None:
    path = tmp_path / "example.py"
    path.write_text('pattern = "(?m)^(a+)+$"\n' * count)

    results = check_regexes_with_deno(collect_all_regexes([str(path)]))

    assert results is not None
    assert len(results) == count
    assert all(result["status"] == "vulnerable" for result in results)


def test_explicit_regex_fstring_still_detects_vulnerable_fragment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "example.py"
    path.write_text('import re\npattern = re.compile(f"^{prefix}(a+)+$")\n')
    monkeypatch.setattr(sys, "argv", ["redos-linter", str(path)])

    assert main() == 1
    assert "VULNERABLE" in capsys.readouterr().out


def test_explicit_regex_fstring_keeps_unclassified_fragments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "example.py"
    path.write_text('import re\npattern = re.compile(f"[{prefix}]")\n')
    monkeypatch.setattr(sys, "argv", ["redos-linter", str(path)])

    assert main() == 2  # noqa: PLR2004 -- An incomplete explicit regex must not pass.
    assert "could not classify every regex" in capsys.readouterr().err


@pytest.mark.parametrize("pattern", ["*", "(?i)^prefix$", "(?x)^prefix$", "(?m:prefix)"])
def test_invalid_and_unsupported_explicit_patterns_still_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], pattern: str
) -> None:
    path = tmp_path / "example.py"
    path.write_text(f"import re\npattern = re.compile({pattern!r})\n")
    monkeypatch.setattr(sys, "argv", ["redos-linter", str(path)])

    assert main() == 2  # noqa: PLR2004 -- Unclassified patterns must fail the check.
    assert "could not classify every regex" in capsys.readouterr().err
