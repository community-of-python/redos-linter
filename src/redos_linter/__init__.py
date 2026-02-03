import argparse
import ast
import json
import os
import subprocess
import sys
from pathlib import Path


try:
    import deno  # type: ignore[import-untyped]
except ImportError:
    deno = None


# ANSI color codes for better output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def use_colors() -> bool:
    """Check if colors should be used (TTY and not disabled by environment)."""
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def get_deno_path() -> str:
    python_executable = sys.executable
    bin_dir = Path(python_executable).parent
    deno_path = bin_dir / "deno"
    if deno_path.exists():
        return str(deno_path)

    if deno is None:
        raise FileNotFoundError("Could not find the deno executable: deno package not installed")

    deno_dir = Path(deno.__file__).parent
    deno_path = deno_dir / "bin" / "deno"
    if deno_path.exists():
        return str(deno_path)

    raise FileNotFoundError("Could not find the deno executable.")


class RegexExtractor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.regexes: list[dict[str, int | str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr
                in (
                    "compile",
                    "search",
                    "match",
                    "fullmatch",
                    "split",
                    "findall",
                    "finditer",
                    "sub",
                    "subn",
                )
            )
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            self.regexes.append(
                {
                    "regex": node.args[0].value,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )
        self.generic_visit(node)


def extract_regexes_from_file(filepath: str) -> list[dict]:
    with Path(filepath).open() as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath)
    extractor = RegexExtractor()
    extractor.visit(tree)

    lines = code.splitlines()
    for regex_info in extractor.regexes:
        regex_info["source_lines"] = get_source_context(lines, regex_info["line"])

    return extractor.regexes


def get_source_context(lines: list[str], line_num: int, context: int = 2) -> list[str]:
    """Get source lines with context (before and after the target line)."""
    start = max(0, line_num - context - 1)  # -1 because line_num is 1-indexed
    end = min(len(lines), line_num + context)

    context_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_num - 1 else "    "
        context_lines.append(f"{prefix}{i + 1:3d}: {lines[i]}")

    return context_lines


def collect_files(paths: list[str]) -> list[str]:
    """Collect Python files from the given paths."""
    files_to_check = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files_to_check.extend(str(f) for f in path.rglob("*.py"))
        else:
            files_to_check.append(p)
    return [f for f in files_to_check if ".venv" not in f and "node_modules" not in f]


def collect_all_regexes(files: list[str]) -> list[dict]:
    """Extract all regexes from the given files."""
    regexes_with_paths = []
    for file_path in files:
        regexes = extract_regexes_from_file(file_path)
        regexes_with_paths.extend(
            {
                "regex": regex_info["regex"],
                "filePath": file_path,
                "line": regex_info["line"],
                "col": regex_info["col"],
                "source_lines": regex_info["source_lines"],
            }
            for regex_info in regexes
        )
    return regexes_with_paths


def check_regexes_with_deno(regexes: list[dict]) -> list[dict] | None:
    """Check regexes for vulnerabilities using Deno."""
    deno_path = get_deno_path()
    checker_path = Path(__file__).parent / "checker.js"
    bundle_path = Path(__file__).parent / "recheck.bundle.js"

    env = os.environ.copy()
    env["RECHECK_BACKEND"] = "pure"

    process = subprocess.run(  # noqa: S603
        [deno_path, "run", "--allow-read", str(checker_path), str(bundle_path)],
        input=json.dumps(regexes).encode("utf-8"),
        capture_output=True,
        env=env,
        check=False,
    )

    if process.stderr:
        return None

    output = process.stdout.decode("utf-8")
    if not output:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def display_results(results: list[dict]) -> None:
    """Display the check results."""
    vulnerable_count = sum(1 for r in results if r["status"] == "vulnerable")

    (Colors.RED if vulnerable_count > 0 else Colors.GREEN) if use_colors() else ""

    for result in results:
        if result["status"] == "vulnerable":
            if use_colors():
                if "sourceLines" in result:
                    for _line in result["sourceLines"]:
                        pass
            elif "sourceLines" in result:
                for _line in result["sourceLines"]:
                    pass


def main() -> None:
    """Run the ReDoS linter."""
    parser = argparse.ArgumentParser(
        description="ReDoS Linter - Detects Regular Expression Denial of Service vulnerabilities"
    )
    parser.add_argument(
        "paths",
        metavar="path",
        type=str,
        nargs="+",
        help="Files or directories to check",
    )
    args = parser.parse_args()

    files_to_check = collect_files(args.paths)
    regexes_with_paths = collect_all_regexes(files_to_check)

    if not regexes_with_paths:
        if use_colors():
            pass
        else:
            pass
        return

    results = check_regexes_with_deno(regexes_with_paths)
    if results is None:
        return

    display_results(results)


if __name__ == "__main__":
    main()
