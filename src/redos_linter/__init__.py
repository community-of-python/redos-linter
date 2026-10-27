import argparse
import ast
import json
import os
import re
import subprocess
import sys
import warnings
from pathlib import Path
from typing import TypedDict, cast

import deno  # type: ignore[import-untyped]


# Minimum length for a string to be considered a potential regex
MIN_REGEX_LENGTH = 2
REGEX_FUNCTIONS = {"compile", "search", "match", "fullmatch", "findall", "finditer", "split", "sub", "subn"}
TEXT_METHODS = {"glob", "rglob", "open"}


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


class RegexInfo(TypedDict):
    regex: str
    line: int
    col: int


class RegexExtractor(ast.NodeVisitor):
    def __init__(self, lines: list[str], filename: str = "<unknown>") -> None:
        self.regexes: list[RegexInfo] = []
        self.lines = lines
        self.filename = filename
        self.regex_modules = {"re", "regex"}
        self.regex_functions: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        self.regex_modules.update(alias.asname or alias.name for alias in node.names if alias.name in {"re", "regex"})

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"re", "regex"}:
            self.regex_functions.update(
                (alias.asname or alias.name, alias.name)
                for alias in node.names
                if alias.name in REGEX_FUNCTIONS | {"escape"}
            )

    def visit_Call(self, node: ast.Call) -> None:
        regex_function = self._regex_function(node.func)
        text_call = (isinstance(node.func, ast.Name) and node.func.id == "open") or (
            isinstance(node.func, ast.Attribute) and node.func.attr in TEXT_METHODS
        )
        self.visit(node.func)
        arguments = [(index == 0, argument) for index, argument in enumerate(node.args)]
        arguments.extend((keyword.arg == "pattern", keyword.value) for keyword in node.keywords)
        for pattern_argument, argument in arguments:
            if regex_function in REGEX_FUNCTIONS and pattern_argument:
                self._visit_regex_argument(argument)
            elif isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                if regex_function is None and not text_call:
                    self.visit(argument)
            else:
                self.visit(argument)

    def _visit_regex_argument(self, node: ast.expr) -> None:
        if isinstance(node, ast.Constant):
            self._record_regex(node, explicit=True)
        elif isinstance(node, ast.JoinedStr):
            dynamic = any(isinstance(value, ast.FormattedValue) for value in node.values)
            if dynamic:
                sys.stderr.write(
                    f"Warning: {self.filename}:{node.lineno}:{node.col_offset}: "
                    "dynamic regex is only partially analyzed; runtime pattern safety is unknown\n"
                )
            for value in node.values:
                if isinstance(value, ast.Constant):
                    if dynamic and self._is_incomplete_fragment(value):
                        continue
                    self._record_regex(value, explicit=True)
                elif isinstance(value, ast.FormattedValue):
                    self.visit(value)
        else:
            self.visit(node)

    @staticmethod
    def _is_incomplete_fragment(node: ast.Constant) -> bool:
        if not isinstance(node.value, str):
            return False
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            try:
                re.compile(node.value)
            except re.error as error:
                return error.msg.startswith(
                    (
                        "unterminated character set",
                        "missing ), unterminated subpattern",
                        "unbalanced parenthesis",
                        "bad escape (end of pattern)",
                    )
                )
            except OverflowError:
                return False
        return False

    def _regex_function(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.regex_functions.get(node.id)
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.regex_modules
            and node.attr in REGEX_FUNCTIONS | {"escape"}
        ):
            return node.attr
        return None

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if len(node.values) == 1 and isinstance(node.values[0], ast.Constant):
            self.visit(node.values[0])
        else:
            # Fragments do not represent the complete dynamically constructed pattern.
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    self.visit(value)

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        for index, operand in enumerate(operands):
            # Each operand can participate in the comparison on either side.
            adjacent_ops = node.ops[max(0, index - 1) : index + 1]
            if (
                isinstance(operand, ast.Constant)
                and isinstance(operand.value, str)
                and any(isinstance(op, (ast.In, ast.NotIn)) for op in adjacent_ops)
            ):
                # Membership tests treat literal strings as text, not regexes.
                continue
            self.visit(operand)

    def visit_Constant(self, node: ast.Constant) -> None:
        self._record_regex(node)

    def _record_regex(self, node: ast.Constant, *, explicit: bool = False) -> None:
        # Check if this is a string constant that looks like a regex pattern
        if isinstance(node.value, str) and (explicit or self._looks_like_regex(node.value)):
            # Check if the line has an ignore comment
            line_num = node.lineno - 1  # AST line numbers are 1-indexed, list indices are 0-indexed
            if line_num < len(self.lines):
                line_content = self.lines[line_num]
                if "# redos-linter: ignore" in line_content:
                    # Skip this regex as it's marked to be ignored
                    return

            self.regexes.append(
                {
                    "regex": node.value,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

    def _looks_like_regex(self, s: str) -> bool:
        """Determine if a string looks like a regex pattern."""
        # Skip empty strings and very short strings
        if not s or len(s) < MIN_REGEX_LENGTH:
            return False

        # Skip strings that are clearly not regex patterns
        if s.isalpha() or s.isdigit() or s.isspace():
            return False

        # Check for common regex metacharacters
        regex_chars = r".^$*+?{}[]\|()"
        if not any(c in regex_chars for c in s):
            return False
        # Heuristically discovered text must at least be valid Python regex syntax.
        # Explicit regex arguments remain visible even when invalid or unsupported.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            try:
                re.compile(s)
            except (re.error, OverflowError):
                return False
        return True


class RegexInfoWithContext(TypedDict):
    regex: str
    line: int
    col: int
    source_lines: list[str]


def extract_regexes_from_file(filepath: str) -> list[RegexInfoWithContext]:
    with Path(filepath).open() as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath)
    lines = code.splitlines()
    extractor = RegexExtractor(lines, filename=filepath)
    extractor.visit(tree)

    return [
        RegexInfoWithContext(
            regex=ri["regex"],
            line=ri["line"],
            col=ri["col"],
            source_lines=get_source_context(lines, ri["line"]),
        )
        for ri in extractor.regexes
    ]


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
    files_to_check: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files_to_check.extend(str(f) for f in path.rglob("*.py"))
        else:
            files_to_check.append(p)
    return [f for f in files_to_check if ".venv" not in f and "node_modules" not in f and ".cache" not in f]


class RegexInfoWithFile(TypedDict):
    regex: str
    filePath: str
    line: int
    col: int
    source_lines: list[str]


def collect_all_regexes(files: list[str]) -> list[RegexInfoWithFile]:
    """Extract all regexes from the given files."""
    regexes_with_paths: list[RegexInfoWithFile] = []
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


class CheckerError(TypedDict, total=False):
    kind: str
    message: str


class CheckerDetails(TypedDict, total=False):
    error: CheckerError


class RecheckResult(CheckerDetails):
    status: str
    sourceLines: list[str]
    regex: str
    filePath: str
    line: int
    col: int
    attack: dict[str, object | None]


class AttackInfo(TypedDict):
    string: str
    base: int
    pumps: list[dict[str, str]]


def check_regexes_with_deno(regexes: list[RegexInfoWithFile]) -> list[RecheckResult] | None:
    """Check regexes for vulnerabilities using Deno."""
    deno_path: str = deno.find_deno_bin()
    checker_path = Path(__file__).parent / "checker.js"
    bundle_path = Path(__file__).parent / "recheck.bundle.js"

    env = os.environ.copy()
    env["RECHECK_BACKEND"] = "pure"

    process = subprocess.run(  # noqa: S603
        [deno_path, "run", "--allow-read", str(checker_path), bundle_path.as_uri()],
        input=json.dumps(regexes).encode("utf-8"),
        capture_output=True,
        env=env,
        check=False,
    )

    if process.returncode != 0 or process.stderr:
        error = process.stderr.decode("utf-8") or f"Checker exited with status {process.returncode}\n"
        if use_colors():
            sys.stderr.write(f"{Colors.RED}Error: {Colors.END}{error}")
        else:
            sys.stderr.write(f"Error: {error}")
        return None

    output = process.stdout.decode("utf-8")
    try:
        return cast("list[RecheckResult] | None", json.loads(output))
    except json.JSONDecodeError:
        if use_colors():
            sys.stderr.write(f"{Colors.RED}Error: Invalid response from checker{Colors.END}\n")
        else:
            sys.stderr.write("Error: Invalid response from checker\n")
        return None


def main() -> int:  # noqa: PLR0912,PLR0915,C901
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
        empty_msg = "No vulnerabilities found in analyzed static patterns.\n"
        if use_colors():
            sys.stdout.write(f"{Colors.GREEN}{empty_msg}{Colors.END}")
        else:
            sys.stdout.write(empty_msg)
        return 0

    results = check_regexes_with_deno(regexes_with_paths)
    if not isinstance(results, list) or len(results) != len(regexes_with_paths):
        sys.stderr.write("Error: Incomplete or invalid response from checker\n")
        return 2
    if any(not isinstance(result, dict) or "status" not in result for result in results):
        sys.stderr.write("Error: Invalid response from checker\n")
        return 2

    total_regexes = len(results)
    vulnerable_count = sum(1 for r in results if r["status"] == "vulnerable")

    suffix = "s" if total_regexes != 1 else ""
    analyzing_msg = f"Analyzing {total_regexes} regular expression{suffix}...\n\n"
    if use_colors():
        sys.stdout.write(f"{Colors.BLUE}{analyzing_msg}{Colors.END}")
    else:
        sys.stdout.write(analyzing_msg)

    for result in results:
        if result["status"] == "vulnerable":
            attack: AttackInfo | None = result.get("attack")  # type: ignore[assignment]
            location = f"{result.get('filePath', 'unknown')}:{result.get('line', '?')}:{result.get('col', '?')}"
            # Limit attack string length to prevent overly long output
            max_attack_string_length = 100

            if use_colors():
                sys.stdout.write(f"{Colors.RED}VULNERABLE:{Colors.END} {location}\n")
                sys.stdout.write(f"   {Colors.YELLOW}Pattern:{Colors.END} {Colors.CYAN}{result['regex']}{Colors.END}\n")
                sys.stdout.write(
                    f"   {Colors.YELLOW}Issue:{Colors.END} Exponential backtracking due to nested quantifiers\n"
                )
                if attack:
                    attack_string = attack.get("string", "unknown")
                    # Truncate attack string if it's too long
                    if isinstance(attack_string, str) and len(attack_string) > max_attack_string_length:
                        attack_string = attack_string[:max_attack_string_length] + "..."
                    attack_str = json.dumps(attack_string)
                    sys.stdout.write(
                        f"   {Colors.YELLOW}Attack string:{Colors.END} {Colors.MAGENTA}{attack_str}{Colors.END}\n"
                    )
                    if attack.get("pumps") and attack["pumps"]:
                        pump = attack["pumps"][0]
                        pump_msg = (
                            f'Repeating {Colors.CYAN}"{pump["pump"]}"{Colors.END} causes catastrophic backtracking'
                        )
                        sys.stdout.write(f"   {Colors.YELLOW}Exploit:{Colors.END} {pump_msg}\n")
                        complexity = attack.get("base", "unknown")
                        sys.stdout.write(
                            f"   {Colors.YELLOW}Complexity:{Colors.END} {complexity} character repetitions\n"
                        )
                sys.stdout.write(f"   {Colors.YELLOW}Source context:{Colors.END}\n")
                for line in result.get("sourceLines", []):
                    sys.stdout.write(f"   {line}\n")
                sys.stdout.write("\n")
            else:
                sys.stdout.write(f"VULNERABLE: {location}\n")
                sys.stdout.write(f"   Pattern: {result['regex']}\n")
                sys.stdout.write("   Issue: Exponential backtracking due to nested quantifiers\n")
                if attack:
                    attack_string = attack.get("string", "unknown")
                    # Truncate attack string if it's too long
                    if isinstance(attack_string, str) and len(attack_string) > max_attack_string_length:
                        attack_string = attack_string[:max_attack_string_length] + "..."
                    sys.stdout.write(f"   Attack string: {json.dumps(attack_string)}\n")
                    if attack.get("pumps") and attack["pumps"]:
                        pump = attack["pumps"][0]
                        sys.stdout.write(f'   Exploit: Repeating "{pump["pump"]}" causes catastrophic backtracking\n')
                        sys.stdout.write(f"   Complexity: {attack.get('base', 'unknown')} character repetitions\n")
                sys.stdout.write("   Source context:\n")
                for line in result.get("sourceLines", []):
                    sys.stdout.write(f"   {line}\n")
                sys.stdout.write("\n")

    unclassified_results = [result for result in results if result["status"] not in {"safe", "vulnerable"}]
    if unclassified_results:
        for result in unclassified_results:
            location = f"{result.get('filePath', 'unknown')}:{result.get('line', '?')}:{result.get('col', '?')}"
            error = result.get("error") or {}
            reason = error.get("kind", result["status"])
            message = error.get("message", "no further details")
            sys.stderr.write(f"UNCLASSIFIED: {location}\n   Pattern: {result.get('regex', '')!r}\n")
            sys.stderr.write(f"   Reason: {reason}: {message}\n")
        sys.stderr.write("Error: Checker could not classify every regex\n")
        return 2

    if vulnerable_count == 0:
        safe_msg = (
            f"All {total_regexes} analyzed static regex{'es' if total_regexes != 1 else ''} "
            "appear safe from ReDoS attacks.\n"
        )
        if use_colors():
            sys.stdout.write(f"{Colors.GREEN}{safe_msg}{Colors.END}")
        else:
            sys.stdout.write(safe_msg)
    else:
        vuln_msg = f"Found {vulnerable_count} vulnerable regex{'es' if vulnerable_count != 1 else ''} out of {total_regexes} total.\n"  # noqa: E501
        if use_colors():
            sys.stdout.write(f"{Colors.RED}{vuln_msg}{Colors.END}")
        else:
            sys.stdout.write(vuln_msg)
        sys.stdout.write("\n")
        if use_colors():
            sys.stdout.write(f"{Colors.BLUE}Recommendations:{Colors.END}\n")
        else:
            sys.stdout.write("Recommendations:\n")
        sys.stdout.write("   - Use atomic grouping or possessive quantifiers where possible\n")
        sys.stdout.write("   - Avoid nested quantifiers like (a+)+ or (a*)*\n")
        sys.stdout.write("   - Consider using re.compile with re.IGNORECASE carefully\n")
        sys.stdout.write("   - Test regexes with long, malformed input strings\n")

    return 1 if vulnerable_count else 0


if __name__ == "__main__":
    sys.exit(main())
