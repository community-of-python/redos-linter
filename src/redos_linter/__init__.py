import argparse
import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast


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


class RegexInfo(TypedDict):
    regex: str
    line: int
    col: int


class RegexExtractor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.regexes: list[RegexInfo] = []

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


class RegexInfoWithContext(TypedDict):
    regex: str
    line: int
    col: int
    source_lines: list[str]


def extract_regexes_from_file(filepath: str) -> list[RegexInfoWithContext]:
    with Path(filepath).open() as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath)
    extractor = RegexExtractor()
    extractor.visit(tree)

    lines = code.splitlines()
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
    return [f for f in files_to_check if ".venv" not in f and "node_modules" not in f]


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


class RecheckResult(TypedDict):
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
        if use_colors():
            sys.stderr.write(f"{Colors.RED}Error: {Colors.END}{process.stderr.decode('utf-8')}")
        else:
            sys.stderr.write(f"Error: {process.stderr.decode('utf-8')}")
        return None

    output = process.stdout.decode("utf-8")
    if not output:
        if use_colors():
            sys.stdout.write(f"{Colors.GREEN}No vulnerable regexes found.{Colors.END}\n")
        else:
            sys.stdout.write("No vulnerable regexes found.\n")
        return None

    try:
        return cast("list[RecheckResult] | None", json.loads(output))
    except json.JSONDecodeError:
        if use_colors():
            sys.stderr.write(f"{Colors.RED}Error: Invalid response from checker{Colors.END}\n")
        else:
            sys.stderr.write("Error: Invalid response from checker\n")
        return None


def main() -> None:  # noqa: PLR0912,PLR0915,C901
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
            sys.stdout.write(f"{Colors.GREEN}No vulnerable regexes found.{Colors.END}\n")
        else:
            sys.stdout.write("No vulnerable regexes found.\n")
        return

    results = check_regexes_with_deno(regexes_with_paths)
    if results is None:
        return

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
            if use_colors():
                sys.stdout.write(f"{Colors.RED}VULNERABLE:{Colors.END} {location}\n")
                sys.stdout.write(f"   {Colors.YELLOW}Pattern:{Colors.END} {Colors.CYAN}{result['regex']}{Colors.END}\n")
                sys.stdout.write(
                    f"   {Colors.YELLOW}Issue:{Colors.END} Exponential backtracking due to nested quantifiers\n"
                )
                if attack:
                    attack_str = json.dumps(attack.get("string", "unknown"))
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
                    sys.stdout.write(f"   Attack string: {json.dumps(attack.get('string', 'unknown'))}\n")
                    if attack.get("pumps") and attack["pumps"]:
                        pump = attack["pumps"][0]
                        sys.stdout.write(f'   Exploit: Repeating "{pump["pump"]}" causes catastrophic backtracking\n')
                        sys.stdout.write(f"   Complexity: {attack.get('base', 'unknown')} character repetitions\n")
                sys.stdout.write("   Source context:\n")
                for line in result.get("sourceLines", []):
                    sys.stdout.write(f"   {line}\n")
                sys.stdout.write("\n")

    if vulnerable_count == 0:
        safe_msg = f"All {total_regexes} regex{'es' if total_regexes != 1 else ''} appear safe from ReDoS attacks.\n"
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


if __name__ == "__main__":
    main()
