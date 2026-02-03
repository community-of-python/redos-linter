import ast
import sys
import os
import glob
import json
import subprocess
import argparse

# ANSI color codes for better output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def use_colors():
    """Check if colors should be used (TTY and not disabled by environment)"""
    return sys.stdout.isatty() and os.environ.get('NO_COLOR') is None

def get_deno_path():
    python_executable = sys.executable
    bin_dir = os.path.dirname(python_executable)
    deno_path = os.path.join(bin_dir, 'deno')
    if os.path.exists(deno_path):
        return deno_path

    import deno
    deno_dir = os.path.dirname(deno.__file__)
    deno_path = os.path.join(deno_dir, "bin", "deno")
    if os.path.exists(deno_path):
        return deno_path

    raise FileNotFoundError("Could not find the deno executable.")

class RegexExtractor(ast.NodeVisitor):
    def __init__(self):
        self.regexes = []

    def visit_Call(self, node):
        if (isinstance(node.func, ast.Attribute) and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == 're' and
                node.func.attr in ('compile', 'search', 'match', 'fullmatch', 'split', 'findall', 'finditer', 'sub', 'subn')):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.regexes.append({
                    'regex': node.args[0].value,
                    'line': node.lineno,
                    'col': node.col_offset
                })
        self.generic_visit(node)

def extract_regexes_from_file(filepath):
    with open(filepath, 'r') as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath)
    extractor = RegexExtractor()
    extractor.visit(tree)
    
    lines = code.splitlines()
    for regex_info in extractor.regexes:
        regex_info['source_lines'] = get_source_context(lines, regex_info['line'])
    
    return extractor.regexes

def get_source_context(lines, line_num, context=2):
    """Get source lines with context (before and after the target line)"""
    start = max(0, line_num - context - 1)  # -1 because line_num is 1-indexed
    end = min(len(lines), line_num + context)
    
    context_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_num - 1 else "    "
        context_lines.append(f"{prefix}{i + 1:3d}: {lines[i]}")
    
    return context_lines

def main():
    parser = argparse.ArgumentParser(description='ReDoS Linter - Detects Regular Expression Denial of Service vulnerabilities')
    parser.add_argument('paths', metavar='path', type=str, nargs='+', help='Files or directories to check')
    args = parser.parse_args()

    files_to_check = []
    for p in args.paths:
        if os.path.isdir(p):
            for ext in ('**/*.py',):
                files_to_check.extend(glob.glob(os.path.join(p, ext), recursive=True))
        else:
            files_to_check.append(p)

    files_to_check = [f for f in files_to_check if '.venv' not in f and 'node_modules' not in f]

    regexes_with_paths = []
    for file_path in files_to_check:
        regexes = extract_regexes_from_file(file_path)
        for regex_info in regexes:
            regexes_with_paths.append({
                'regex': regex_info['regex'], 
                'filePath': file_path,
                'line': regex_info['line'],
                'col': regex_info['col'],
                'source_lines': regex_info['source_lines']
            })

    if not regexes_with_paths:
        if use_colors():
            print(f"{Colors.GREEN}✅ No regexes found to analyze.{Colors.END}")
        else:
            print("✅ No regexes found to analyze.")
        return

    deno_path = get_deno_path()
    checker_path = os.path.join(os.path.dirname(__file__), 'checker.js')
    bundle_path = os.path.join(os.path.dirname(__file__), 'recheck.bundle.js')

    env = os.environ.copy()
    env['RECHECK_BACKEND'] = 'pure'
    
    # Debug: print what we're sending to JS
    # print(f"DEBUG: Sending {len(regexes_with_paths)} regexes to JS", file=sys.stderr)
    # for i, r in enumerate(regexes_with_paths[:2]):
    #     print(f"DEBUG: Regex {i}: {list(r.keys())}", file=sys.stderr)
    
    process = subprocess.run(
        [deno_path, 'run', '--allow-read', checker_path, bundle_path],
        input=json.dumps(regexes_with_paths).encode('utf-8'),
        capture_output=True,
        env=env
    )
    
    if process.stderr:
        if use_colors():
            print(f"{Colors.RED}❌ Error:{Colors.END} {process.stderr.decode('utf-8')}", file=sys.stderr)
        else:
            print("❌ Error:", process.stderr.decode('utf-8'), file=sys.stderr)
        return
    
    output = process.stdout.decode('utf-8')
    if not output:
        if use_colors():
            print(f"{Colors.GREEN}✅ No vulnerable regexes found.{Colors.END}")
        else:
            print("✅ No vulnerable regexes found.")
        return
    
    try:
        results = json.loads(output)
        # Debug: Check what we got back
        # print(f"DEBUG: Got {len(results)} results from JS", file=sys.stderr)
        # if results:
        #     print(f"DEBUG: First result keys: {list(results[0].keys())}", file=sys.stderr)
        #     if 'sourceLines' in results[0]:
        #         print(f"DEBUG: sourceLines type: {type(results[0]['sourceLines'])}", file=sys.stderr)
        #         print(f"DEBUG: sourceLines length: {len(results[0]['sourceLines']) if results[0]['sourceLines'] else 'None'}", file=sys.stderr)
    except json.JSONDecodeError:
        if use_colors():
            print(f"{Colors.RED}❌ Error: Invalid response from checker{Colors.END}", file=sys.stderr)
        else:
            print("❌ Error: Invalid response from checker", file=sys.stderr)
        return
    
    total_regexes = len(results)
    vulnerable_count = sum(1 for r in results if r['status'] == 'vulnerable')
    
    if use_colors():
        print(f"{Colors.BLUE}🔍 Analyzing {total_regexes} regular expression{'s' if total_regexes != 1 else ''}...{Colors.END}\n")
    else:
        print(f"🔍 Analyzing {total_regexes} regular expression{'s' if total_regexes != 1 else ''}...\n")
    
    for result in results:
        if result['status'] == 'vulnerable':
            attack = result['attack']
            if use_colors():
                print(f"{Colors.RED}❌ VULNERABLE:{Colors.END} {result['filePath']}:{result['line']}:{result['col']}")
                print(f"   {Colors.YELLOW}Pattern:{Colors.END} {Colors.CYAN}{result['regex']}{Colors.END}")
                print(f"   {Colors.YELLOW}Issue:{Colors.END} Exponential backtracking due to nested quantifiers")
                print(f"   {Colors.YELLOW}Attack string:{Colors.END} {Colors.MAGENTA}{json.dumps(attack['string'])}{Colors.END}")
                if attack.get('pumps') and attack['pumps']:
                    pump = attack['pumps'][0]
                    print(f"   {Colors.YELLOW}Exploit:{Colors.END} Repeating {Colors.CYAN}\"{pump['pump']}\"{Colors.END} causes catastrophic backtracking")
                print(f"   {Colors.YELLOW}Complexity:{Colors.END} {attack.get('base', 'unknown')} character repetitions")
                print(f"   {Colors.YELLOW}Source context:{Colors.END}")
                for line in result.get('sourceLines', []):
                    print(f"   {line}")
                print('')
            else:
                print(f"❌ VULNERABLE: {result['filePath']}:{result['line']}:{result['col']}")
                print(f"   Pattern: {result['regex']}")
                print(f"   Issue: Exponential backtracking due to nested quantifiers")
                print(f"   Attack string: {json.dumps(attack['string'])}")
                if attack.get('pumps') and attack['pumps']:
                    pump = attack['pumps'][0]
                    print(f"   Exploit: Repeating \"{pump['pump']}\" causes catastrophic backtracking")
                print(f"   Complexity: {attack.get('base', 'unknown')} character repetitions")
                print(f"   Source context:")
                for line in result.get('sourceLines', []):
                    print(f"   {line}")
                print('')
    
    if vulnerable_count == 0:
        if use_colors():
            print(f"{Colors.GREEN}✅ All {total_regexes} regex{'es' if total_regexes != 1 else ''} appear safe from ReDoS attacks.{Colors.END}")
        else:
            print(f"✅ All {total_regexes} regex{'es' if total_regexes != 1 else ''} appear safe from ReDoS attacks.")
    else:
        if use_colors():
            print(f"{Colors.RED}🚨 Found {vulnerable_count} vulnerable regex{'es' if vulnerable_count != 1 else ''} out of {total_regexes} total.{Colors.END}")
        else:
            print(f"🚨 Found {vulnerable_count} vulnerable regex{'es' if vulnerable_count != 1 else ''} out of {total_regexes} total.")
        print('')
        if use_colors():
            print(f"{Colors.BLUE}💡 Recommendations:{Colors.END}")
        else:
            print("💡 Recommendations:")
        print("   • Use atomic grouping or possessive quantifiers where possible")
        print("   • Avoid nested quantifiers like (a+)+ or (a*)*")
        print("   • Consider using re.compile with re.IGNORECASE carefully")
        print("   • Test regexes with long, malformed input strings")

if __name__ == "__main__":
    main()
