import ast
import sys
import os
import glob
import json
import subprocess

def get_deno_path():
    # Find the deno executable in the current environment's bin directory
    python_executable = sys.executable
    bin_dir = os.path.dirname(python_executable)
    deno_path = os.path.join(bin_dir, 'deno')
    if os.path.exists(deno_path):
        return deno_path
    
    # Fallback for some environments where it might be in a different place
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
                self.regexes.append(node.args[0].value)
        self.generic_visit(node)

def extract_regexes_from_file(filepath):
    with open(filepath, 'r') as f:
        code = f.read()
    tree = ast.parse(code, filename=filepath)
    extractor = RegexExtractor()
    extractor.visit(tree)
    return extractor.regexes

def main():
    if len(sys.argv) < 2:
        print("Usage: python linter.py <file_or_directory>")
        sys.exit(1)

    inputs = sys.argv[1:]
    files_to_check = []
    for p in inputs:
        if os.path.isdir(p):
            for ext in ('**/*.py',):
                files_to_check.extend(glob.glob(os.path.join(p, ext), recursive=True))
        else:
            files_to_check.append(p)
    
    files_to_check = [f for f in files_to_check if '.venv' not in f and 'node_modules' not in f]

    regexes_with_paths = []
    for file_path in files_to_check:
        regexes = extract_regexes_from_file(file_path)
        for regex in regexes:
            regexes_with_paths.append({'regex': regex, 'filePath': file_path})

    if not regexes_with_paths:
        print("No regexes found.")
        return
    
    deno_path = get_deno_path()
    env = os.environ.copy()
    env['RECHECK_BACKEND'] = 'pure'
    process = subprocess.run(
        [deno_path, 'run', '--allow-read', 'checker.js'],
        input=json.dumps(regexes_with_paths).encode('utf-8'),
        capture_output=True,
        env=env
    )
    print(process.stdout.decode('utf-8'))
    if process.stderr:
        print("Error:", process.stderr.decode('utf-8'))


if __name__ == "__main__":
    main()
