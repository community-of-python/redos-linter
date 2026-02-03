pre-build:
    #!/bin/bash
    file_name=src/redos_linter/recheck.bundle.js
    if test -f "$file_name"; then
        exit 0
    fi
    ./node_modules/.bin/esbuild src/redos_linter/recheck-entry.js --bundle --format=esm --platform=browser --outfile="$file_name"

run:
    uv run redos-linter .
