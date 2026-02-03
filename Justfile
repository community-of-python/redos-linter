default: install lint test

install:
    #!/bin/bash
    uv lock --upgrade
    uv sync --all-extras --frozen
    recheck_bundle_path=src/redos_linter/recheck.bundle.js
    if test -f "$recheck_bundle_path"; then
        exit 0
    fi
    ./node_modules/.bin/esbuild src/redos_linter/recheck-entry.js --bundle --format=esm --platform=browser --outfile="$recheck_bundle_path"

lint:
    uv run ruff format
    uv run ruff check --fix
    uv run mypy .

test *args:
    uv run --no-sync pytest {{ args }}

publish:
    rm -rf dist
    uv version $GITHUB_REF_NAME
    uv build
    uv publish --token $PYPI_TOKEN

run:
    uv run redos-linter .
