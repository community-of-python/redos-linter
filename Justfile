# build the recheck bundle
build:
    ./node_modules/.bin/esbuild src/redos_linter/recheck-entry.js --bundle --outfile=src/redos_linter/recheck.bundle.js --format=esm --platform=browser

# run the linter
run:
    uv run redos-linter .
