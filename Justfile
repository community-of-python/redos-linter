# build the recheck bundle
build:
    ./node_modules/.bin/esbuild src/recheck-entry.js --bundle --outfile=dist/recheck.bundle.js --format=esm --platform=browser

# run the linter
run:
    uv run redos-linter .
