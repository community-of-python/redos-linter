build:
    ./node_modules/.bin/esbuild recheck-entry.js --bundle --outfile=recheck.bundle.js --format=esm --platform=browser
