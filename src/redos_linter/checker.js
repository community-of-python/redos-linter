const bundlePath = Deno.args[0];
const { recheck } = await import(bundlePath);

function main(content) {
    const regexesWithPaths = JSON.parse(content);
    const results = [];

    for (const item of regexesWithPaths) {
        const { regex, filePath, line, col, source_lines } = item;
        const result = recheck.checkSync(regex, '');
        results.push({
            regex: regex,
            filePath: filePath,
            line: line,
            col: col,
            sourceLines: source_lines,
            status: result.status,
            attack: result.attack
        });
    }

    console.log(JSON.stringify(results));
}

(async () => {
    const reader = Deno.stdin.readable.getReader();
    let content = '';
    const decoder = new TextDecoder();
    while (true) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        content += decoder.decode(value);
    }
    main(content);
})();
