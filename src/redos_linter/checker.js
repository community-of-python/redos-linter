const bundlePath = Deno.args[0];
const { recheck } = await import(bundlePath);

function main(content) {
    const regexesWithPaths = JSON.parse(content);

    for (const item of regexesWithPaths) {
        const { regex, filePath } = item;
        const result = recheck.checkSync(regex, '');
        if (result.status === 'vulnerable') {
            console.log(`Vulnerable regex found in ${filePath}: ${regex}`);
            console.log(`  Reason: ${JSON.stringify(result.attack)}`);
        }
    }
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
