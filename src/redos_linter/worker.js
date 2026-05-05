self.onmessage = async (event) => {
    const { bundlePath, shard } = event.data;
    const { recheck } = await import(bundlePath);
    const results = shard.map((item) => {
        const result = recheck.checkSync(item.regex, '');
        return {
            regex: item.regex,
            filePath: item.filePath,
            line: item.line,
            col: item.col,
            sourceLines: item.source_lines,
            status: result.status,
            attack: result.attack,
        };
    });
    self.postMessage(results);
    self.close();
};
