export function checkPattern(recheck, pattern) {
    let source = pattern;
    const flags = new Set();
    let prefix;
    while ((prefix = /^\(\?([ms]+)\)/.exec(source)) !== null) {
        for (const flag of prefix[1]) flags.add(flag);
        source = source.slice(prefix[0].length);
    }
    return recheck.checkSync(source, [...flags].join(''));
}
