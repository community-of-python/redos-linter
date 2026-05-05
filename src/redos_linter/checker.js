const bundlePath = Deno.args[0];

async function readStdin() {
    const reader = Deno.stdin.readable.getReader();
    const decoder = new TextDecoder();
    let content = '';
    while (true) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        content += decoder.decode(value);
    }
    return content;
}

function mapResult(item, result) {
    return {
        regex: item.regex,
        filePath: item.filePath,
        line: item.line,
        col: item.col,
        sourceLines: item.source_lines,
        status: result.status,
        attack: result.attack,
    };
}

async function runInline(items) {
    const { recheck } = await import(bundlePath);
    return items.map((item) => mapResult(item, recheck.checkSync(item.regex, '')));
}

function runInWorker(shard) {
    return new Promise((resolve, reject) => {
        const workerUrl = new URL('./worker.js', import.meta.url);
        const worker = new Worker(workerUrl.href, { type: 'module' });
        worker.onmessage = (event) => {
            worker.terminate();
            resolve(event.data);
        };
        worker.onerror = (event) => {
            worker.terminate();
            reject(event.message ?? new Error('worker failed'));
        };
        worker.postMessage({ bundlePath, shard });
    });
}

const PARALLEL_THRESHOLD = 8;

const items = JSON.parse(await readStdin());
const cores = navigator.hardwareConcurrency || 1;
const workerCount = Math.min(cores, items.length);

let results;
if (workerCount <= 1 || items.length < PARALLEL_THRESHOLD) {
    results = await runInline(items);
} else {
    const shards = Array.from({ length: workerCount }, () => []);
    items.forEach((item, index) => shards[index % workerCount].push(item));
    const shardResults = await Promise.all(shards.map(runInWorker));
    results = shardResults.flat();
}

console.log(JSON.stringify(results));
