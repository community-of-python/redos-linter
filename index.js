const recheck = require('recheck');
const fs = require('fs');
const Parser = require('tree-sitter');
const Python = require('tree-sitter-python');
const { globSync } = require('glob');
const path = require('path');

async function checkFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const parser = new Parser();
    parser.setLanguage(Python);
    const tree = parser.parse(code);
    const query = new Parser.Query(Python, `
        (call
            (attribute
                (identifier) @re
                attribute: (identifier) @method)
            (argument_list
                (string) @regex)
            (#eq? @re "re")
            (#match? @method "(compile|search|match|fullmatch|split|findall|finditer|sub|subn)"))
    `);
    const matches = query.captures(tree.rootNode);
    const regexes = matches.filter(m => m.name == 'regex' && m.node).map(m => {
        let text = m.node.text;
        if (text.startsWith('r')) {
            text = text.substring(1);
        }
        return text.slice(1, -1);
    });

    for (const regex of regexes) {
        const result = await recheck.check(regex, '');
        if (result.status === 'vulnerable') {
            console.log(`Vulnerable regex found in ${filePath}: ${regex}`);
            console.log(`  Reason: ${JSON.stringify(result.attack)}`);
        }
    }
}

async function main() {
    const inputs = process.argv.slice(2);
    let files = [];
    for (const input of inputs) {
        if (fs.statSync(input).isDirectory()) {
            files = files.concat(globSync(path.join(input, '**/*.py'), { ignore: ['**/.venv/**', '**/node_modules/**'] }));
        } else if (input.endsWith('.py')) {
            files.push(input);
        }
    }

    const promises = files.map(file => checkFile(file));
    await Promise.all(promises);
}

main();
