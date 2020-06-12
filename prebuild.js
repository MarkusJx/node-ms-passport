const { spawn } = require('child_process');

buildNodeMsPassport();

function buildNodeMsPassport() {
    if (process.platform !== "win32") {
        console.log("\nNot building the NodeMsPassport library\n");
        return;
    }

    console.log("\nBuilding the NodeMsPassport library x64\n");

    const child = spawn('msbuild', ['NodeMsPassport/NodeMsPassport.sln', '/p:Platform=x64','-p:Configuration=Release']);

    child.stdout.setEncoding('utf8');
    child.stdout.pipe(process.stdout);

    child.stderr.setEncoding('utf8');
    child.stderr.pipe(process.stdout);

    child.on('close', (code) => {
        console.log(`\nChild process exited with code ${code}`);
    });

    console.log("\nBuilding the NodeMsPassport library x86\n");

    const child_x86 = spawn('msbuild', ['NodeMsPassport/NodeMsPassport.sln', '/p:Platform=x86','-p:Configuration=Release']);

    child_x86.stdout.setEncoding('utf8');
    child_x86.stdout.pipe(process.stdout);

    child_x86.stderr.setEncoding('utf8');
    child_x86.stderr.pipe(process.stdout);

    child_x86.on('close', (code) => {
        console.log(`\nChild process exited with code ${code}`);
    });
}