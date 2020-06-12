const { spawn } = require('child_process');

buildNodeMsPassport();

function buildNodeMsPassport() {
    if (process.platform !== "win32") {
        console.log("\nNot building the NodeMsPassport library\n");
        return;
    }

    console.log("\nBuilding the NodeMsPassport library\n");
    let platform;
    if (process.arch === 'x64') {
        platform = '/p:Platform=x64';
    } else {
        platform = '/p:Platform=Win32';
    }

    const child = spawn('msbuild', ['NodeMsPassport/NodeMsPassport.sln', platform,'-p:Configuration=Release']);

    child.stdout.setEncoding('utf8');
    child.stdout.pipe(process.stdout);

    child.stderr.setEncoding('utf8');
    child.stderr.pipe(process.stdout);

    child.on('close', (code) => {
        console.log(`\nChild process exited with code ${code}`);
    });
}