const { exec } = require('child_process');

let platform;
if (process.arch === 'x64') {
    platform = 'x64';
} else {
    platform = 'x86';
}

exec("..\\GacInstaller.exe install CSNodeMsPassport.dll", {cwd: "passport\\" + platform}, (error, stdout, stderr) => {
    if (error) {
        console.log(`error: ${error.message}`);
        return;
    }
    if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
    }

    console.log(stdout);
});