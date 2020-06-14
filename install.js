const { exec } = require('child_process');

let platform;
if (process.arch === 'x64') {
    console.log("Installing 64 bit CSNodeMsPassport.dll to global assembly cache");
    platform = 'x64';
} else {
    console.log("Installing 32 bit CSNodeMsPassport.dll to global assembly cache");
    platform = 'x86';
}

exec("CSNodeMsPassport.msi", {cwd: "passport\\" + platform}, (error, stdout, stderr) => {
    if (error) {
        console.log(`error: ${error.message}`);
        process.exit(1);
    }

    if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
    }

    console.log(stdout);
});