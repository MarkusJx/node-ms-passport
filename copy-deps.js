const fs = require('fs');
const dir = './passport';
const Path = require('path');

// Source: https://stackoverflow.com/a/32197381
const deleteFolderRecursive = function(path) {
    if (fs.existsSync(path)) {
        fs.readdirSync(path).forEach((file, index) => {
            const curPath = Path.join(path, file);
            if (fs.lstatSync(curPath).isDirectory()) { // recurse
                deleteFolderRecursive(curPath);
            } else { // delete file
                fs.unlinkSync(curPath);
            }
        });
        fs.rmdirSync(path);
    }
};

if (process.argv[2] === "copy") {
    if (!fs.existsSync(dir)) {
        console.log("Creating directory:", dir);
        fs.mkdirSync(dir);
    } else {
        console.log(dir, "already exists, deleting it");
        deleteFolderRecursive(dir);
        console.log("Creating directory:", dir);
        fs.mkdirSync(dir);
    }

    console.log("Copying deps to:", dir);

    if (process.platform === "win32") {
        let csNative, csNative_out, dotNetBridge, dotNetBridge_out;
        if (process.arch === 'x64') {
            csNative = "NodeMsPassport/x64/Release/CSNodeMsPassport.dll";
            dotNetBridge = "NodeMsPassport/x64/Release/NodeMsPassport.dll";
        } else {
            csNative = "NodeMsPassport/win32/Release/CSNodeMsPassport.dll";
            dotNetBridge = "NodeMsPassport/win32/Release/NodeMsPassport.dll";
        }

        csNative_out = dir + "/CSNodeMsPassport.dll";
        dotNetBridge_out = dir + "/NodeMsPassport.dll";

        fs.copyFileSync(dotNetBridge, dotNetBridge_out);
        fs.copyFileSync(csNative, csNative_out);
        fs.copyFileSync("NodeMsPassport/GacInstaller/bin/Release/GacInstaller.exe", dir + "/GacInstaller.exe");
    }

    fs.copyFileSync("build/Release/passport.node", dir + "/passport.node");
} else if (process.argv[2] === "clean") {
    if (fs.existsSync(dir)) {
        console.log("Deleting directory:", dir);
        deleteFolderRecursive(dir);
    } else {
        console.warn("Could not delete directory:", dir, "as it doesn't exist");
    }
} else {
    throw new TypeError("Unknown command: " + process.argv[2]);
}