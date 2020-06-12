const fs = require('fs');
const base_dir = './passport';
const Path = require('path');

// Source: https://stackoverflow.com/a/32197381
const deleteFolderRecursive = function (path) {
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
    if (!fs.existsSync(base_dir)) {
        console.log("Creating directory:", base_dir);
        fs.mkdirSync(base_dir);
    } else {
        console.log(base_dir, "already exists, deleting it");
        deleteFolderRecursive(base_dir);
        console.log("Creating directory:", base_dir);
        fs.mkdirSync(base_dir);
    }

    let dir32 = base_dir + "/x86";
    let dir64 = base_dir + "/x64";

    if (!fs.existsSync(dir32)) {
        console.log("Creating directory:", dir32);
        fs.mkdirSync(dir32);
    }

    if (!fs.existsSync(dir64)) {
        console.log("Creating directory:", dir64);
        fs.mkdirSync(dir64);
    }

    console.log("Copying deps to:", base_dir);

    let csNative, csNative_out, dotNetBridge, dotNetBridge_out;
    csNative = "NodeMsPassport/x64/Release/CSNodeMsPassport.dll";
    dotNetBridge = "NodeMsPassport/x64/Release/NodeMsPassport.dll";

    csNative_out = dir64 + "/CSNodeMsPassport.dll";
    dotNetBridge_out = dir64 + "/NodeMsPassport.dll";

    fs.copyFileSync(dotNetBridge, dotNetBridge_out);
    fs.copyFileSync(csNative, csNative_out);

    csNative = "NodeMsPassport/Release/CSNodeMsPassport.dll";
    dotNetBridge = "NodeMsPassport/Release/NodeMsPassport.dll";

    csNative_out = dir32 + "/CSNodeMsPassport.dll";
    dotNetBridge_out = dir32 + "/NodeMsPassport.dll";

    fs.copyFileSync(dotNetBridge, dotNetBridge_out);
    fs.copyFileSync(csNative, csNative_out);
    fs.copyFileSync("NodeMsPassport/GacInstaller/bin/Release/GacInstaller.exe", base_dir + "/GacInstaller.exe");

    fs.copyFileSync("build32/Release/passport.node", dir32 + "/passport.node");
    fs.copyFileSync("build64/Release/passport.node", dir64 + "/passport.node");
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