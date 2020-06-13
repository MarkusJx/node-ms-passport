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
} else if (process.argv[2] === "create-lib") {
    const bin_dir = "passportLib";

    if (!fs.existsSync(bin_dir)) {
        console.log("Creating directory:", bin_dir);
        fs.mkdirSync(bin_dir);
    } else {
        console.log(bin_dir, "already exists, deleting it");
        deleteFolderRecursive(bin_dir);
        console.log("Creating directory:", bin_dir);
        fs.mkdirSync(bin_dir);
    }

    let root32 = bin_dir + "/x86";
    let root64 = bin_dir + "/x64";

    let dir32 = bin_dir + "/x86/bin";
    let dir64 = bin_dir + "/x64/bin";

    let lib_dir32 = bin_dir + "/x86/lib";
    let lib_dir64 = bin_dir + "/x64/lib";

    let include_dir = bin_dir + "/include";

    if (!fs.existsSync(root32)) {
        console.log("Creating directory:", root32);
        fs.mkdirSync(root32);
    }

    if (!fs.existsSync(root64)) {
        console.log("Creating directory:", root64);
        fs.mkdirSync(root64);
    }

    if (!fs.existsSync(include_dir)) {
        console.log("Creating directory:", include_dir);
        fs.mkdirSync(include_dir);
    }

    if (!fs.existsSync(lib_dir32)) {
        console.log("Creating directory:", lib_dir32);
        fs.mkdirSync(lib_dir32);
    }

    if (!fs.existsSync(lib_dir64)) {
        console.log("Creating directory:", lib_dir64);
        fs.mkdirSync(lib_dir64);
    }

    if (!fs.existsSync(dir32)) {
        console.log("Creating directory:", dir32);
        fs.mkdirSync(dir32);
    }

    if (!fs.existsSync(dir64)) {
        console.log("Creating directory:", dir64);
        fs.mkdirSync(dir64);
    }

    console.log("Copying deps to:", bin_dir);

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

    fs.copyFileSync("NodeMsPassport/x64/Release/NodeMsPassport.lib", lib_dir64 + "/NodeMsPassport.lib");
    fs.copyFileSync("NodeMsPassport/Release/NodeMsPassport.lib", lib_dir32 + "/NodeMsPassport.lib")

    fs.copyFileSync("NodeMsPassport/NodeMsPassport/NodeMsPassport.h", include_dir + "/NodeMsPassport.h");
} else {
    throw new TypeError("Unknown command: " + process.argv[2]);
}