const path = require('path');
const fs = require('fs');

const BINARY_NAME = "passport.node";
const CS_BINARY_NAME = "CSNodeMsPassport.dll";
const WINDOWS_WINMD = "Windows.winmd";
const NODEMSPASSPORT_NAME = "NodeMsPassport.lib";
const OUT_DIR = path.join(__dirname, 'bin');
const LIB_DIR = path.join(__dirname, 'lib');
const BUILD_DIR = path.join(__dirname, 'build');

// Source: https://stackoverflow.com/a/32197381
function deleteFolderRecursive(p) {
    if (fs.existsSync(p)) {
        fs.readdirSync(p).forEach((file) => {
            const curPath = path.join(p, file);
            if (fs.lstatSync(curPath).isDirectory()) { // recurse
                deleteFolderRecursive(curPath);
            } else { // delete file
                fs.unlinkSync(curPath);
            }
        });
        fs.rmdirSync(p);
    }
}

function deleteIfExists(p) {
    if (fs.existsSync(p)) {
        if (fs.lstatSync(p).isDirectory()) {
            console.log(`Directory ${p} exists, deleting it`);
            deleteFolderRecursive(p);
        } else {
            console.log(`${p} exists, deleting it`);
            fs.unlinkSync(p);
        }
    }
}

if (process.argv.length === 2) {
    deleteIfExists(BUILD_DIR);
} else if (process.argv.length === 3) {
    switch (process.argv[2]) {
        case "--post_build":
            deleteIfExists(OUT_DIR);
            deleteIfExists(LIB_DIR);
            fs.mkdirSync(OUT_DIR);
            fs.mkdirSync(LIB_DIR);
            fs.copyFileSync(path.join(BUILD_DIR, 'Release', BINARY_NAME), path.join(OUT_DIR, BINARY_NAME));
            fs.copyFileSync(path.join(BUILD_DIR, 'Release', CS_BINARY_NAME), path.join(OUT_DIR, CS_BINARY_NAME));
            fs.copyFileSync(path.join(BUILD_DIR, 'Release', WINDOWS_WINMD), path.join(OUT_DIR, WINDOWS_WINMD));
            fs.copyFileSync(path.join(BUILD_DIR, 'Release', NODEMSPASSPORT_NAME), path.join(LIB_DIR, NODEMSPASSPORT_NAME));
            break;
        case "--clean":
            deleteIfExists(OUT_DIR);
            deleteIfExists(LIB_DIR);
            deleteIfExists(BUILD_DIR);
            break;
        default:
            throw new Error(`Unknown argument: ${process.argv[2]}`);
    }
} else {
    throw new Error("Invalid number of arguments supplied");
}