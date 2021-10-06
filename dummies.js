// A file for dummy classes if the module could not be built

function dummy() {
    throw new Error("Your current platform is not supported");
}

const Passport = dummy.bind({});

Passport.passportAccountExists = dummy;
Passport.passportAvailable = dummy;
Passport.verifySignatureHex = dummy;
Passport.verifySignature = dummy;

const passwords = {
    encryptHex: dummy,
    encrypt: dummy,
    decryptHex: dummy,
    decrypt: dummy,
    isEncryptedHex: dummy,
    isEncrypted: dummy
}

const passport_utils = {
    generateRandomHex: dummy,
    generateRandom: dummy
}

module.exports = {
    PassportError: dummy,
    CredentialStore: dummy,
    Credential: dummy,
    Passport: Passport,
    passwords: passwords,
    passport_utils: passport_utils
}