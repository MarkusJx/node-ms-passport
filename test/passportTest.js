const assert = require("assert");
const { Passport, passport_utils } = require('../index');

if (process.platform !== 'win32') {
    console.log("INFO: Skipping passport tests since running on unix");
    return;
}

describe('Passport hex test', function() {
    let publicKey, challenge, signed;
    it('Checking if passport is available', () => {
        assert(Passport.passportAvailable());
    });

    const pass = new Passport("test_hex");
    it('Creating passport key', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        await pass.createPassportKey();
    });

    it('Checking public key', async() => {
        publicKey = await pass.getPublicKeyHex();
        assert.notStrictEqual(publicKey, null);
    });

    it('Generating challenge', function() {
        challenge = passport_utils.generateRandomHex(25);
        assert.strictEqual(challenge.length, 50);
    });

    it('Signing challenge', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        signed = await pass.passportSignHex(challenge);
        assert.notStrictEqual(signed, null);
    });

    it('Verifying signature', async function() {
        const signatureMatches = await Passport.verifySignatureHex(challenge, signed, publicKey);
        assert(signatureMatches);
    });

    it('Deleting passport key', async() => {
        await pass.deletePassportAccount();
        assert.strictEqual(Passport.passportAccountExists("test_hex"), false);
    });
});

describe('Passport test', function() {
    let publicKey, challenge, signed;
    it('Checking if passport is available', () => {
        assert(Passport.passportAvailable());
    });

    const pass = new Passport("test");
    it('Creating passport key', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        await pass.createPassportKey();
    });

    it('Checking public key', async() => {
        publicKey = await pass.getPublicKey();
        assert.notStrictEqual(publicKey, null);
    });

    it('Generating challenge', function() {
        challenge = passport_utils.generateRandom(25);
        assert.strictEqual(challenge.length, 25);
    });

    it('Signing challenge', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        signed = await pass.passportSign(challenge);
        assert.notStrictEqual(signed, null);
    });

    it('Verifying signature', async function() {
        const signatureMatches = await Passport.verifySignature(challenge, signed, publicKey);
        assert(signatureMatches);
    });

    it('Deleting passport key', async() => {
        await pass.deletePassportAccount();
        assert.strictEqual(Passport.passportAccountExists("test"), false);
    });
});