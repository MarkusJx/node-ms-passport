const assert = require("assert");
const { Passport, VerificationResult } = require('../index');
const crypto = require('crypto');

if (process.platform !== 'win32') {
    console.log("INFO: Skipping passport tests since running on unix");
    return;
}

describe('Passport hex test', function() {
    let publicKey, challenge, signed;
    it('Check if passport is available', () => {
        assert(Passport.passportAvailable());
    });

    const pass = new Passport("test_hex");
    it('Create passport key', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        await pass.createPassportKey();
    });

    it('Check public key', async() => {
        publicKey = await pass.getPublicKeyHex();
        assert.notStrictEqual(publicKey, null);
    });

    it('Get public key hash', async() => {
        const hash = await pass.getPublicKeyHashHex();
        const check = crypto.createHash('sha256')
            .update(Buffer.from(publicKey, 'hex'))
            .digest();

        assert.strictEqual(hash.toLowerCase(), check.toString('hex'));
    });

    it('Generate challenge', function() {
        challenge = crypto.randomBytes(25).toString('hex');
        assert.strictEqual(challenge.length, 50);
    });

    it('Sign challenge', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        signed = await pass.passportSignHex(challenge);
        assert.notStrictEqual(signed, null);
    });

    it('Verify signature', async function() {
        const signatureMatches = await Passport.verifySignatureHex(challenge, signed, publicKey);
        assert(signatureMatches);
    });

    it('Delete passport key', async() => {
        await pass.deletePassportAccount();
        assert.strictEqual(Passport.passportAccountExists("test_hex"), false);
    });
});

describe('Passport test', function() {
    let publicKey, challenge, signed;
    it('Check if passport is available', () => {
        assert(Passport.passportAvailable());
    });

    const pass = new Passport("test");
    it('Create passport key', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        await pass.createPassportKey();
    });

    it('Check public key', async() => {
        publicKey = await pass.getPublicKey();
        assert.notStrictEqual(publicKey, null);
    });

    it('Get public key hash', async() => {
        const hash = await pass.getPublicKeyHash();
        const check = crypto.createHash('sha256')
            .update(Buffer.from(publicKey, 'hex'))
            .digest();

        assert.ok(hash.equals(check));
    });

    it('Generate challenge', function() {
        challenge = crypto.randomBytes(25);
        assert.strictEqual(challenge.length, 25);
    });

    it('Sign challenge', async function() {
        this.timeout(0); // No timeout since this requires user interaction
        signed = await pass.passportSign(challenge);
        assert.notStrictEqual(signed, null);
    });

    it('Verify signature', async function() {
        const signatureMatches = await Passport.verifySignature(challenge, signed, publicKey);
        assert(signatureMatches);
    });

    it('Delete passport key', async() => {
        await pass.deletePassportAccount();
        assert.strictEqual(Passport.passportAccountExists("test"), false);
    });

    it('Request verification', async() => {
        this.timeout(0);
        const res = await Passport.requestVerification("Testing");
        assert.strictEqual(res, VerificationResult.Verified);
    });
});