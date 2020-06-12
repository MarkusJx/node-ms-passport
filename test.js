const assert = require("assert");
const {describe} = require("mocha");
const {passport, passport_utils, credentials} = require('./node-ms-passport');

describe('Passport test', function () {
    let createRes, publicKey, challenge, signed;
    it('Checking if passport is available', () => {
        assert(passport.passportAvailable());
    });
    it('Creating passport key', function () {
        this.timeout(0); // No timeout since this requires user interaction
        createRes = passport.createPassportKey("test");
        assert.strictEqual(createRes.status, 0);
    });
    it('Checking public key', function () {
        publicKey = passport.getPublicKey("test");
        assert.strictEqual(publicKey.status, 0);
        assert.strictEqual(publicKey.data, createRes.data);
    });
    it('Generating challenge', function () {
        challenge = passport_utils.generateRandom(25);
        assert.strictEqual(challenge.length, 50);
    });
    it('Signing challenge', function () {
        this.timeout(0); // No timeout since this requires user interaction
        signed = passport.passportSign("test", challenge);
        assert.strictEqual(signed.status, 0);
    });
    it('Verifying signature', function () {
        const signatureMatches = passport.verifySignature(challenge, signed.data, createRes.data);
        assert(signatureMatches);
    });
    it('Deleting passport key', function () {
        const deleted = passport.deletePassportAccount("test");
        assert.strictEqual(deleted, 0);
    });
});

describe('Credential manager test', function () {
    it('Credential write', function () {
        assert(credentials.write("test/test", "test", "testPassword"));
    });
    it('Credential read', function () {
        const read = credentials.read("test/test");
        assert.notStrictEqual(read, null);
        assert.strictEqual(read.username, "test");
        assert.strictEqual(read.password, "testPassword");
    });
    it('Credential delete', function () {
        assert(credentials.remove("test/test"));
    });
});
