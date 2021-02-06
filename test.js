const assert = require("assert");
const { passport, passport_utils, passwords, credentialStore } = require('./index');

describe('Passport test', function () {
    let createRes, publicKey, challenge, signed;
    it('Checking if passport is available', () => {
        assert(passport.passportAvailable());
    });

    const pass = new passport("test");
    it('Creating passport key', function () {
        this.timeout(0); // No timeout since this requires user interaction
        createRes = pass.createPassportKey();
        assert.strictEqual(createRes.status, 0);
    });

    it('Deleting passport key', () => {
        const deleted = pass.deletePassportAccount();
        assert.strictEqual(deleted, 0);
    });

    it('Creating passport key asynchronously', async function () {
        this.timeout(0);
        createRes = await pass.createPassportKeyAsync();
        assert.strictEqual(createRes.status, 0);
    });

    it('Checking public key', () => {
        publicKey = pass.getPublicKey();
        assert.strictEqual(publicKey.status, 0);
        assert.strictEqual(publicKey.data, createRes.data);
    });

    it('Generating challenge', function () {
        challenge = passport_utils.generateRandom(25);
        assert.strictEqual(challenge.length, 50);
    });

    it('Signing challenge', function () {
        this.timeout(0); // No timeout since this requires user interaction
        signed = pass.passportSign(challenge);
        assert.strictEqual(signed.status, 0);
    });

    it('Verifying signature', function () {
        const signatureMatches = passport.verifySignature(challenge, signed.data, createRes.data);
        assert(signatureMatches);
    });

    it('Signing challenge asynchronously', async function () {
        this.timeout(0);
        signed = await pass.passportSignAsync(challenge);
        assert.strictEqual(signed.status, 0);
    });

    it('Verifying signature', function () {
        const signatureMatches = passport.verifySignature(challenge, signed.data, createRes.data);
        assert(signatureMatches);
    });

    it('Deleting passport key', () => {
        const deleted = pass.deletePassportAccount();
        assert.strictEqual(deleted, 0);
    });
});

describe('Credential manager test', function () {
    describe('with encryption', () => {
        const cred = new credentialStore("test/test", true);
        it('Credential write', function () {
            assert(cred.write("test", "testPassword"));
        });

        it('Credential read', () => {
            const read = cred.read();
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, "testPassword");
        });

        it('Password encrypted check', () => {
            const encrypted = cred.isEncrypted();
            assert(encrypted);
        });

        it('Credential delete', () => {
            assert(cred.remove());
        });
    });

    describe('without encryption', function () {
        const cred = new credentialStore("test/testRaw", false);
        it('Credential write', () => {
            assert(cred.write("test", "testPassword"));
        });

        it('Credential read', () => {
            const read = cred.read();
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, "testPassword");
        });

        it('Password encrypted check', () => {
            const encrypted = cred.isEncrypted();
            assert.strictEqual(encrypted, false);
        });

        it('Credential delete', () => {
            assert(cred.remove());
        });
    });
});

describe('Password encryption', function () {
    let data;
    it('Encrypt password', () => {
        data = passwords.encrypt("TestPassword");
        assert.notStrictEqual(data, null);
    });

    it('Check if encrypted', () => {
        let encrypted = passwords.isEncrypted(data);
        assert(encrypted);
    });

    it('Check if throws on invalid hex string', function () {
        assert.throws(function () {
            passwords.isEncrypted("data");
        }, new Error("Invalid character: 't' is not a valid hex digit"));
    });

    it('Decrypt password', () => {
        data = passwords.decrypt(data);
        assert.strictEqual(data, "TestPassword");
    });
});