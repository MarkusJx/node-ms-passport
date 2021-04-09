const assert = require("assert");
const { passport, passport_utils, passwords, credentialStore } = require('./index');

describe('Passport hex test', function () {
    let publicKey, challenge, signed;
    it('Checking if passport is available', () => {
        assert(passport.passportAvailable());
    });

    const pass = new passport("test_hex");
    it('Creating passport key', async function () {
        this.timeout(0); // No timeout since this requires user interaction
        await pass.createPassportKey();
    });

    it('Checking public key', async () => {
        publicKey = await pass.getPublicKeyHex();
        assert.notStrictEqual(publicKey, null);
    });

    it('Generating challenge', function () {
        challenge = passport_utils.generateRandomHex(25);
        assert.strictEqual(challenge.length, 50);
    });

    it('Signing challenge', async function () {
        this.timeout(0); // No timeout since this requires user interaction
        signed = await pass.passportSignHex(challenge);
        assert.notStrictEqual(signed, null);
    });

    it('Verifying signature', async function () {
        const signatureMatches = await passport.verifySignatureHex(challenge, signed, publicKey);
        assert(signatureMatches);
    });

    it('Deleting passport key', async () => {
        await pass.deletePassportAccount();
        assert.strictEqual(passport.passportAccountExists("test_hex"), false);
    });
});

describe('Passport test', function () {
    let publicKey, challenge, signed;
    it('Checking if passport is available', () => {
        assert(passport.passportAvailable());
    });

    const pass = new passport("test");
    it('Creating passport key', async function () {
        this.timeout(0); // No timeout since this requires user interaction
        await pass.createPassportKey();
    });

    it('Checking public key', async () => {
        publicKey = await pass.getPublicKey();
        assert.notStrictEqual(publicKey, null);
    });

    it('Generating challenge', function () {
        challenge = passport_utils.generateRandom(25);
        assert.strictEqual(challenge.length, 25);
    });

    it('Signing challenge', async function () {
        this.timeout(0); // No timeout since this requires user interaction
        signed = await pass.passportSign(challenge);
        assert.notStrictEqual(signed, null);
    });

    it('Verifying signature', async function () {
        const signatureMatches = await passport.verifySignature(challenge, signed, publicKey);
        assert(signatureMatches);
    });

    it('Deleting passport key', async () => {
        await pass.deletePassportAccount();
        assert.strictEqual(passport.passportAccountExists("test"), false);
    });
});

describe('Credential manager test', function () {
    describe('with encryption', () => {
        const cred = new credentialStore("test/test", true);
        it('Credential write', async function () {
            assert(await cred.write("test", "testPassword"));
        });

        it('Credential read', async () => {
            const read = await cred.read();
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, "testPassword");
        });

        it('Password encrypted check', async () => {
            const encrypted = await cred.isEncrypted();
            assert(encrypted);
        });

        it('Credential delete', async () => {
            assert(await cred.remove());
        });
    });

    describe('without encryption', function () {
        const cred = new credentialStore("test/testRaw", false);
        it('Credential write', async () => {
            assert(await cred.write("test", "testPassword"));
        });

        it('Credential read', async () => {
            const read = await cred.read();
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, "testPassword");
        });

        it('Password encrypted check', async () => {
            const encrypted = await cred.isEncrypted();
            assert.strictEqual(encrypted, false);
        });

        it('Credential delete', async () => {
            assert(await cred.remove());
        });
    });
});

describe('Password encryption (hex)', function () {
    let data;
    it('Encrypt password', async () => {
        data = await passwords.encryptHex("TestPassword");
        assert.notStrictEqual(data, null);
    });

    it('Check if encrypted', async () => {
        let encrypted = await passwords.isEncryptedHex(data);
        assert(encrypted);
    });

    it('Check if throws on invalid hex string', function (done) {
        passwords.isEncryptedHex("data").then(() => {
            done("Should have thrown an exception");
        }, () => done());
    });

    it('Decrypt password', async () => {
        data = await passwords.decryptHex(data);
        assert.strictEqual(data, "TestPassword");
    });
});

describe('Password encryption', function () {
    let data;
    it('Encrypt password', async () => {
        data = await passwords.encrypt("TestPassword");
        assert.notStrictEqual(data, null);
    });

    it('Check if encrypted', async () => {
        let encrypted = await passwords.isEncrypted(data);
        assert(encrypted);
    });

    it('Check if throws on invalid hex string', function (done) {
        passwords.isEncrypted("data").then(() => {
            done("Should have thrown an exception");
        }, () => done());
    });

    it('Decrypt password', async () => {
        data = await passwords.decrypt(data);
        assert.strictEqual(data, "TestPassword");
    });
});