const assert = require("assert");
const {passport, passport_utils, credentials, passwords} = require('./index');


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
    it('Deleting passport key', function () {
        const deleted = passport.deletePassportAccount("test");
        assert.strictEqual(deleted, 0);
    });
    it('Creating passport key asynchronously', async function () {
        this.timeout(0);
        createRes = await passport.createPassportKeyAsync("test");
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
    it('Signing challenge asynchronously', async function () {
        this.timeout(0);
        signed = await passport.passportSignAsync("test", challenge);
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
    describe('with encryption', function () {
        it('Credential write', function () {
            assert(credentials.write("test/test", "test", "testPassword"));
        });
        it('Credential read', function () {
            const read = credentials.read("test/test");
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, "testPassword");
        });
        it('Password encrypted check', function () {
            const encrypted = credentials.isEncrypted("test/test");
            assert(encrypted);
        });
        it('Credential delete', function () {
            assert(credentials.remove("test/test"));
        });
    });
    describe('without encryption', function () {
        it('Credential write', function () {
            assert(credentials.write("test/testRaw", "test", "testPassword", false));
        });
        it('Credential read', function () {
            const read = credentials.read("test/testRaw", false);
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, "testPassword");
        });
        it('Password encrypted check', function () {
            const encrypted = credentials.isEncrypted("test/testRaw");
            assert.strictEqual(encrypted, false);
        });
        it('Credential delete', function () {
            assert(credentials.remove("test/testRaw"));
        });
    });
});

describe('Password encryption', function () {
    let data;
    it('Encrypt password', function () {
        data = passwords.encrypt("TestPassword");
        assert.notStrictEqual(data, null);
    });
    it('Check if encrypted', function () {
        let encrypted = passwords.isEncrypted(data);
        assert(encrypted);
    });
    it('Check if throws on invalid hex string', function () {
        assert.throws(function () {
            passwords.isEncrypted("data");
        }, new Error("Invalid character: 't' is not a valid hex digit"));
    });
    it('Decrypt password', function () {
        data = passwords.decrypt(data);
        assert.strictEqual(data, "TestPassword");
    });
});