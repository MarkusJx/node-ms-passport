const assert = require("assert");
const { passwords, CredentialStore } = require('../index');

if (process.platform !== 'win32') {
    console.log("INFO: Skipping passwords and CredentialStore tests since running on unix");
    return;
}

it('Check if the module is available', () => {
    assert.ok(!nodeMsPassportAvailable());
});

describe('Credential manager test', function() {
    describe('with encryption', () => {
        const cred = new CredentialStore("test/test", true);
        it('Credential write', async function() {
            await cred.write("test", "testPassword");
            assert.ok(await cred.exists());
        });

        it('Credential read', async() => {
            const read = await cred.read();
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, null);

            await read.loadPassword();
            assert.strictEqual(read.password, "testPassword")
        });

        it('Password encrypted check', async() => {
            const encrypted = await cred.isEncrypted();
            assert.ok(encrypted);
        });

        it('Credential delete', async() => {
            await cred.remove();
            assert.ok(!await cred.exists());
        });

        it('Invalid credential read', (done) => {
            cred.read().then(() => {
                done("Should have thrown");
            }).catch(() => {
                done();
            });
        });
    });

    describe('without encryption', function() {
        const cred = new CredentialStore("test/testRaw", false);
        it('Credential write', async() => {
            await cred.write("test", "testPassword");
            assert.ok(await cred.exists());
        });

        it('Credential read', async() => {
            const read = await cred.read();
            assert.notStrictEqual(read, null);
            assert.strictEqual(read.username, "test");
            assert.strictEqual(read.password, null);

            await read.loadPassword();
            assert.strictEqual(read.password, "testPassword")
        });

        it('Password encrypted check', async() => {
            const encrypted = await cred.isEncrypted();
            assert.strictEqual(encrypted, false);
        });

        it('Credential delete', async() => {
            await cred.remove();
            assert.ok(!await cred.exists());
        });

        it('Invalid credential read', (done) => {
            cred.read().then(() => {
                done("Should have thrown");
            }).catch(() => {
                done();
            });
        });
    });

    describe('Credential test', function() {
        const store = new CredentialStore("test/test", true);
        /**
         * @type {Credential}
         */
        let cred = null;
        it('Read', async() => {
            await store.write("test", "testPassword");
            assert.ok(await store.exists());

            cred = await store.read();
        });

        it('Account id read', () => {
            assert.strictEqual(cred.accountId, "test/test");
        });

        it('Username read', () => {
            assert.strictEqual(cred.username, "test");
        });

        it('Password read', () => {
            assert.strictEqual(cred.password, null);
        });

        it('Password load', async() => {
            assert.strictEqual(cred.password, null);

            await cred.loadPassword();
            assert.strictEqual(cred.password, "testPassword");
        });

        it('Password buffer check', () => {
            assert.ok(cred.passwordBuffer.length > 0);
        });

        it('Password unload', async() => {
            assert.strictEqual(cred.password, "testPassword");

            await cred.unloadPassword();
            assert.strictEqual(cred.password, null);
        });

        it('Is encrypted check', async() => {
            assert.ok(cred.encrypted);
            assert.ok(await cred.isEncrypted());
        });

        it('Update', async() => {
            await cred.loadPassword();
            await cred.update("newUser", "newPass");

            assert.strictEqual(cred.username, "newUser");
            assert.strictEqual(cred.password, null);

            await cred.loadPassword();
            assert.strictEqual(cred.password, "newPass");
        });

        it('Refresh data', async() => {
            const c1 = await store.read();
            await c1.loadPassword();
            assert.strictEqual(c1.username, "newUser");
            assert.strictEqual(c1.password, "newPass");

            await c1.update("user", "pass");
            assert.strictEqual(c1.username, "user");
            assert.strictEqual(c1.password, null);

            await c1.loadPassword();
            assert.strictEqual(c1.password, "pass");

            await cred.refreshData();
            assert.strictEqual(cred.username, "user");
            assert.strictEqual(cred.password, null);

            await cred.loadPassword();
            assert.strictEqual(cred.password, "pass");
        });

        it('Set encrypted', async() => {
            await cred.setEncrypted(false);
            assert.ok(!cred.encrypted);
            assert.ok(!await cred.isEncrypted());
            assert.ok(!await store.isEncrypted());
            assert.strictEqual(cred.password, null);

            await cred.loadPassword();
            assert.strictEqual(cred.password, "pass");

            await cred.setEncrypted(true);
            assert.ok(cred.encrypted);
            assert.ok(await cred.isEncrypted());
            assert.ok(await store.isEncrypted());
            assert.strictEqual(cred.password, null);

            await cred.loadPassword();
            assert.strictEqual(cred.password, "pass");
        });
    });

    describe('Enumerate test', async() => {
        const cred = new CredentialStore("test/testEnum");
        await cred.write("test", "test");

        it('Read all', async() => {
            let read = await CredentialStore.enumerateAccounts();

            assert.ok(read.length >= 1);
            assert.notStrictEqual(read.find(e => e.accountId == "test/testEnum" && e.username == "test"), undefined);
        });

        it('Wildcard read', async() => {
            let read = await CredentialStore.enumerateAccounts("test*");

            assert.ok(read.length >= 1);
            assert.notStrictEqual(read.find(e => e.accountId == "test/testEnum" && e.username == "test"), undefined);
        });

        it('Exact read', async() => {
            let read = await CredentialStore.enumerateAccounts("test/testEnum");

            assert.ok(read.length >= 1);
            assert.notStrictEqual(read.find(e => e.accountId == "test/testEnum" && e.username == "test"), undefined);
        });

        await cred.remove();
    });
});

describe('Password encryption (hex)', function() {
    let data;
    it('Encrypt password', async() => {
        data = await passwords.encryptHex("TestPassword");
        assert.notStrictEqual(data, null);
    });

    it('Check if encrypted', async() => {
        let encrypted = await passwords.isEncryptedHex(data);
        assert(encrypted);
    });

    it('Check if throws on invalid hex string', function(done) {
        passwords.isEncryptedHex("data").then(() => {
            done("Should have thrown an exception");
        }, () => done());
    });

    it('Decrypt password', async() => {
        data = await passwords.decryptHex(data);
        assert.strictEqual(data, "TestPassword");
    });
});

describe('Password encryption', function() {
    let data;
    it('Encrypt password', async() => {
        data = await passwords.encrypt("TestPassword");
        assert.notStrictEqual(data, null);
    });

    it('Check if encrypted', async() => {
        let encrypted = await passwords.isEncrypted(data);
        assert(encrypted);
    });

    it('Check if throws on invalid hex string', function(done) {
        passwords.isEncrypted("data").then(() => {
            done("Should have thrown an exception");
        }, () => done());
    });

    it('Decrypt password', async() => {
        data = await passwords.decrypt(data);
        assert.strictEqual(data, "TestPassword");
    });
});