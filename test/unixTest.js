const assert = require("assert");
const { passwords, CredentialStore, Credential, Passport, PassportError, PassportModule } = require('../index');

if (process.platform === 'win32') {
    console.log("INFO: Skipping unix tests since running on windows");
    return;
}

const error = new Error("Your current platform is not supported");

it('Check if the module is available', () => {
    assert.ok(!PassportModule.available());
});

describe('Dummy test', () => {
    it('PassportError creation', () => {
        assert.throws(() => new PassportError(), error);
    });

    describe('Passport test', () => {
        it('Passport creation', () => {
            assert.throws(() => new Passport(), error);
        });

        it('Account exists', () => {
            assert.throws(() => Passport.passportAccountExists(), error);
        });

        it('Passport available', () => {
            assert.throws(() => Passport.passportAvailable(), error);
        })

        it('Verify signature (hex)', () => {
            assert.throws(() => Passport.verifySignatureHex(), error);
        });

        it('Verify signature', () => {
            assert.throws(() => Passport.verifySignature(), error);
        });
    });

    it('Credential creation', () => {
        assert.throws(() => new Credential(), error);
    });

    it('CredentialStore creation', () => {
        assert.throws(() => new CredentialStore(), error);
    });

    describe('Passwords test', () => {
        it('Encrypt (hex)', () => {
            assert.throws(() => passwords.encryptHex(), error);
        });

        it('Encrypt', () => {
            assert.throws(() => passwords.encrypt(), error);
        });

        it('Decrypt (hex)', () => {
            assert.throws(() => passwords.decryptHex(), error);
        });

        it('Decrypt', () => {
            assert.throws(() => passwords.decrypt(), error);
        });

        it('Is encrypted (hex)', () => {
            assert.throws(() => passwords.isEncryptedHex(), error);
        });

        it('Is encrypted', () => {
            assert.throws(() => passwords.isEncrypted(), error);
        });
    });
});