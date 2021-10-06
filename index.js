/**
 * node-ms-passport
 *
 * MIT License
 *
 * Copyright (c) 2020 - 2021 MarkusJx
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

const fs = require('fs');
const path = require('path');
const passport_native = loadNativeModule();
const dummies = require('./dummies');

// Set the location for the C# dll
if (passport_native) {
    passport_native.setCSharpDllLocation(path.join(__dirname, 'bin/'));
}

function loadNativeModule() {
    const p = path.join(__dirname, 'bin', 'passport.node');
    if (fs.existsSync(p) && process.platform === 'win32') {
        return require(p);
    } else {
        if (process.platform === 'win32') {
            const version = require('child_process').execSync('ver', { encoding: 'utf-8' }).toString().trim()
                .split('[')[1].split(' ')[1].split('.')[0];
            if (Number(version) >= 10) {
                throw new Error("The platform is windows 10 but the native module could not be found");
            }
        }
        return null;
    }
}

/**
 * A passport error
 */
class PassportError extends Error {
    /**
     * Create a passport error
     * 
     * @param {string} message the error message
     * @param {number} code the error code
     */
    constructor(message, code) {
        super(message);
        this.name = "PassportError";
        this.code = code;

        if (typeof code !== 'number') {
            throw new Error("Parameter 'code' must be typeof 'number'");
        } else if (typeof message !== 'string') {
            throw new Error("Parameter 'message' must be typeof 'string'");
        }
    }

    /**
     * Get the error code
     * 
     * @returns {number} the error code
     */
    getCode() {
        return this.code;
    }
}

/**
 * Rethrow an error
 * 
 * @param {Error} e the error to rethrow
 */
function rethrowError(e) {
    const regex = /^\w+#\d{0,2}$/g;
    if (regex.test(e.message)) {
        const parts = e.message.split('#');
        throw new PassportError(parts[0], Number(parts[1]));
    } else {
        throw e;
    }
}

const errorCodes = {
    ERR_ANY: -1,
    ERR_UNKNOWN: 1,
    ERR_MISSING_PIN: 2,
    ERR_USER_CANCELLED: 3,
    ERR_USER_PREFERS_PASSWORD: 4,
    ERR_ACCOUNT_NOT_FOUND: 5,
    ERR_SIGN_OP_FAILED: 6,
    ERR_KEY_ALREADY_DELETED: 7,
    ERR_ACCESS_DENIED: 8
};

/**
 * Microsoft passport for node js
 */
class Passport {
    /**
     * Create a passport instance
     * 
     * @param {string} accountId the id of the passport account
     */
    constructor(accountId) {
        if (typeof accountId !== 'string') {
            throw new Error("Parameter 'accountId' must be typeof 'string'");
        } else if (accountId.length === 0) {
            throw new Error("Parameter 'accountId' must not be empty");
        }

        this.accountExists = this.constructor.passportAccountExists(accountId);
        Object.defineProperty(this, 'accountId', {
            value: accountId,
            enumerable: true,
            configurable: true,
            writable: false
        });
    }

    /**
     * Create a microsoft passport key asynchronously
     * 
     * @returns {Promise<void>}
     */
    async createPassportKey() {
        try {
            await passport_native.createPassportKey(this.accountId);
            this.accountExists = true;
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Sign a challenge
     *
     * @param {string} challenge the challenge to sign
     * @returns {Promise<string>} the signature as a hex string
     */
    async passportSignHex(challenge) {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            return await passport_native.passportSignHex(this.accountId, challenge);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Sign a challenge
     *
     * @param {Buffer} challenge the challenge to sign
     * @returns {Promise<Buffer>} the signature in a buffer
     */
    async passportSign(challenge) {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            return await passport_native.passportSign(this.accountId, challenge);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Delete a passport account
     * 
     * @returns {Promise<void>}
     */
    async deletePassportAccount() {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            await passport_native.deletePassportAccount(this.accountId);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Get the public key
     *
     * @returns {Promise<string>} the public key as a hex string
     */
    async getPublicKeyHex() {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            return await passport_native.getPublicKeyHex(this.accountId);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Get the public key
     *
     * @returns {Promise<Buffer>} the public key in a buffer
     */
    async getPublicKey() {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            return await passport_native.getPublicKey(this.accountId);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Get a SHA-256 hash of the public key
     *
     * @returns {Promise<string>} the hashed public key as a hex string
     */
    async getPublicKeyHashHex() {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            return await passport_native.getPublicKeyHashHex(this.accountId);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Get a SHA-256 hash of the public key
     *
     * @returns {Promise<Buffer>} the hashed public key in a buffer
     */
    async getPublicKeyHash() {
        if (!this.accountExists)
            throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
        try {
            return await passport_native.getPublicKeyHash(this.accountId);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Check if a passport account exists
     * 
     * @param {string} accountId the id of the account to check
     * @returns {boolean} true, if the account with the given id exists
     */
    static passportAccountExists(accountId) {
        try {
            return passport_native.passportAccountExists(accountId);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Check if ms passport is available on this machine
     *
     * @returns {boolean} true if passport is available
     */
    static passportAvailable() {
        try {
            return passport_native.passportAvailable();
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Verify a challenge signed by passport
     *
     * @param {string} challenge the challenge used
     * @param {string} signature the signature returned
     * @param {string} publicKey the public key of the application
     * @returns {boolean} true, if the signature matches
     */
    static async verifySignatureHex(challenge, signature, publicKey) {
        try {
            return await passport_native.verifySignatureHex(challenge, signature, publicKey);
        } catch (e) {
            rethrowError(e);
        }
    }

    /**
     * Verify a challenge signed by passport
     *
     * @param {Buffer} challenge the challenge used
     * @param {Buffer} signature the signature returned
     * @param {Buffer} publicKey the public key of the application
     * @returns {boolean} true, if the signature matches
     */
    static async verifySignature(challenge, signature, publicKey) {
        try {
            return await passport_native.verifySignature(challenge, signature, publicKey);
        } catch (e) {
            rethrowError(e);
        }
    }
}

/**
 * Password encryption using windows APIs
 */
const passwords = {
    /**
     * Encrypt a password using CredProtect. Throws on error
     *
     * @param {string} data the data to encrypt
     * @returns {Promise<string>} the result as hex string or null if unsuccessful
     */
    encryptHex: async function(data) {
        return await passport_native.encryptPasswordHex(data);
    },
    /**
     * Encrypt a password using CredProtect. Throws on error
     * 
     * @param {string} data the data to encrypt
     * @returns {Promise<Buffer>} the result in a buffer or null if unsuccessful
     */
    encrypt: async function(data) {
        return await passport_native.encryptPassword(data);
    },
    /**
     * Decrypt a password using CredUnprotect. Throws on error
     *
     * @param {string} data the data to decrypt as hex string
     * @returns {Promise<string>} the result as string or null if unsuccessful
     */
    decryptHex: async function(data) {
        return await passport_native.decryptPasswordHex(data);
    },
    /**
     * Decrypt a password using CredUnprotect. Throws on error
     *
     * @param {Buffer} data the data to decrypt as hex string
     * @returns {Promise<string>} the result as string or null if unsuccessful
     */
    decrypt: async function(data) {
        return await passport_native.decryptPassword(data);
    },
    /**
     * Check if data was encrypted using CredProtect. Throws an error on error
     *
     * @param {string} data the data as hex string
     * @returns {Promise<boolean>} if the password is encrypted
     */
    isEncryptedHex: async function(data) {
        return await passport_native.passwordEncryptedHex(data);
    },
    /**
     * Check if data was encrypted using CredProtect. Throws an error on error
     *
     * @param {Buffer} data the data in a buffer
     * @returns {Promise<boolean>} if the password is encrypted
     */
    isEncrypted: async function(data) {
        return await passport_native.passwordEncrypted(data);
    }
}

module.exports = {
    PassportError: passport_native ? PassportError : dummies.PassportError,
    errorCodes: errorCodes,
    Passport: passport_native ? Passport : dummies.Passport,
    CredentialStore: passport_native ? passport_native.CredentialStore : dummies.CredentialStore,
    Credential: passport_native ? passport_native.Credential : dummies.Credential,
    passwords: passport_native ? passwords : dummies.passwords,
    /**
     * Passport C++ library variables
     */
    passport_lib: {
        include_dir: path.join(__dirname, 'cpp_src'),
        library_dir: path.join(__dirname, 'lib'),
        library: path.join(__dirname, 'lib', 'NodeMsPassport.lib')
    }
}