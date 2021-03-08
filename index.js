/**
 * node-ms-passport
 *
 * MIT License
 *
 * Copyright (c) 2020 MarkusJx
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

// Check if this runs on windows and check if this is windows 10
if (process.platform !== 'win32') {
    throw new Error("OS is not supported. Only windows 10 is supported");
} else {
    let version = require('child_process').execSync('ver', { encoding: 'utf-8' }).toString().trim();
        version = version.split('[')[1].split(' ')[1].split('.')[0];
    if (Number(version) !== 10) {
        throw new Error("Windows version is not supported. Only windows 10 is supported");
    }
}

const path = require('path');
const passport_native = require(path.join(__dirname, 'bin', 'passport.node'));

// Set the location for the C# dll
passport_native.setCSharpDllLocation(path.join(__dirname, 'bin/'));

class PassportError extends Error {
    #code = -1;

    constructor(message, code) {
        super(message);
        this.name = "PassportError";
        this.#code = code;

        if (typeof code !== 'number') {
            throw new Error("Parameter 'code' must be typeof 'number'");
        } else if (typeof message !== 'string') {
            throw new Error("Parameter 'message' must be typeof 'string'");
        }
    }

    getCode() {
        return this.#code;
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

module.exports = {
    PassportError: PassportError,
    errorCodes: errorCodes,
    passport: class {
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

        async createPassportKey() {
            try {
                await passport_native.createPassportKey(this.accountId);
                this.accountExists = true;
            } catch (e) {
                rethrowError(e);
            }
        }

        async passportSign(challenge) {
            if (!this.accountExists)
                throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
            try {
                return await passport_native.passportSign(this.accountId, challenge);
            } catch (e) {
                rethrowError(e);
            }
        }

        async deletePassportAccount() {
            if (!this.accountExists)
                throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
            try {
                await passport_native.deletePassportAccount(this.accountId);
            } catch (e) {
                rethrowError(e);
            }
        }

        async getPublicKey() {
            if (!this.accountExists)
                throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
            try {
                return await passport_native.getPublicKey(this.accountId);
            } catch (e) {
                rethrowError(e);
            }
        }

        async getPublicKeyHash() {
            if (!this.accountExists)
                throw new PassportError("The passport account does not exist", errorCodes.ERR_ACCOUNT_NOT_FOUND);
            try {
                return await passport_native.getPublicKeyHash(this.accountId);
            } catch (e) {
                rethrowError(e);
            }
        }

        static passportAccountExists(accountId) {
            try {
                return passport_native.passportAccountExists(accountId);
            } catch (e) {
                rethrowError(e);
            }
        }

        static passportAvailable() {
            try {
                return passport_native.passportAvailable();
            } catch (e) {
                rethrowError(e);
            }
        }

        static async verifySignature(challenge, signature, publicKey) {
            try {
                return await passport_native.verifySignature(challenge, signature, publicKey);
            } catch (e) {
                rethrowError(e);
            }
        }
    },
    credentialStore: class {
        constructor(accountId, encryptPasswords = true) {
            if (typeof accountId !== 'string') {
                throw new Error("Parameter 'accountId' must be typeof 'string'");
            } else if (accountId.length === 0) {
                throw new Error("Parameter 'accountId' must not be empty");
            } else if (typeof encryptPasswords !== 'boolean') {
                throw new Error("Parameter 'encryptPasswords' must be typeof'boolean'");
            }

            Object.defineProperty(this, 'accountId', {
                value: accountId,
                enumerable: true,
                configurable: true,
                writable: false
            });

            Object.defineProperty(this, 'encryptPasswords', {
                value: encryptPasswords,
                enumerable: true,
                configurable: true,
                writable: false
            });
        }

        async write(user, password) {
            return await passport_native.writeCredential(this.accountId, user, password, this.encryptPasswords);
        }

        async read() {
            return await passport_native.readCredential(this.accountId, this.encryptPasswords);
        }

        async remove() {
            return await passport_native.removeCredential(this.accountId);
        }

        async isEncrypted() {
            return await passport_native.credentialEncrypted(this.accountId);
        }
    },
    /**
     * Password encryption using windows APIs
     */
    passwords: {
        /**
         * Encrypt a password using CredProtect. Throws on error
         *
         * @param data {string} the data to encrypt
         * @returns {string} the result as hex string or null if unsuccessful
         */
        encrypt: async function (data) {
            return await passport_native.encryptPassword(data);
        },
        /**
         * Decrypt a password using CredUnprotect. Throws on error
         *
         * @param data {string} the data to decrypt as hex string
         * @returns {string} the result as string or null if unsuccessful
         */
        decrypt: async function (data) {
            return await passport_native.decryptPassword(data);
        },
        /**
         * Check if data was encrypted using CredProtect. Throws an error on error
         *
         * @param data {string} the data as hex string
         * @returns {boolean} if the password is encrypted
         */
        isEncrypted: async function (data) {
            return await passport_native.passwordEncrypted(data);
        }
    },
    /**
     * Utilities
     */
    passport_utils: {
        /**
         * Generate random bytes
         *
         * @param length {number} the length of the challenge in bytes
         * @return {string} the random bytes as hex string
         */
        generateRandom: function (length) {
            return passport_native.generateRandom(length);
        }
    },
    /**
     * Passport C++ library variables
     */
    passport_lib: {
        include_dir: path.join(__dirname, 'cpp_src'),
        library_dir: path.join(__dirname, 'lib'),
        library: path.join(__dirname, 'lib', 'NodeMsPassport.lib')
    }
}