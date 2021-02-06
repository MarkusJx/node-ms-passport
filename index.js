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
    let version = require('child_process').execSync('ver').toString().trim();
    version = version.split("[")[1].replace("Version ", "").split(".")[0];
    if (Number(version) !== 10) {
        throw new Error("Windows version is not supported. Only windows 10 is supported");
    }
}

const path = require('path');
const passport_native = require(path.join(__dirname, 'bin', 'passport.node'));

// Set the location for the C# dll
passport_native.js_setCSharpDllLocation(path.join(__dirname, 'bin/'));

module.exports = {
    passport: class {
        constructor(accountId) {
            this.accountExists = this.constructor.passportAccountExists(accountId);
            Object.defineProperty(this, 'accountId', {
                value: accountId,
                enumerable: true,
                configurable: true,
                writable: false
            });
        }

        createPassportKey() {
            const res = passport_native.js_createPassportKey(this.accountId);
            if (res.status === 0) this.accountExists = true;

            return res;
        }

        async createPassportKeyAsync() {
            const res = await passport_native.js_createPassportKeyAsync(this.accountId);
            if (res.status === 0) this.accountExists = true;

            return res;
        }

        passportSign(challenge) {
            if (!this.accountExists) throw new Error("The passport account does not exist");
            return passport_native.js_passportSign(this.accountId, challenge);
        }

        passportSignAsync(challenge) {
            if (!this.accountExists) throw new Error("The passport account does not exist");
            return passport_native.js_passportSignAsync(this.accountId, challenge);
        }

        deletePassportAccount() {
            if (!this.accountExists) throw new Error("The passport account does not exist");

            const res = passport_native.js_deletePassportAccount(this.accountId);
            if (res === 0) this.accountExists = false;

            return res;
        }

        getPublicKey() {
            if (!this.accountExists) throw new Error("The passport account does not exist");
            return passport_native.js_getPublicKey(this.accountId);
        }

        getPublicKeyHash() {
            if (!this.accountExists) throw new Error("The passport account does not exist");
            return passport_native.js_getPublicKeyHash(this.accountId);
        }

        static passportAccountExists(accountId) {
            const res = passport_native.js_passportAccountExists(accountId);
            switch (res) {
                case 0:
                    return true;
                case 1:
                    return false;
                case 2:
                    throw new Error("An error occurred while trying to check if a passport account exists");
                default:
                    throw new Error("An unknown error occurred");
            };
        }

        static passportAvailable() {
            return passport_native.js_passportAvailable();
        }

        static verifySignature(challenge, signature, publicKey) {
            return passport_native.js_verifySignature(challenge, signature, publicKey);
        }
    },
    credentialStore: class {
        constructor(accountId, encryptPasswords = true) {
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

        write(user, password) {
            return passport_native.js_writeCredential(this.accountId, user, password, this.encryptPasswords);
        }

        read() {
            return passport_native.js_readCredential(this.accountId, this.encryptPasswords);
        }

        remove() {
            return passport_native.js_removeCredential(this.accountId);
        }

        isEncrypted() {
            return passport_native.js_credentialEncrypted(this.accountId);
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
        encrypt: function (data) {
            return passport_native.js_encryptPassword(data);
        },
        /**
         * Decrypt a password using CredUnprotect. Throws on error
         *
         * @param data {string} the data to decrypt as hex string
         * @returns {string} the result as string or null if unsuccessful
         */
        decrypt: function(data) {
            return passport_native.js_decryptPassword(data);
        },
        /**
         * Check if data was encrypted using CredProtect. Throws an error on error
         *
         * @param data {string} the data as hex string
         * @returns {boolean} if the password is encrypted
         */
        isEncrypted: function (data) {
            return passport_native.js_passwordEncrypted(data);
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
            return passport_native.js_generateRandom(length);
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