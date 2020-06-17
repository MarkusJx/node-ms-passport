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

const passport_native = require('./passport/' + ((process.arch === 'x64') ? 'x64' : 'x86') + '/bin/passport.node');

module.exports = {
    /**
     * Microsoft passport for node js
     *
     * If the status is zero, everything was ok, 1 if a unknown error occurred, 2 if the user needs to create a pin,
     * 3 if the user cancelled the process
     */
    passport: {
        /**
         * Check if ms passport is available on this machine
         *
         * @returns {boolean} true if passport is available
         */
        passportAvailable: function () {
            return passport_native.js_passportAvailable();
        },
        /**
         * Create a microsoft passport key
         *
         * @param accountId {string} the account id to add
         * @return {{status: number, ok: boolean, data: string | null}} the status, equals to 0 if everything is ok.
         *          If so, data will contain the public key as hex string
         */
        createPassportKey: function (accountId) {
            return passport_native.js_createPassportKey(accountId);
        },
        /**
         * Create a microsoft passport key asynchronously
         *
         * @param accountId {string} the account id to add
         * @return {promise.<{status: number, ok: boolean, data: string | null}>} the status, equals to 0 if everything is ok.
         *          If so, data will contain the public key as hex string
         */
        createPassportKeyAsync: function (accountId) {
            return passport_native.js_createPassportKeyAsync(accountId);
        },
        /**
         * Sign a challenge
         *
         * @param accountId {string} the account id
         * @param challenge {string} the challenge to sign
         * @return {{status: number, ok: boolean, data: string | null}} the status, equals to 0 if everything is ok.
         *         If so, data will contain the signature as hex string
         */
        passportSign: function (accountId, challenge) {
            return passport_native.js_passportSign(accountId, challenge);
        },
        /**
         * Sign a challenge asynchronously
         *
         * @param accountId {string} the account id
         * @param challenge {string} the challenge to sign
         * @return {promise.<{status: number, ok: boolean, data: string | null}>} the status, equals to 0 if everything is ok.
         *         If so, data will contain the signature as hex string
         */
        passportSignAsync: function (accountId, challenge) {
            return passport_native.js_passportSignAsync(accountId, challenge);
        },
        /**
         * Delete a passport account
         *
         * @param accountId {string} the account to delete
         * @return {number} 0, if the account could be deleted, 1, if a unknown error occurred, 2,
         *         if the access was denied and 3, if the key is already deleted
         */
        deletePassportAccount: function (accountId) {
            return passport_native.js_deletePassportAccount(accountId);
        },
        /**
         * Get the public key
         *
         * @param accountId {string} the account id for the public key to get
         * @return {{status: number, ok: boolean, data: string | null}} the status, equals to 0 if everything is ok.
         *         If so, data will contain the public key as hex string
         */
        getPublicKey: function (accountId) {
            return passport_native.js_getPublicKey(accountId);
        },
        /**
         * Get a SHA-256 hash of the public key
         *
         * @param accountId {string} the account id for the public key to get
         * @return {{status: number, ok: boolean, data: string | null}} the status, equals to 0 if everything is ok.
         *         If so, data will contain the public key hash as hex string
         */
        getPublicKeyHash: function (accountId) {
            return passport_native.js_getPublicKeyHash(accountId);
        },
        /**
         * Verify a challenge signed by passport
         *
         * @param challenge {string} the challenge used
         * @param signature {string} the signature returned
         * @param publicKey {string} the public key of the application
         * @return {boolean} if the signature matches
         */
        verifySignature: function (challenge, signature, publicKey) {
            return passport_native.js_verifySignature(challenge, signature, publicKey);
        }
    },
    /**
     * Windows credential storage for node js
     */
    credentials: {
        /**
         * Write data to the password storage
         *
         * @param {string} target the account id
         * @param {string} user the user name to store
         * @param {string} password the password to store
         * @param {boolean} encrypt whether to encrypt the password
         * @return {boolean} if the operation was successful
         */
        write: function (target, user, password, encrypt = true) {
            return passport_native.js_writeCredential(target, user, password, encrypt);
        },
        /**
         * Read data from the password storage
         *
         * @param target {string} the account id
         * @param {boolean} encrypt whether the password is encrypted
         * @return {{username: string, password: string} | null} the username and password or null if unsuccessful
         */
        read: function (target, encrypt = true) {
            return passport_native.js_readCredential(target, encrypt);
        },
        /**
         * Remove a entry from the credential storage
         *
         * @param target {string} the account id to remove
         * @return {boolean} if the operation was successful
         */
        remove(target) {
            return passport_native.js_removeCredential(target);
        },
        /**
         * Check if a password entry is encrypted. Throws an error on error
         *
         * @param target {string} the account id to check
         * @return {boolean} if the password is encrypted
         */
        isEncrypted: function (target) {
            return passport_native.js_credentialEncrypted(target);
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
        library_dir32: __dirname + "\\passport\\x86\\lib",
        library_dir64: __dirname + "\\passport\\x64\\lib",
        library_dir: __dirname + "\\passport\\" + ((process.arch === 'x64') ? 'x64' : 'x86') + "\\lib",
        library32: __dirname + "\\passport\\x86\\lib\\NodeMsPassport.lib",
        library64: __dirname + "\\passport\\x64\\lib\\NodeMsPassport.lib",
        binary_dir32: __dirname + "\\passport\\x86\\bin",
        binary_dir64: __dirname + "\\passport\\x64\\bin",
        binary_dir: __dirname + "\\passport\\" + ((process.arch === 'x64') ? 'x64' : 'x86') + "\\bin",
        binary32: __dirname + "\\passport\\x86\\bin\\NodeMsPassport.dll",
        binary64: __dirname + "\\passport\\x64\\bin\\NodeMsPassport.dll"
    },
    include: __dirname + "\\passport\\include",
    library: __dirname + "\\passport\\" + ((process.arch === 'x64') ? 'x64' : 'x86') + "\\lib\\NodeMsPassport.lib",
    binary: __dirname + "\\passport\\" + ((process.arch === 'x64') ? 'x64' : 'x86') + "\\bin\\NodeMsPassport.dll"
}