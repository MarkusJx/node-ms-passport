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

const passport_native = require('./passport/' + ((process.arch === 'x64') ? 'x64' : 'x86') + '/passport.node');

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
         * @return {{status: number, data: string | null}} the status, equals to 0 if everything is ok. If so,
         *         data will contain the public key as hex string
         */
        createPassportKey: function (accountId) {
            return passport_native.js_createPassportKey(accountId);
        },
        /**
         * Sign a challenge
         *
         * @param accountId {string} the account id
         * @param challenge {string} the challenge to sign
         * @return {{status: number, data: string | null}} the status, equals to 0 if everything is ok. If so,
         *         data will contain the signature as hex string
         */
        passportSign: function (accountId, challenge) {
            return passport_native.js_passportSign(accountId, challenge);
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
         * @return {{status: number, data: string | null}} the status, equals to 0 if everything is ok. If so,
         *         data will contain the public key as hex string
         */
        getPublicKey: function (accountId) {
            return passport_native.js_getPublicKey(accountId);
        },
        /**
         * Get a SHA-256 hash of the public key
         *
         * @param accountId {string} the account id for the public key to get
         * @return {{status: number, data: string | null}} the status, equals to 0 if everything is ok. If so,
         *         data will contain the public key hash as hex string
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
         * @return {boolean} if the operation was successful
         */
        write: function (target, user, password) {
            return passport_native.js_writeCredential(target, user, password);
        },
        /**
         * Read data from the password storage
         *
         * @param target {string} the account id
         * @return {{username: string, password: string} | null} the username and password or null if unsuccessful
         */
        read: function (target) {
            return passport_native.js_readCredential(target);
        },
        /**
         * Remove a entry from the credential storage
         *
         * @param target {string} the account id to remove
         * @return {boolean} if the operation was successful
         */
        remove(target) {
            return passport_native.js_removeCredential(target);
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
    }
}