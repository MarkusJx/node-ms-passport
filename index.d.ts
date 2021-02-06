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

import { passport_lib } from ".";

/**
 * A passport operation result
 */
export type passportResult = {
    // The status. Equals to zero, if everything was ok,
    // if it is 1, an unknown error occurred, if it is
    // 2, the user needs to create a pin,
    // 3 if the user cacelled the process
    status: number;
    // Whether the function call was successful
    ok: boolean;
    // The (hex) data of the call or null, if it failed
    data: string | null;
};

/**
 * A result from a credential read operation
 */
export type credentialReadResult = {
    // The user name
    username: string;
    // The password
    password: string;
};

/**
 * Microsoft passport for node js
 *
 * If the status is zero, everything was ok,
 * 1 if an unknown error occurred,
 * 2 if the user needs to create a pin,
 * 3 if the user cancelled the process
 */
export class passport {
    // The id of the passport account
    readonly accountId: string;
    // Whether the passport account exists
    accountExists: boolean;

    /**
     * Create a passport instance
     * 
     * @param accountId the id of the passport account
     */
    constructor(accountId: string);

    /**
         * Create a microsoft passport key
         *
         * @return the status, equals to 0 if everything is ok. If so, data will contain the public key as hex string
         */
    createPassportKey(): passportResult;

    /**
     * Create a microsoft passport key asynchronously
     *
     * @return the status, equals to 0 if everything is ok.
     *         If so, data will contain the public key as hex string
     */
    createPassportKeyAsync(): Promise<passportResult>;

    /**
     * Sign a challenge
     *
     * @param challenge the challenge to sign
     * @return the status, equals to 0 if everything is ok.
     *         If so, data will contain the signature as hex string
     */
    passportSign(challenge: string): passportResult;

    /**
     * Sign a challenge asynchronously
     *
     * @param challenge the challenge to sign
     * @return the status, equals to 0 if everything is ok.
     *         If so, data will contain the signature as hex string
     */
    passportSignAsync(challenge: string): Promise<passportResult>;

    /**
     * Delete a passport account
     *
     * @return 0, if the account could be deleted, 1, if a unknown error occurred, 2,
     *         if the access was denied and 3, if the key is already deleted
     */
    deletePassportAccount(): number;

    /**
     * Get the public key
     *
     * @return the status, equals to 0 if everything is ok.
     *         If so, data will contain the public key as hex string
     */
    getPublicKey(): passportResult;

    /**
     * Get a SHA-256 hash of the public key
     *
     * @return the status, equals to 0 if everything is ok.
     *         If so, data will contain the public key hash as hex string
     */
    getPublicKeyHash(): passportResult;

    /**
     * Check if a passport account exists
     * 
     * @param accountId the id of the account to check
     */
    static passportAccountExists(accountId: string): boolean;

    /**
     * Check if ms passport is available on this machine
     *
     * @returns true if passport is available
     */
    static passportAvailable(): boolean;

    /**
     * Verify a challenge signed by passport
     *
     * @param challenge the challenge used
     * @param signature the signature returned
     * @param publicKey the public key of the application
     * @return if the signature matches
     */
    static verifySignature(challenge: string, signature: string, publicKey: string): boolean;
};

/**
 * Windows credential storage for node js
 */
export class credentialStore {
    // The id of the credential account
    readonly accountId: string;
    // Whether to encrypt passwords
    readonly encryptPasswords: boolean;

    /**
     * Create a credentialStore instance
     * 
     * @param accountId the id of the creadential account
     * @param encryptPasswords whether to encrypt passwords
     */
    constructor(accountId: string, encryptPasswords: boolean = true);

    /**
     * Write data to the password storage
     *
     * @param user the user name to store
     * @param password the password to store
     * @return if the operation was successful
     */
    write(user: string, password: string): boolean;

    /**
     * Read data from the password storage
     *
     * @return the username and password or null if unsuccessful
     */
    read(): credentialReadResult | null;

    /**
     * Remove a entry from the credential storage
     *
     * @return if the operation was successful
     */
    remove(): boolean;

    /**
     * Check if a password entry is encrypted. Throws an error on error
     *
     * @return if the password is encrypted
     */
    isEncrypted(): boolean;
};

/**
 * Password encryption using windows APIs
 */
export namespace passwords {
    /**
     * Encrypt a password using CredProtect. Throws on error
     *
     * @param data the data to encrypt
     * @returns the result as hex string or null if unsuccessful
     */
    function encrypt(data: string): string;

    /**
     * Decrypt a password using CredUnprotect. Throws on error
     *
     * @param data the data to decrypt as hex string
     * @returns the result as string or null if unsuccessful
     */
    function decrypt(data: string): string;

    /**
     * Check if data was encrypted using CredProtect. Throws an error on error
     *
     * @param data the data as hex string
     * @returns if the password is encrypted
     */
    function isEncrypted(data: string): boolean;
};

/**
 * Utilities
 */
export namespace passport_utils {
    /**
     * Generate random bytes
     *
     * @param length the length of the challenge in bytes
     * @return the random bytes as hex string
     */
    function generateRandom(length: number): string;
};

/**
 * Passport C++ library variables
 */
export namespace passport_lib {
    // The include directory
    const include_dir: string;
    // The library directory
    const library_dir: string;
    // The library name
    const library: string;
};
