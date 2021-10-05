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
 * The error codes that may be stored
 * by the PassportError class
 */
export enum errorCodes {
    // An exception was thrown by the native
    // addon of which the error code is unknown
    ERR_ANY = -1,
    // An unknown error occurred
    ERR_UNKNOWN = 1,
    // The user needs to create a pin
    ERR_MISSING_PIN = 2,
    // The user cancelled the operation
    ERR_USER_CANCELLED = 3,
    // The user prefers a password
    ERR_USER_PREFERS_PASSWORD = 4,
    // The passport account was not found
    ERR_ACCOUNT_NOT_FOUND = 5,
    // The sign operation failed
    ERR_SIGN_OP_FAILED = 6,
    // The key is already deleted
    ERR_KEY_ALREADY_DELETED = 7,
    // The access was denied
    ERR_ACCESS_DENIED = 8
}

/**
 * A passport error
 */
export class PassportError extends Error {
    /**
     * Create a new PassportError instance
     * 
     * @param message the error message
     * @param code the error code
     */
    public constructor(message: string, code: number);

    /**
     * Get the error code. Returns one
     * of errorCodes.
     * 
     * @returns the error code
     */
    public getCode(): number;
}

/**
 * Microsoft passport for node js
 */
export class passport {
    // The id of the passport account
    public readonly accountId: string;
    // Whether the passport account exists
    public accountExists: boolean;

    /**
     * Create a passport instance
     * 
     * @param accountId the id of the passport account
     */
    public constructor(accountId: string);

    /**
     * Create a microsoft passport key asynchronously
     */
    public createPassportKey(): Promise<void>;

    /**
     * Sign a challenge
     *
     * @param challenge the challenge to sign
     * @return the signature as a hex string
     */
    public passportSignHex(challenge: string): Promise<string>;

    /**
     * Sign a challenge
     *
     * @param challenge the challenge to sign
     * @return the signature in a buffer
     */
    public passportSign(challenge: Buffer): Promise<Buffer>;

    /**
     * Delete a passport account
     */
    public deletePassportAccount(): Promise<void>;

    /**
     * Get the public key
     *
     * @return the public key as a hex string
     */
    public getPublicKeyHex(): Promise<string>;

    /**
     * Get the public key
     *
     * @return the public key in a buffer
     */
    public getPublicKey(): Promise<Buffer>;

    /**
     * Get a SHA-256 hash of the public key
     *
     * @return the hashed public key as a hex string
     */
    public getPublicKeyHashHex(): Promise<string>;

    /**
     * Get a SHA-256 hash of the public key
     *
     * @return the hashed public key in a buffer
     */
    public getPublicKeyHash(): Promise<Buffer>;

    /**
     * Check if a passport account exists
     * 
     * @param accountId the id of the account to check
     * @return true, if the account with the given id exists
     */
    public static passportAccountExists(accountId: string): boolean;

    /**
     * Check if ms passport is available on this machine
     *
     * @returns true if passport is available
     */
    public static passportAvailable(): boolean;

    /**
     * Verify a challenge signed by passport
     *
     * @param challenge the challenge used
     * @param signature the signature returned
     * @param publicKey the public key of the application
     * @return true, if the signature matches
     */
    public static verifySignatureHex(challenge: string, signature: string, publicKey: string): Promise<boolean>;

    /**
     * Verify a challenge signed by passport
     *
     * @param challenge the challenge used
     * @param signature the signature returned
     * @param publicKey the public key of the application
     * @return true, if the signature matches
     */
    public static verifySignature(challenge: Buffer, signature: Buffer, publicKey: Buffer): Promise<boolean>;
}

/**
 * A stored credential blob
 */
export class Credential {
    private constructor(accountId: string, username: string, password: Buffer, encrypt: boolean);

    public get accountId(): string;

    public get username(): string;

    public get password(): string | null;

    public get encrypted(): boolean;

    public get passwordBuffer(): Buffer | null;

    public loadPassword(): Promise<void>;

    public unloadPassword(): Promise<void>;

    public refreshData(): Promise<void>;

    public update(username: string, password: string): Promise<void>;

    public setEncrypted(encrypt: boolean): Promise<void>;

    public isEncrypted(): Promise<boolean>;
}

/**
 * Windows credential store for node.js
 */
export class CredentialStore {
    public constructor(accountId: string, encrypt?: boolean);

    public get accountId(): string;

    public get encryptPasswords(): string;

    public write(username: string, password: string): Promise<void>;

    public read(): Promise<Credential>;

    public remove(): Promise<void>;

    public exists(): Promise<boolean>;

    public isEncrypted(): Promise<boolean>;
}

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
    function encryptHex(data: string): Promise<string>;

    /**
     * Encrypt a password using CredProtect. Throws on error
     *
     * @param data the data to encrypt
     * @returns the result in a buffer or null if unsuccessful
     */
    function encrypt(data: string): Promise<Buffer>;

    /**
     * Decrypt a password using CredUnprotect. Throws on error
     *
     * @param data the data to decrypt as hex string
     * @returns the result as string or null if unsuccessful
     */
    function decryptHex(data: string): Promise<string>;

    /**
     * Decrypt a password using CredUnprotect. Throws on error
     *
     * @param data the data to decrypt in a buffer
     * @returns the result as string or null if unsuccessful
     */
    function decrypt(data: Buffer): Promise<string>;

    /**
     * Check if data was encrypted using CredProtect. Throws an error on error
     *
     * @param data the data as hex string
     * @returns if the password is encrypted
     */
    function isEncryptedHex(data: string): Promise<boolean>;

    /**
     * Check if data was encrypted using CredProtect. Throws an error on error
     *
     * @param data the data in a buffer
     * @returns if the password is encrypted
     */
    function isEncrypted(data: Buffer): Promise<boolean>;
}

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
    function generateRandomHex(length: number): string;

    /**
     * Generate random bytes
     *
     * @param length the length of the challenge in bytes
     * @return the random bytes in a buffer
     */
    function generateRandom(length: number): Buffer;
}

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
}
