# node-ms-passport

Microsoft Passport and Credential storage for Node.js. Only works on Windows. Obviously.
Uses C# and C++ to store credentials and sign data.

**This addon is only intended to be used with client-only applications, e.g. electron.**

## Installation
```
npm install node-ms-passport
```

## Build requirements
Visual Studio 2017 or 2019 with installed packages:
* .NET SDK v4.7.2 or later
* C++ build tools
* CMake
* Windows 10 SDK

or with installed workloads:
* .NET desktop development
* Desktop development with C++

## Usage
### Passport

To use it, simply define
```js
const {passport} = require('node-ms-passport');
```

#### ``static passport.passportAvailable(): boolean``
Check if Microsoft passport is available on this system:
```js
if (passport.passportAvailable()) {
    // MS Passport is available
} else {
    // MS Passport is not available
}
```

#### ``static passportAccountExists(accountId: string): boolean``
Check if a passport account exists:
```js
if (passport.passportAccountExists("SOME_ID")) {
    // The passport account with the id exists
} else {
    // The account does not exist
}
```

#### ``static async verifySignature(challenge: string, signature: string, publicKey: string): Promise<boolean>``
Verify a signature:
```js
const matches = await passport.verifySignature(CHALLENGE, SIGNATURE, PUBLICKEY);
```

#### ``new passport(accountId: string)``
Create a new instance of the passport class
```js
const pass = new passport("SOME_ID");
```
If the account already exists, ``passport.accountExists``
will be set to ``true``.

#### ``async passport.createPassportKey(): Promise<void>``
Create a passport account and generate a public key:
```js
await pass.createPassportKey();
```

#### ``async passportSign(challenge: string): Promise<string>``
Sign a challenge with the account's private key.
Returns the signature as a hex string.
```js
const signature = await pass.passportSign("SOME_CHALLENGE");
```

#### ``async getPublicKey(): Promise<string>``
Get the account's public key as a hex string:
```js
const pubkey = await pass.getPublicKey();
``` 

#### ``async getPublicKeyHash(): Promise<string>``
Get the SHA256 Hash of the public key as a hex string:
```js
const hash = await pass.getPublicKeyHash();
```

#### ``async deletePassportAccount(): Promise<void>``
Delete the passport account:
```js
await pass.deletePassportAccount();
```

#### Exceptions
Almost every passport operation can throw an instance of ``PassportError``.
Every instance of ``PassportError`` stores an error code, which is one of ``errorCodes``:
```js
{
    // An exception was thrown by the native
    // addon of which the error code is unknown
    ERR_ANY: -1,
    // An unknown error occurred
    ERR_UNKNOWN: 1,
    // The user needs to create a pin
    ERR_MISSING_PIN: 2,
    // The user cancelled the operation
    ERR_USER_CANCELLED: 3,
    // The user prefers a password
    ERR_USER_PREFERS_PASSWORD: 4,
    // The passport account was not found
    ERR_ACCOUNT_NOT_FOUND: 5,
    // The sign operation failed
    ERR_SIGN_OP_FAILED: 6,
    // The key is already deleted
    ERR_KEY_ALREADY_DELETED: 7,
    // The access was denied
    ERR_ACCESS_DENIED: 8
}
```

### Credential vault

It also supports the windows credential vault. Passwords will be encrypted by default.
To use it, simply define
```js
const {credentialStore} = require('node-ms-passport');
```

#### ``new credentialStore(accountId: string, encryptPasswords: boolean = true)``
Create a new ``credentialStore`` instance. Takes an account id and a
boolean which controls whether to encrypt the stored password.
```js
const store = new credentialStore("some/id", true);
```

#### ``async write(user: string, password: string): Promise<boolean>``
Store a username and password. Returns true, if the operation was successful.
```js
let ok = await store.write("username", "pa$$word");
```

#### ``async read(): Promise<credentialReadResult | null>``
Read a username and password from the credential vault.
Returns a ``credentialReadResult`` on success storing the username
and password or ``null`` if the operation failed.
```js
let res = await store.read();
if (res === null) {
    // The operation failed
} else {
    // The operation was successful
    let user = res.username;
    let pass = res.password;
}
```

#### ``async remove(): Promise<boolean>`` 
Remove a username and password from the credential vault.
Returns ``true`` if the operation failed.
```js
let ok = await store.remove();
```

#### ``async isEncrypted(): Promise<boolean>``
Check if the password in the credential vault is encrypted:
```js
let encrypted = store.isEncrypted();
```

### Encrypt data

Encrypting data using [CredProtectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credprotectw)
and [CredUnprotectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credunprotectw) is also
supported.
To use it, simply define
```js
const {passwords} = require('node-ms-passport');
```

#### ``async passwords.encrypt(data: string): Promise<string>``
Encrypt a password. Returns the encrypted password as a hex string.
```js
const encrypted = await passwords.encrypt("pa$$word");
```

#### ``async passwords.decrypt(data: string): Promise<string>``
Decrypt a hex-encoded password. Returns the decrypted password string.
```js
const password = await passwords.decrypt(encrypted);
```

#### ``async passwords.isEncrypted(data: string): Promise<boolean>``
Check if a hex-encoded password is encrypted:
```js
const is_encrypted = await passwords.isEncrypted(encrypted);
```

### Passport utils
#### ``passport_utils.generateRandom(length: number): string``
Generate random bytes and get them as a hex-encoded string:
```js
const {passport_utils} = require('node-ms-passport');

const rnd = passport_utils.generateRandom(25);
```

### Examples
#### Passport
```js
const {passport, passport_utils} = require('node-ms-passport');

// Check if this system supports ms passport
if (!passport.passportAvailable()) {
    // MS Passport is not available
    return;
}

// Create a new passport instance
const pass = new passport("SOME_ID");

// If the account does not exist,
// create it
if (!pass.accountExists) {
    await pass.createPassportKey();
}

// Get the public key
let pubkey = await pass.getPublicKey();

// Generate a challenge
let challenge = passport_utils.generateRandom(25);

// Sign the challenge
let signature = await pass.passportSign(challenge);

// Check if the signature matches
let signature_matches = await passport.verifySignature(
                                                challenge,
                                                signed,
                                                pubkey);

if (!signature_matches) {
    // The signature does not match
    return;
}

// Delete the passport key
await pass.deletePassportAccount();
```

#### Credential vault
```js
const {credentialStore} = require('node-ms-passport');

// Create a new credentialStore instance
// with encrypting password
const store = new credentialStore("test/test", true);

// Create a new credentialStore instance
// without encryping passwords
const plain_store = new credentialStore("test/plain", false);

// Write the password
let ok = await store.write("test", "pa$$word");
of (!ok) {
    // Could not store the password
    return;
}

// Check if the stored password is encrypted
let encrypted = await store.isEncrypted();
if (!encrypted) {
    // It should be encrypted...
    return;
}

// Read the password
let res = await store.read();
if (res === null) {
    // The read operation failed
    return;
}

// Get the username and password
let user = res.username;
let pass = res.password;

// Delete the credential
ok = await store.remove();
if (!ok) {
    // Could not delete the credential
    return;
}
```

#### Password encryption
Encrypting and decrypting a password:
```js
const {passwords} = require('node-ms-passport');

// Encrypt a password
let data;
try {
    data = await passwords.encrypt("TestPassword");
} catch (e) {
    return; // Throws on failure
}

// Check if the data is encrypted
let encrypted;
try {
    encrypted = await passwords.isEncrypted(data);
} catch (e) {
    return; // Throws error on failure
}

if (!encrypted) { // Should not be called
    console.error("Data should be encrypted, but it is not");
    return;
}

// Trying to call any function which requires a hex string with
// invalid data will throw an error
try {
    await passwords.isEncrypted("data"); // 't' is no valid hex character
} catch (e) {
    console.error(e);
    return;
}

// Decrypt the data
try {
    data = passwords.decrypt(data);
} catch (e) {
    return; // Throws on failure
}
```

## C++ Api
A c++ api is shipped with the addon to be used with custom node.js modules.
To get the include path call: ``node -p "require('node-ms-passport').passport_lib.include_dir"``, for the library to link to call:
``node -p "require('node-ms-passport').passport_lib.library"``.

Your should probably set the location of the C# dll in order for the program to work properly:
```c++
nodeMsPassport::passport::setCSharpDllLocation("CSHARP_DLL_LOCATION");
```

### Passport example
```c++
#include <NodeMsPassport.hpp>

int main() {
    using namespace nodeMsPassport::passport;

    // Check if passport is available
    if (!passportAvailable()) {
        return 1;    
    }

    // Create passport key, this call will block and wait for user input
    OperationResult result = createPassportKey("test");
    if (!result.ok()) {
        return 1;
    }

    // The public key will be stored in OperationResult::data
    secure_vector<unsigned char> publicKey = result.data;

    std::string challenge_str = "Challenge";
    secure_vector<unsigned char> challenge(challenge_str.begin(),
                                             challenge_str.end());

    // Sign the challenge, this call will block and wait for user input, too
    result = passportSign("test", challenge);
    if (!result.ok()) {
            return 1;
    }

    // Check if the signature matches (Probably on a different machine)
    bool matches = verifySignature(challenge, result.data, publicKey);
    if (!matches) {
        return 2;    
    }

    // Delete the passport account
    int status = deletePassportAccount("test");
    if (status != 0) { // Returns 0 on success, like everything else
        return 1;
    }

    return 0;
}
```

### Credential manager example
Since the c++ api has all the functionality of the node.js api, the credential manager is also available.
```c++
#include <NodeMsPassport.hpp>

int main() {
    using namespace nodeMsPassport::credentials;

    // Write a password and encrypt it
    bool ok = write(L"test/test", L"testUser", L"testPassword", true);
    if (!ok) {
        return 1;
    }

    // Check if the password is encrypted
    bool encrypted;
    try {
        encrypted = isEncrypted(L"test/test");
    } catch (NodeMsPassport::encryptionException &e) {
        return 1; // Throws exception if not ok
    }

    // Should return true
    if (!encrypted) {
        // Should never be called,
        // if the encryption fails, write returns false.
        return 2;
    }

    // Read the password, it is encrypted, so decrypt it. If you don't know
    // if the password is encrypted, use isEncrypted() to find out.
    std::wstring user;
    secure_wstring password;
    ok = read(L"test/test", user, password, true);
    if (!ok) {
        return 1;
    }

    // Remove the password from the database
    ok = remove(L"test/test");
    if (!ok) {
        return 1;
    }

    return 0;
}
```

### Data encryption
Data encryption also works as with node.js and uses 
[CredProtectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credprotectw)
and [CredUnprotectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credunprotectw) to protect data.

```c++
#include <NodeMsPassport.hpp>

int main() {
    using namespace nodeMsPassport::passwords;
    
    secure_wstring password = L"Password";

    // Encrypt the data
    bool ok = encrypt(password);
    if (!ok) {
        return 1;
    }

    // Check if the data is encrypted
    bool encrypted;
    try {
        encrypted = isEncrypted(password);
    } catch (NodeMsPassport::encryptionException &e) {
        return 1; // Throws exception if not ok
    }

    // The result is stored in res.res
    if (!encrypted) {
        // Should never be called, if the encryption fails,
        // encrypt returns false.
        return 2;
    }

    // Decrypt the data
    ok = decrypt(password);
    if (!ok) {
        return 1;
    }

    // Result should match
    if (password == L"Password") {
        return 0;
    } else {
        return -1;
    }
}
```
