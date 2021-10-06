# node-ms-passport

Microsoft Passport and Credential storage for Node.js. Only works on Windows. Obviously.
Uses C# and C++ to store credentials and sign data. Typescript definitions are available.

**This addon is only intended to be used with client-only applications, e.g. electron.**

**Another important note**: As of version ``1.2.0``, when installed and imported on a non-windows machine,
that process will no longer throw errors. Instead, if any of the modules methods/constructors
are called an ``Error`` will be thrown.

## Installation
```
npm install node-ms-passport
```

The native library is built using cmake-js, so you should set the runtime to electron
in your ``package.json`` if you are planning on using this addon with electron:
```json
{
  "cmake-js": {
    "runtime": "electron",
    "runtimeVersion": "electron-runtime-version-here",
    "arch": "whatever-setting-is-appropriate-for-your-application's-windows-build"
  }
}
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
const {Passport} = require('node-ms-passport');
```

#### ``static passport.passportAvailable(): boolean``
Check if Microsoft passport is available on this system:
```js
if (Passport.passportAvailable()) {
    // MS Passport is available
} else {
    // MS Passport is not available
}
```

#### ``static passportAccountExists(accountId: string): boolean``
Check if a passport account exists:
```js
if (Passport.passportAccountExists("SOME_ID")) {
    // The passport account with the id exists
} else {
    // The account does not exist
}
```

#### ``static verifySignatureHex(challenge: string, signature: string, publicKey: string): Promise<boolean>``
Verify a signature (all arguments as hex-encoded strings):
```js
const matches = await Passport.verifySignatureHex(CHALLENGE, SIGNATURE, PUBLICKEY);
```

#### ``static verifySignature(challenge: Buffer, signature: Buffer, publicKey: Buffer): Promise<boolean>``
Verify a signature:
```js
const matches = await Passport.verifySignature(CHALLENGE, SIGNATURE, PUBLICKEY);
```

#### ``new passport(accountId: string)``
Create a new instance of the passport class
```js
const pass = new Passport("SOME_ID");
```
If the account already exists, ``passport.accountExists``
will be set to ``true``.

#### ``passport.createPassportKey(): Promise<void>``
Create a passport account and generate a public key:
```js
await pass.createPassportKey();
```

#### ``passportSignHex(challenge: string): Promise<string>``
Sign a challenge with the account's private key.
Returns the signature as a hex string.
```js
const signature = await pass.passportSignHex("SOME_CHALLENGE");
```

#### ``passportSign(challenge: Buffer): Promise<Buffer>``
Sign a challenge with the account's private key.
Returns the signature bytes in a ``Buffer``.
```js
const signature = await pass.passportSign(Buffer.from("SOME_CHALLENGE"));
```

#### ``getPublicKeyHex(): Promise<string>``
Get the account's public key as a hex string:
```js
const pubkey = await pass.getPublicKeyHex();
```

#### ``getPublicKey(): Promise<Buffer>``
Get the account's public key bytes in a ``Buffer``:
```js
const pubkey = await pass.getPublicKey();
```

#### ``getPublicKeyHashHex(): Promise<string>``
Get the SHA256 Hash of the public key as a hex string:
```js
const hash = await pass.getPublicKeyHashHex();
```

#### ``getPublicKeyHash(): Promise<string>``
Get the SHA256 Hash bytes of the public key in a ``Buffer``:
```js
const hash = await pass.getPublicKeyHash();
```

#### ``deletePassportAccount(): Promise<void>``
Delete the passport account:
```js
await pass.deletePassportAccount();
```

#### Exceptions
Almost every passport operation can throw an instance of ``PassportError``.
Every instance of ``PassportError`` stores an error code, which is one of ``errorCodes``:
```ts
enum errorCodes {
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
```

### Credential vault

It also supports the windows credential vault. Passwords will be encrypted by default.
To use it, simply define
```js
const {CredentialStore} = require('node-ms-passport');
```

#### ``new CredentialStore(accountId: string, encryptPasswords: boolean = true)``
Create a new ``CredentialStore`` instance. Takes an account id and a
boolean which controls whether to encrypt the stored password.
```js
const store = new CredentialStore("some/id", true);
```

#### ``get accountId(): string``
Get the stored account id

#### ``get encryptPasswords(): boolean``
Check if the passwords will be encrypted

#### ``write(user: string, password: string): Promise<void>``
Store a username and password. Throws on error.
If the credentials already exist, they will be overwritten.
```js
let ok = await store.write("username", "pa$$word");
```

#### ``read(): Promise<Credential>``
Read a username and password from the credential vault.
Returns a ``Credential`` on success storing the username
and password. Throws an error if the operation failed.
```js
let cred = await store.read();
```

#### ``remove(): Promise<void>`` 
Remove a username and password from the credential vault.
Throws on error. This will cause all subsequent interactions
with the credential vault (``refreshData()`` and ``setEncrypted()``)
from the ``Credential`` class to fail.
```js
await store.remove();
```

#### ``isEncrypted(): Promise<boolean>``
Check if the password in the credential vault is encrypted:
```js
let encrypted = store.isEncrypted();
```

#### ``exists(): Promise<boolean>``
Check if the account exists:
```js
if (await store.exists()) {
    // Do something like
    let cred = await store.read();
}
```

#### Credential class
Credentials are stored using the ``Credential`` class.
The password is stored in an encrypted form until
``loadPassword()`` is called.

**Note**: Almost all password operations are synchronized,
so calling a async operation and a sync operation, the
synchroized operation will possibly wait on the async
operation to finish so make sure to not call a operation which
may take some time like ``loadPassword()`` and a synchronized
operation like ``get password()`` at once since this may
cause your application to freeze.

*TL;DR*: Always await async operations before calling
sync operations on these types of objects.

##### Get a ``Credential`` instance
```ts
// Create a new credential store instance
const store = new CredentialStore("some/id", true);

// Read the data. Throws if the data does not exist.
const cred: Credential = await store.read();
```

##### ``get accountId(): string``
Get the account id

##### ``get username(): string``
Get the username

##### ``get password(): string | null``
Get the password. Returns ``null`` if the password is not loaded.
In this case you should call ``loadPassword()`` to load
the password. After that, the plain text password will be returned.

##### ``get encrypted(): boolean``
Check if the password will be stored in an encrypted form.
Does not represent if the password is *actually* stored in an encrypted form.

##### ``get passwordBuffer(): Buffer | null``
Get the password in a ``char16_t`` buffer.
Returns ``null`` if the password is not loaded.

##### ``loadPassword(): Promise<void>``
Load the password to retrieve it later on.
If the password is already loaded, this is a no-op.
```js
// Get the password
let password = cred.password;
if (password == null) {
    // The password is not loaded, load it
    await cred.loadPassword();
    // The password is now retrieved
    password = cred.password;
} else {
    // The password is already loaded
}
```

##### ``unloadPassword(): Promise<void>``
Unloads the password. The password get operation
will return ``null`` after this is called.
If the password is not loaded, this is a no-op.

##### ``refreshData(): Promise<void>``
Refresh the cached data with the data actually
stored in the password vault.

##### ``update(username: string, password: string): Promise<void>``
Update the stored username and password.
After this call, the password will not be loaded,
you must call ``loadPassword`` to retrieve it.
```js
await store.update("newUser", "newPassword");
```

##### ``setEncrypted(encrypt: boolean): Promise<void>``
Set whether the password should be stored in encrypted form.
Does not alter the form in which the password is stored in the memory (RAM).
After this call, the password will not be loaded,
you must call ``loadPassword`` to retrieve it.
If the supplied value matches the current value, this is a no-op.

**Note**: This does not change the ``encryptPasswords`` value
in the ``CredentialStore`` class that was used to create this
``Credential`` instance.

##### ``ioEncrypted(): Promise<boolean>``
Check if the password is *actually* encrypted
in the credential store.
```js
await store.setEncrypted(true);

let encrypted = await store.isEncrypted();
// encrypted is now true
```

### Encrypt data

Encrypting data using [CredProtectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credprotectw)
and [CredUnprotectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credunprotectw) is also
supported.
To use it, simply define
```js
const {passwords} = require('node-ms-passport');
```

#### ``passwords.encryptHex(data: string): Promise<string>``
Encrypt a password. Returns the encrypted password as a hex string.
```js
const encrypted = await passwords.encryptHex("pa$$word");
```

#### ``passwords.encrypt(data: string): Promise<Buffer>``
Encrypt a password. Returns the encrypted password bytes in a ``Buffer``.
```js
const encrypted = await passwords.encrypt("pa$$word");
```

#### ``passwords.decryptHex(data: string): Promise<string>``
Decrypt a hex-encoded password. Returns the decrypted password string.
```js
const password = await passwords.decryptHex(encrypted);
```

#### ``passwords.decrypt(data: Buffer): Promise<string>``
Decrypt password bytes in a ``Buffer``. Returns the decrypted password string.
```js
const password = await passwords.decrypt(encrypted);
```

#### ``passwords.isEncryptedHex(data: string): Promise<boolean>``
Check if a hex-encoded password is encrypted:
```js
const is_encrypted = await passwords.isEncryptedHex(encrypted);
```

#### ``passwords.isEncrypted(data: Buffer): Promise<boolean>``
Check if password bytes in a ``Buffer`` are encrypted:
```js
const is_encrypted = await passwords.isEncrypted(encrypted);
```

### Examples
#### Passport
```ts
import {Passport} from "node-ms-passport";
import * as crypto from "crypto";

// Check if this system supports ms passport
if (!Passport.passportAvailable()) {
    // MS Passport is not available
    return;
}

// Create a new passport instance
const pass = new Passport("SOME_ID");

// If the account does not exist,
// create it
if (!pass.accountExists) {
    await pass.createPassportKey();
}

// Get the public key
let pubkey: Buffer = await pass.getPublicKey();

// Generate a challenge
let challenge: Buffer = crypto.randomBytes(25);

// Sign the challenge
let signature: Buffer = await pass.passportSign(challenge);

// Check if the signature matches
let signature_matches = await Passport.verifySignature(
                                                challenge,
                                                signature,
                                                pubkey);

if (!signature_matches) {
    // The signature does not match
    return;
}

// Delete the passport key
await pass.deletePassportAccount();
```

#### Credential vault
```ts
import {CredentialStore, Credential} from "node-ms-passport";

// Create a new CredentialStore instance
// with encrypting password
const store = new CedentialStore("test/test", true);

// Check if the credentials are already stored
if (await store.exists()) {
    // Do something with that
}

// Create a new credentialStore instance
// without encryping passwords
const plain_store = new CredentialStore("test/plain", false);

// Write the password. Throws on error.
await store.write("test", "pa$$word");

// Check if the stored password is encrypted
if (!await store.isEncrypted()) {
    // It should be encrypted. This shouldn't happen.
    // If it still does, please open a new issue.
    return;
}

// Read the password. Throws on error.
let cred: Credential = await store.read();

// Get the username
let user: string = res.username;

// The password is not yet loaded,
// call loadPassword() to load it
await cred.loadPassword();

// Get the password
let pass: string = cred.password;

// Do something with the data...

// We are done with the password, unload it.
// Note: As strings are copied, this can also
// be called directly after the password has
// been retrieved, it will not affect any
// already retrieved passwords
await cred.unloadPassword();

// Maybe update the data...
await cred.update("newUser", "newPass");

// Maybe we don't want the credentials
// to be encrypted anymore...
await cred.setEncrypted(false);

// Delete the credential.
await store.remove();
```

#### Password encryption
Encrypting and decrypting a password:
```ts
import {passwords} from "node-ms-passport";

// Encrypt a password
let data: Buffer;
try {
    data = await passwords.encrypt("TestPassword");
} catch (e) {
    return; // Throws on failure
}

// Check if the data is encrypted
let encrypted: boolean;
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
#include <iostream>

int main() {
    using namespace nodeMsPassport::credentials;

    try {
        // Write a password and encrypt it. Throws on error.
        write(L"test/test", L"testUser", L"testPassword", true);

        // Check if the password is encrypted
        if (!isEncrypted(L"test/test")) {
            // Should never be called,
            // if the encryption fails, write returns false.
            return 2;
        }

        // Read the password, it is encrypted, so decrypt it.
        // If you don't know if the password is encrypted,
        // use isEncrypted() to find out.
        std::wstring user;
        secure_wstring password;
        read(L"test/test", user, password, true);

        // Remove the password from the database
        remove(L"test/test");
    } catch (const std::exception &e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
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
#include <iostream>

int main() {
    using namespace nodeMsPassport::passwords;
    
    secure_wstring password = L"Password";

    try {
        // Encrypt the data
        encrypt(password);

        // Check if the data is encrypted
        if (!isEncrypted(password)) {
            // Should never be called, if the encryption fails,
            // encrypt returns false.
            return 2;
        }

        // Decrypt the data
        decrypt(password);
    } catch (const std::exception &e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
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
