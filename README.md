# node-ms-passport

Microsoft Passport and Credential storage for Node.js. Only works on Windows. Obviously.
Uses C# and C++ to store credentials and sign data.

**This addon is only intended to be used with client-only applications, e.g. electron.**

## Usage
### Passport

To use it, simply define
```js
const {passport} = require('node-ms-passport');
```

Check if passport is available on this machine
```js
const {passport} = require('node-ms-passport');

const passportAvailable = passport.passportAvailable();
if (!passportAvailable) {
    console.error("Passport is not available");
}
```

Create a passport key and sign a challenge with it:
```js
const {passport, passport_utils} = require('node-ms-passport');

// Returns a status and the public key
let privateKey = passport.createPassportKey("test");
// Check if the status is zero, if not, abort
if (privateKey.status !== 0) {
    return;
}

// Generate a challenge as hex string
let challenge = passport_utils.generateRandom(25);

// Sign it
let signature = passport.passportSign("test", challenge);
// Check if the status is zero, if not, abort
if (signature.status !== 0) {
    return;
}

// Verify the signature
let signatureMatches = passport.verifySignature(challenge, 
                                                signature.data,
                                                privateKey.data);
if (signatureMatches) {
    // Do something with it...
}
```

Delete the passport key
```js
let res = passport.deletePassportAccount("test");
// Check if the status is zero, if not, abort
if (res !== 0) {
    return;
}
```

#### Async operations
Asynchronous operations are supported for use in ui applications to not freeze the app while it waits for
user input. User input is required on key creation and on signing a challenge.

```js
// Create key
passport.createPassportKeyAsync("testAsync").then(res => {
    if (res.status !== 0) {
        console.error("Could not create passport key: " + res.status);
    }
});

// Sign data
passport.passportSignAsync("test", challenge).then(res => {
    if (res.status !== 0) {
        console.error("Could not sign challenge: " + res.status);
    }
});
```

#### Return values
Many functions return a object containing a status value.
If the status is zero, everything was ok, 1 if a unknown error occurred, 2 if the user needs to create a pin, 
3 if the user cancelled the process. ```deletePassportAccount``` just returns a number. It works the same way.

### Credential vault

It also supports the windows credential vault. Passwords will be encrypted by default.
To use it, simply define
```js
const {credentials} = require('node-ms-passport');
```

Writing and reading credentials to and from the windows credential manager:
```js
const {credentials} = require('node-ms-passport');

// Write credentials
let successful = credentials.write("test/test", "test", "testPassword");
if (!successful) {
    // Do something with it...
}

// Maybe check if the data is encrypted, here the this would return true
const encrypted = credentials.isEncrypted("test/test");
// Check if the operation was successful
if (!encrypted.ok) {
    return;
}

// The result will be stored in encrypted.encrypted

// Read credentials
let result = credentials.read("test/test");
// credentials.read() returns null if the operation failed
if (result == null) {
    return;
}

// Get the username and password
let username = result.username;
let password = result.password;

// Use it
console.log("Read username:", username, "and password:", password);

// Delete this credential
successful = credentials.remove("test/test");
if (!successful) {
    // Do something with it, throw an error, 
    // get some ice cream to eat under the shower...
}
```

Encryption can be turned off by passing ``false`` to the read and write methods:

```js
// Write credentials
let successful = credentials.write("test/test", "test", "testPassword", false);
if (!successful) {
    // Do something with it...
}

// isEncrypted() check will return false

// Read credentials
let result = credentials.read("test/test", false);
// credentials.read() returns null if the operation failed
if (result == null) {
    return;
}
```

### Encrypt data

Encrypting data using [CredProtectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credprotectw)
and [CredUnprotectW](https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credunprotectw) is also
supported.
To use it, simply define
```js
const {passwords} = require('node-ms-passport');
```

Encrypting and decrypting a password:
```js
const {passwords} = require('node-ms-passport');

// Encrypt a password
let data = passwords.encrypt("TestPassword");
// Returns null on failure
if (data == null) {
    return;
}

// Check if the data is encrypted
let res = passwords.isEncrypted(data);
// Check if the operation was successful
if (!res.ok) {
    return;
}
// The result will be stored in res.encrypted

// Trying to call any function which requires a hex string with
// invalid data will throw an error
try {
    passwords.isEncrypted("data"); // 't' is no valid hex character
} catch (e) {
    console.error(e);
    return;
}

// Decrypt the data
data = passwords.decrypt(data);
// Returns null on failure
if (data == null) {
    return;
}
```

## C++ Api
A c++ api is shipped with the addon to be used with custom node.js modules.
To get the include path call: ``node -p "require('node-ms-passport').include"``, for the library to link to call:
``node -p "require('node-ms-passport').library"``, to get the binary file path call: ``node -p "require('node-ms-passport').binary"``.

###Passport example
```c++
#include <NodeMsPassport.hpp>

int main() {
    using namespace NodeMsPassport::passport;

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
    using namespace NodeMsPassport::credentials;

    // Write a password and encrypt it
    bool ok = write(L"test/test", L"testUser", L"testPassword", true);
    if (!ok) {
        return 1;
    }

    // Check if the password is encrypted
    bool encrypted = isEncrypted(L"test/test", ok);
    if (!ok) {
        return 1;
    }

    // Should return true
    if (!encrypted) {
        return 2; // Should never be called, if the encryption fails, write returns false.
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
    using namespace NodeMsPassport::passwords;
    
    secure_wstring password = L"Password";

    // Encrypt the data
    bool ok = encrypt(password);
    if (!ok) {
        return 1;
    }

    // Check if the data is encrypted
    util::result res = isEncrypted(password);
    if (!res.ok) {
        return 1;
    }

    // The result is stored in res.res
    if (!res.res) {
        // Should never be called, if the encryption fails,
        // encrypt returns false.
        return 2;
    }

    // Decrypt the data
    ok = decrypt(password);
    if (!res.ok) {
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