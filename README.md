# node-ms-passport

Microsoft Passport and Credential storage for Node.js. Only works on Windows. Obviously.
Uses C# and C++ to store credentials and sign data.

## Usage
### Passport

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
let signatureMatches = passport.verifySignature(challenge, signature.data, privateKey.data);
if (signatureMatches) {
    // Do something with it...
}
```

Delete the passport key
```js
const {passport} = require('node-ms-passport');
let res = passport.deletePassportAccount("test");
// Check if the status is zero, if not, abort
if (res !== 0) {
    return;
}
```

#### Return values
Many functions return a object containing a status value.
If the status is zero, everything was ok, 1 if a unknown error occurred, 2 if the user needs to create a pin, 
3 if the user cancelled the process. ```deletePassportAccount``` just returns a number. It works the same way.

### Credential vault

Writing and reading credentials to and from the windows credential manager:
```js
const {credentials} = require('./node-ms-passport');

// Write credentials
let successful = credentials.write("test/test", "test", "testPassword");
if (!successful) {
    // Do something with it...
}

// Read credentials
let result = credentials.read("test/test");
// credentials.read() returns null if the operation failed
if (result == null) {
    return;
}

// Get the username and password
let username = result.username:
let password = result.password:

// Use it
console.log("Read username:", username, "and password:", password);

// Delete this credential
successful = credentials.remove("test/test");
if (!successful) {
    // Do something with it, throw an error, get some ice cream to eat under the shower...
}
```