using Passport.Utils;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

/// <summary>
/// The C# node-ms-passport namespace
/// </summary>
namespace CSNodeMsPassport {
    /// <summary>
    /// The passport class
    /// </summary>
    public static class Passport {
        private const int NTE_NO_KEY = unchecked((int)0x8009000D);
        private const int NTE_PERM = unchecked((int)0x80090010);

        /// <summary>
        /// A passport operation result
        /// </summary>
        public struct PassportResult {
            /// <summary>
            /// The buffer containing the actual operation result.
            /// Will be set to null, if the operation failed.
            /// </summary>
            public byte[] buffer;

            /// <summary>
            /// The status of the operation.<br></br>
            /// Default codes:<br></br>
            /// 0: The operation was successful<br></br>
            /// 1: An unknown error occurred<br></br>
            /// 2: The user needs to create a PIN<br></br>
            /// 3: The user cancelled the passport enrollment process
            /// </summary>
            public int status;
        }

        /// <summary>
        /// Create a passport key
        /// </summary>
        /// <param name="accountId">The account id</param>
        /// <returns>A passport result, storing the accounts public key in its buffer</returns>
        public static PassportResult CreatePassportKey(string accountId) {
            try {
                // Run KeyCredentialManager.RequestCreateAsync to create the account.
                // Overwrites any existing accounts
                Task<KeyCredentialRetrievalResult> task = Task.Run(async () =>
                    await KeyCredentialManager.RequestCreateAsync(accountId, KeyCredentialCreationOption.ReplaceExisting));
                // Get the result
                KeyCredentialRetrievalResult keyCreationResult = task.Result;

                // Create a new PassportResult instance
                PassportResult res = new PassportResult();

                // Check the KeyCredentialRetrievalResult status
                if (keyCreationResult.Status == KeyCredentialStatus.Success) {
                    // Get the public key
                    KeyCredential userKey = keyCreationResult.Credential;
                    IBuffer publicKey = userKey.RetrievePublicKey();

                    // Copy the public key to the PassportResult's buffer
                    CryptographicBuffer.CopyToByteArray(publicKey, out res.buffer);
                    // The operation was successful
                    res.status = 0;
                } else if (keyCreationResult.Status == KeyCredentialStatus.UserCanceled) {
                    // User cancelled the Passport enrollment process
                    res.status = 3;
                } else if (keyCreationResult.Status == KeyCredentialStatus.NotFound) {
                    // User needs to create PIN
                    res.status = 2;
                } else {
                    // An unknown error occurred
                    res.status = 1;
                }

                // Return the PassportResult
                return res;
            } catch (Exception) {
                // Return a PassportResult instance
                return new PassportResult {
                    status = 1,
                    buffer = null
                };
            }
        }

        /// <summary>
        /// Sign a challenge using windows hello
        /// </summary>
        /// <param name="accountId">The id of the account to use</param>
        /// <param name="challenge">The challenge to sign</param>
        /// <returns>A passport result, storing the signed challenge in its buffer</returns>
        public static PassportResult PassportSign(string accountId, byte[] challenge) {
            try {
                // Try to open the account
                Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
                KeyCredentialRetrievalResult retrieveResult = task.Result;

                // Create a new PassportResult instance
                PassportResult res = new PassportResult();

                // Check the KeyCredentialRetrievalResult status
                if (retrieveResult.Status == KeyCredentialStatus.Success) {
                    // Get the users credential
                    KeyCredential userCredential = retrieveResult.Credential;

                    // Convert the challenge to an IBuffer and sign the challenge
                    IBuffer challengeBuffer = CryptographicBuffer.CreateFromByteArray(challenge);
                    Task<KeyCredentialOperationResult> opTask = Task.Run(async () =>
                        await userCredential.RequestSignAsync(challengeBuffer));
                    KeyCredentialOperationResult opResult = opTask.Result;

                    // Check the KeyCredentialOperationResult status
                    if (opResult.Status == KeyCredentialStatus.Success) {
                        // Get the signature
                        IBuffer signatureBuffer = opResult.Result;

                        // Copy the signature to the PassportResult's buffer
                        CryptographicBuffer.CopyToByteArray(signatureBuffer, out res.buffer);
                        // The operation was successful
                        res.status = 0;
                    } else {
                        // The sign operation failed
                        res.status = -1;
                    }
                } else if (retrieveResult.Status == KeyCredentialStatus.UserCanceled) {
                    // User cancelled the Passport enrollment process
                    res.status = 3;
                } else if (retrieveResult.Status == KeyCredentialStatus.NotFound) {
                    // User needs to create PIN
                    res.status = 2;
                } else {
                    // An unknown error occurred
                    res.status = 1;
                }

                // Return the PassportResult
                return res;
            } catch (Exception) {
                // Return a PassportResult instance
                return new PassportResult {
                    status = 1,
                    buffer = null
                };
            }
        }

        /// <summary>
        /// Get the public key of the windiws hello account
        /// </summary>
        /// <param name="accountId">The id of the account to use</param>
        /// <returns>A passport result, storing the public key in its buffer</returns>
        public static PassportResult GetPublicKey(string accountId) {
            try {
                // Try to get the account
                Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
                KeyCredentialRetrievalResult retrieveResult = task.Result;

                // Create a new PassportResult instance
                PassportResult res = new PassportResult();

                // Check the KeyCredentialRetrievalResult status
                if (retrieveResult.Status == KeyCredentialStatus.Success) {
                    // Get the user's credential
                    KeyCredential userCredential = retrieveResult.Credential;

                    // Get the public key
                    IBuffer publicKey = userCredential.RetrievePublicKey();

                    // Copy the public key to the PassportResult's buffer
                    CryptographicBuffer.CopyToByteArray(publicKey, out res.buffer);
                    // The operation was successful
                    res.status = 0;
                } else if (retrieveResult.Status == KeyCredentialStatus.UserCanceled) {
                    // User cancelled the Passport enrollment process
                    res.status = 3;
                } else if (retrieveResult.Status == KeyCredentialStatus.NotFound) {
                    // User needs to create PIN
                    res.status = 2;
                } else {
                    // An unknown error occurred
                    res.status = 1;
                }

                // Return the PassportResult
                return res;
            } catch (Exception) {
                // Return a PassportResult instance
                return new PassportResult {
                    status = 1,
                    buffer = null
                };
            }
        }

        /// <summary>
        /// Get a hashed version of the public key
        /// </summary>
        /// <param name="accountId">The id of the account to use</param>
        /// <returns>A passport result,s toring the hashed public key in its buffer</returns>
        public static PassportResult GetPublicKeyHash(string accountId) {
            PassportResult res = GetPublicKey(accountId);
            if (res.status == 0) {
                // Get a hash provider for the SHA256 algorithm and hash the public key
                HashAlgorithmProvider hashProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
                IBuffer publicKeyHash = hashProvider.HashData(CryptographicBuffer.CreateFromByteArray(res.buffer));

                // Copy the hashed public key to the PassportResult's buffer
                CryptographicBuffer.CopyToByteArray(publicKeyHash, out res.buffer);
            }

            // Return the PassportResult
            return res;
        }

        /// <summary>
        /// Delete the passport account async.
        /// Returns zero, if the operation was successful,
        /// 3 if the key is already deleted,
        /// 2 if the access was denied and 1 if an unknown
        /// error occurred
        /// </summary>
        /// <param name="accountId">The id of the account to delete</param>
        /// <returns>A Task with an integer</returns>
        private static async Task<int> DeletePassportAccountAsync(string accountId) {
            try {
                // Try to delete the account
                await KeyCredentialManager.DeleteAsync(accountId);
                return 0;
            } catch (Exception ex) {
                switch (ex.HResult) {
                    case NTE_NO_KEY:
                        // Key is already deleted. Ignore this error.
                        return 3;
                    case NTE_PERM:
                        // Access is denied. Ignore this error. We tried our best.
                        return 2;
                    default:
                        // An unknown error occurred
                        return 1;
                }
            }
        }

        /// <summary>
        /// Delete a passport account synchronously.
        /// Returns zero, if the operation was successful,
        /// 3 if the key is already deleted,
        /// 2 if the access was denied and 1 if an unknown
        /// error occurred
        /// </summary>
        /// <param name="accountId">The id of the account to delete</param>
        /// <returns>A return code</returns>
        public static int DeletePassportAccount(string accountId) {
            try {
                Task<int> task = DeletePassportAccountAsync(accountId);
                return task.Result;
            } catch (Exception) {
                return 1;
            }
        }

        /// <summary>
        /// Check if a ms passport account exists<br></br>
        /// Return codes:<br></br>
        /// 0: The account was found<br></br>
        /// 1: The account was not found<br></br>
        /// 2: An error occcurred
        /// </summary>
        /// <param name="accountId">The id of the account to check</param>
        /// <returns>A return code</returns>
        public static int PassportAccountExists(string accountId) {
            try {
                // Try to get the account
                Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
                KeyCredentialRetrievalResult openKeyResult = task.Result;

                // Check the result
                if (openKeyResult.Status == KeyCredentialStatus.Success) {
                    // The account was found
                    return 0;
                } else if (openKeyResult.Status == KeyCredentialStatus.NotFound) {
                    // The account was not found
                    return 1;
                } else {
                    // An unknown error occurred
                    return 2;
                }
            } catch (Exception) {
                // An unknown error occurred
                return 2;
            }
        }

        /// <summary>
        /// Verify a challenge
        /// </summary>
        /// <param name="challenge">The challenge</param>
        /// <param name="signature">The signature returned by a client</param>
        /// <param name="publicKey">The public key of the client</param>
        /// <returns>true, if the signature matches, false otherwise</returns>
        public static bool VerifyChallenge(byte[] challenge, byte[] signature, byte[] publicKey) {
            // Validate that the original challenge was signed using the corresponding private key.
            try {
                CngKey pubCngKey = new SubjectPublicKeyInfo(publicKey).GetPublicKey();

                // Validate that the original challenge was signed using the corresponding private key.
                using (RSACng pubKey = new RSACng(pubCngKey)) {
                    return pubKey.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            } catch (Exception) {
                // The operation failed, just return false
                return false;
            }
        }

        /// <summary>
        /// Check if passport is available on this system
        /// </summary>
        /// <returns>true if passport is available</returns>
        public static bool PassportAvailable() {
            try {
                Task<bool> task = Task.Run(async () => await KeyCredentialManager.IsSupportedAsync());
                return task.Result;
            } catch (Exception) {
                return false;
            }
        }
    }
}