using Passport.Utils;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Credentials.UI;
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
        /// Create a passport key
        /// </summary>
        /// <exception cref="UserCancelledException"></exception>
        /// <exception cref="MissingPinException"></exception>
        /// <exception cref="UserPrefersPasswordException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <param name="accountId">The account id</param>
        public static void CreatePassportKey(string accountId) {
            // Run KeyCredentialManager.RequestCreateAsync to create the account.
            // Overwrites any existing accounts
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () =>
                await KeyCredentialManager.RequestCreateAsync(accountId, KeyCredentialCreationOption.ReplaceExisting));

            // Check the KeyCredentialRetrievalResult status
            switch (task.Result.Status) {
                case KeyCredentialStatus.Success:
                    // The operation was successful
                    return;
                case KeyCredentialStatus.UserCanceled:
                    // User cancelled the Passport enrollment process
                    throw new UserCancelledException();
                case KeyCredentialStatus.NotFound:
                    // User needs to create PIN
                    throw new MissingPinException();
                case KeyCredentialStatus.UserPrefersPassword:
                    // The user prefers a password
                    throw new UserPrefersPasswordException();
                default:
                    // An unknown error occurred
                    throw new UnknownException();
            }
        }

        /// <summary>
        /// Sign a challenge using windows hello
        /// </summary>
        /// <param name="accountId">The id of the account to use</param>
        /// <param name="challenge">The challenge to sign</param>
        /// <exception cref="SignOperationFailedException"></exception>
        /// <exception cref="UserCancelledException"></exception>
        /// <exception cref="AccountNotFoundException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <returns>A passport result, storing the signed challenge in its buffer</returns>
        public static byte[] PassportSign(string accountId, byte[] challenge) {
            // Try to open the account
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
            KeyCredentialRetrievalResult retrieveResult = task.Result;

            // Check the KeyCredentialRetrievalResult status
            switch (retrieveResult.Status) {
                case KeyCredentialStatus.Success:
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
                        CryptographicBuffer.CopyToByteArray(signatureBuffer, out byte[] buffer);
                        // The operation was successful
                        return buffer;
                    } else {
                        // The sign operation failed
                        throw new SignOperationFailedException();
                    }
                case KeyCredentialStatus.UserCanceled:
                    // User cancelled the Passport enrollment process
                    throw new UserCancelledException();
                case KeyCredentialStatus.NotFound:
                    // The account was not found
                    throw new AccountNotFoundException();
                default:
                    // An unknown error occurred
                    throw new UnknownException();
            }
        }

        /// <summary>
        /// Get the public key of the windiws hello account
        /// </summary>
        /// <param name="accountId">The id of the account to use</param>
        /// <exception cref="UserCancelledException"></exception>
        /// <exception cref="AccountNotFoundException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <returns>A passport result, storing the public key in its buffer</returns>
        public static byte[] GetPublicKey(string accountId) {
            // Try to get the account
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
            KeyCredentialRetrievalResult retrievalResult = task.Result;

            // Check the KeyCredentialRetrievalResult status
            switch (retrievalResult.Status) {
                case KeyCredentialStatus.Success:
                    // Get the user's credential
                    KeyCredential userCredential = retrievalResult.Credential;

                    // Get the public key
                    IBuffer publicKey = userCredential.RetrievePublicKey();

                    // Copy the public key to the PassportResult's buffer
                    CryptographicBuffer.CopyToByteArray(publicKey, out byte[] buffer);

                    // The operation was successful
                    return buffer;
                case KeyCredentialStatus.UserCanceled:
                    // User cancelled the Passport enrollment process
                    throw new UserCancelledException();
                case KeyCredentialStatus.NotFound:
                    // The account was not found
                    throw new AccountNotFoundException();
                default:
                    // An unknown error occurred
                    throw new UnknownException();
            }
        }

        /// <summary>
        /// Get the public key
        /// </summary>
        /// <param name="accountId">The id of the account to use</param>
        /// <param name="encoding">The name of the encoding</param>
        /// <exception cref="UserCancelledException"></exception>
        /// <exception cref="AccountNotFoundException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArithmeticException"></exception>
        /// <exception cref="OverflowException"></exception>
        /// <returns>The public key in a buffer</returns>
        public static byte[] GetEncodedPublicKey(string accountId, string encoding) {
            // Try to get the account
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
            KeyCredentialRetrievalResult retrievalResult = task.Result;

            // Check the KeyCredentialRetrievalResult status
            switch (retrievalResult.Status) {
                case KeyCredentialStatus.Success:
                    // Get the user's credential
                    KeyCredential userCredential = retrievalResult.Credential;

                    // Get the enum type
                    var type = (CryptographicPublicKeyBlobType) Enum.Parse(typeof(CryptographicPublicKeyBlobType), encoding);

                    // Get the public key
                    IBuffer publicKey = userCredential.RetrievePublicKey(type);

                    // Copy the public key to the PassportResult's buffer
                    CryptographicBuffer.CopyToByteArray(publicKey, out byte[] buffer);

                    // The operation was successful
                    return buffer;
                case KeyCredentialStatus.UserCanceled:
                    // User cancelled the Passport enrollment process
                    throw new UserCancelledException();
                case KeyCredentialStatus.NotFound:
                    // The account was not found
                    throw new AccountNotFoundException();
                default:
                    // An unknown error occurred
                    throw new UnknownException();
            }
        }

        /// <summary>
        /// Request user verification
        /// </summary>
        /// <param name="message">The message to display</param>
        /// <returns>The verification result</returns>
        public static int RequestVerification(string message) {
            Task<UserConsentVerificationResult> task = Task.Run(async () => await UserConsentVerifier.RequestVerificationAsync(message));
            UserConsentVerificationResult result = task.Result;

            return (int) result;
        }

        /// <summary>
        /// Get a hashed version of the public key
        /// </summary>
        /// <exception cref="UserCancelledException"></exception>
        /// <exception cref="AccountNotFoundException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <param name="accountId">The id of the account to use</param>
        /// <returns>A passport result, storing the hashed public key in its buffer</returns>
        public static byte[] GetPublicKeyHash(string accountId) {
            byte[] res = GetPublicKey(accountId);
            // Get a hash provider for the SHA256 algorithm and hash the public key
            HashAlgorithmProvider hashProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            IBuffer publicKeyHash = hashProvider.HashData(CryptographicBuffer.CreateFromByteArray(res));

            // Copy the hashed public key to the PassportResult's buffer
            CryptographicBuffer.CopyToByteArray(publicKeyHash, out byte[] outBuffer);

            // Return the PassportResult
            return outBuffer;
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
            } catch (Exception e) {
                switch (e.HResult) {
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
        /// </summary>
        /// <exception cref="KeyAlreadyDeletedException"></exception>
        /// <exception cref="AccessDeniedException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <param name="accountId">The id of the account to delete</param>
        public static void DeletePassportAccount(string accountId) {
            Task<int> task = DeletePassportAccountAsync(accountId);
            switch (task.Result) {
                case 0:
                    return;
                case 3:
                    // The key is already deleted
                    throw new KeyAlreadyDeletedException();
                case 2:
                    // The access was denied
                    throw new AccessDeniedException();
                default:
                    // An unknown error occurred
                    throw new UnknownException();
            }
        }

        /// <summary>
        /// Check if a ms passport account exists
        /// </summary>
        /// <exception cref="UserCancelledException"></exception>
        /// <exception cref="UserPrefersPasswordException"></exception>
        /// <exception cref="UnknownException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <param name="accountId">The id of the account to check</param>
        /// <returns>true if the account exists</returns>
        public static bool PassportAccountExists(string accountId) {
            // Try to get the account
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));

            // Check the result
            switch (task.Result.Status) {
                case KeyCredentialStatus.Success:
                    // The account was found
                    return true;
                case KeyCredentialStatus.NotFound:
                    // The account was not found
                    return false;
                case KeyCredentialStatus.UserCanceled:
                    // The operation was cancelled by the user
                    throw new UserCancelledException();
                case KeyCredentialStatus.UserPrefersPassword:
                    // The user prefers a password
                    throw new UserPrefersPasswordException();
                default:
                    // An unknwon error occurred
                    throw new UnknownException();
            }
        }

        /// <summary>
        /// Verify a challenge
        /// </summary>
        /// <param name="challenge">The challenge</param>
        /// <param name="signature">The signature returned by a client</param>
        /// <param name="publicKey">The public key of the client</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <returns>true, if the signature matches, false otherwise</returns>
        public static bool VerifyChallenge(byte[] challenge, byte[] signature, byte[] publicKey) {
            // Validate that the original challenge was signed using the corresponding private key.
            CngKey pubCngKey = new SubjectPublicKeyInfo(publicKey).GetPublicKey();

            // Validate that the original challenge was signed using the corresponding private key.
            RSACng pubKey = new RSACng(pubCngKey);
            return pubKey.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Check if passport is available on this system
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="AggregateException"></exception>
        /// <returns>true if passport is available</returns>
        public static bool PassportAvailable() {
            Task<bool> task = Task.Run(async () => await KeyCredentialManager.IsSupportedAsync());
            return task.Result;
        }
    }
}