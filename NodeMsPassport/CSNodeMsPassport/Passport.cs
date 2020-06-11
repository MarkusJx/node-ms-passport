using Passport.Utils;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace CSNodeMsPassport
{
    public static class Passport
    {
        private const int NTE_NO_KEY = unchecked((int)0x8009000D);
        private const int NTE_PERM = unchecked((int)0x80090010);

        public struct PassportResult
        {
            public byte[] buffer;
            public int status;
        }

        public static PassportResult CreatePassportKey(string accountId)
        {
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.RequestCreateAsync(accountId, KeyCredentialCreationOption.ReplaceExisting));
            KeyCredentialRetrievalResult keyCreationResult = task.Result;

            PassportResult res = new PassportResult();

            if (keyCreationResult.Status == KeyCredentialStatus.Success)
            {
                KeyCredential userKey = keyCreationResult.Credential;
                IBuffer publicKey = userKey.RetrievePublicKey();

                CryptographicBuffer.CopyToByteArray(publicKey, out res.buffer);
                res.status = 0;
            }
            else if (keyCreationResult.Status == KeyCredentialStatus.UserCanceled)
            {
                // User cancelled the Passport enrollment process
                res.status = 3;
            }
            else if (keyCreationResult.Status == KeyCredentialStatus.NotFound)
            {
                // User needs to create PIN
                res.status = 2;
            }
            else
            {
                res.status = 1;
            }

            return res;
        }

        public static PassportResult PassportSign(string accountId, byte[] challenge)
        {
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
            KeyCredentialRetrievalResult retrieveResult = task.Result;

            PassportResult res = new PassportResult();

            if (retrieveResult.Status == KeyCredentialStatus.Success)
            {
                KeyCredential userCredential = retrieveResult.Credential;

                IBuffer challengeBuffer = CryptographicBuffer.CreateFromByteArray(challenge);
                Task<KeyCredentialOperationResult> opTask = Task.Run(async () => await userCredential.RequestSignAsync(challengeBuffer));
                KeyCredentialOperationResult opResult = opTask.Result;

                if (opResult.Status == KeyCredentialStatus.Success)
                {
                    IBuffer signatureBuffer = opResult.Result;

                    CryptographicBuffer.CopyToByteArray(signatureBuffer, out res.buffer);
                    res.status = 0;
                }
                else
                {
                    res.status = -1;
                }
            }
            else if (retrieveResult.Status == KeyCredentialStatus.UserCanceled)
            {
                // User cancelled the Passport enrollment process
                res.status = 3;
            }
            else if (retrieveResult.Status == KeyCredentialStatus.NotFound)
            {
                // User needs to create PIN
                res.status = 2;
            }
            else
            {
                res.status = 1;
            }

            return res;
        }

        public static PassportResult GetPublicKeyHash(string accountId)
        {
            Task<KeyCredentialRetrievalResult> task = Task.Run(async () => await KeyCredentialManager.OpenAsync(accountId));
            KeyCredentialRetrievalResult retrieveResult = task.Result;

            PassportResult res = new PassportResult();

            if (retrieveResult.Status == KeyCredentialStatus.Success)
            {
                KeyCredential userCredential = retrieveResult.Credential;

                HashAlgorithmProvider hashProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
                IBuffer publicKeyHash = hashProvider.HashData(userCredential.RetrievePublicKey());

                CryptographicBuffer.CopyToByteArray(publicKeyHash, out res.buffer);
                res.status = 0;
            }
            else if (retrieveResult.Status == KeyCredentialStatus.UserCanceled)
            {
                // User cancelled the Passport enrollment process
                res.status = 3;
            }
            else if (retrieveResult.Status == KeyCredentialStatus.NotFound)
            {
                // User needs to create PIN
                res.status = 2;
            }
            else
            {
                res.status = 1;
            }

            return res;
        }

        private static async Task<int> DeletePassportAccountAsync(string accountId)
        {
            int res;
            try
            {
                await KeyCredentialManager.DeleteAsync(accountId);
                res = 0;
            }
            catch (Exception ex)
            {
                switch (ex.HResult)
                {
                    case NTE_NO_KEY:
                        // Key is already deleted. Ignore this error.
                        res = 3;
                        break;
                    case NTE_PERM:
                        // Access is denied. Ignore this error. We tried our best.
                        res = 2;
                        break;
                    default:
                        res = 1;
                        break;
                }
            }
            return res;
        }

        public static bool VerifyChallenge(byte[] challenge, byte[] signature, byte[] publicKey)
        {
            bool ok = false;

            // Validate that the original challenge was signed using the corresponding private key.
            try
            {
                CngKey pubCngKey = new SubjectPublicKeyInfo(publicKey).GetPublicKey();

                // Validate that the original challenge was signed using the corresponding private key.
                using (RSACng pubKey = new RSACng(pubCngKey))
                {
                    ok = pubKey.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception) { }

            return ok;
        }

        public static int DeletePassportAccount(string accountId)
        {
            Task<int> task = DeletePassportAccountAsync(accountId);
            return task.Result;
        }

        public static bool PassportAvailable()
        {
            Task<bool> task = Task.Run(async () => await KeyCredentialManager.IsSupportedAsync());
            return task.Result;
        }
    }
}