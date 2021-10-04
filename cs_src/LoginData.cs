using System.Collections.Generic;
using PasswordCredential = Windows.Security.Credentials.PasswordCredential;

namespace CSNodeMsPassport {
    /// <summary>
    /// Login Data which contain a username and a password
    /// </summary>
    public sealed class LoginData {
        /// <summary>
        /// The retrieved user name
        /// </summary>
        public readonly string Username;

        /// <summary>
        /// The retrieved password
        /// </summary>
        public readonly string Password;

        /// <summary>
        /// Create a new LoginData instance from a
        /// Windows.Security.Credentials.PasswordCredential
        /// </summary>
        /// <param name="credential">The PasswordCredential object to convert</param>
        public LoginData(PasswordCredential credential) {
            this.Username = credential.UserName;
            credential.RetrievePassword();
            this.Password = credential.Password;
        }

        /// <summary>
        /// Convert a list of PasswordCredentials to an array of LoginData
        /// </summary>
        /// <param name="data">The PasswordCredential list to convert</param>
        /// <returns>The converted login data</returns>
        public static LoginData[] ConvertList(IReadOnlyList<PasswordCredential> data) {
            int size = data.Count;
            LoginData[] res = new LoginData[size];
            for (int i = 0; i < size; ++i) {
                res[i] = new LoginData(data[i]);
            }

            return res;
        }
    }
}