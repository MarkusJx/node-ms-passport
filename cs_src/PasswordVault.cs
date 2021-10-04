using System;
using System.Collections.Generic;
using PasswordCredential = Windows.Security.Credentials.PasswordCredential;
using WindowsPasswordVault = Windows.Security.Credentials.PasswordVault;

namespace CSNodeMsPassport {
    /// <summary>
    /// A wrapper around Windows.Security.Credentials.PasswordVault
    /// </summary>
    public static class PasswordVault {
        /// <summary>
        /// Check if an account exists in the password vault
        /// </summary>
        /// <param name="resource">The name of the resource</param>
        /// <param name="username">The username to find</param>
        /// <returns>true if the account exists</returns>
        public static bool AccountExists(string resource, string username) {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            try {
                PasswordCredential res = vault.Retrieve(resource, username);
                return res.UserName.Equals(username);
            } catch (Exception) {
                // vault.Retrieve throws an exception if
                // the username does not exist, so in this
                // case, the user does not exist
                return false;
            }
        }

        /// <summary>
        /// Store a username and password in the password vault
        /// </summary>
        /// <param name="resource">The name of the resource</param>
        /// <param name="username">The username to store</param>
        /// <param name="password">The password to store</param>
        public static void Store(string resource, string username, string password) {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            vault.Add(new PasswordCredential(resource, username, password));
        }

        /// <summary>
        /// Retrieve a password from the password vault
        /// </summary>
        /// <param name="resource">The name of the resource</param>
        /// <param name="username">The username to find</param>
        /// <exception cref="Exception">If the username could not be found</exception>
        /// <returns>The retrived user data</returns>
        public static LoginData Retrieve(string resource, string username) {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            PasswordCredential res = vault.Retrieve(resource, username);

            return new LoginData(res);
        }

        /// <summary>
        /// Remove a username and password from the password vault
        /// </summary>
        /// <param name="resource">The name of the resource</param>
        /// <param name="username">The username to remove</param>
        public static void Remove(string resource, string username) {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            PasswordCredential toDelete = vault.Retrieve(resource, username);
            vault.Remove(toDelete);
        }

        /// <summary>
        /// Retrieve all login data by a resource name
        /// </summary>
        /// <param name="resource">The name of the resource</param>
        /// <returns>The retrieved login data</returns>
        public static LoginData[] RetrieveByResource(string resource) {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            IReadOnlyList<PasswordCredential> passwords = vault.FindAllByResource(resource);

            return LoginData.ConvertList(passwords);
        }

        /// <summary>
        /// Retrieve all login data by a username
        /// </summary>
        /// <param name="username">The username to search for</param>
        /// <returns>The retrieved login data</returns>
        public static LoginData[] RetrieveByUsername(string username) {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            IReadOnlyList<PasswordCredential> passwords = vault.FindAllByUserName(username);

            return LoginData.ConvertList(passwords);
        }

        /// <summary>
        /// Retrieve all login data from the password vault
        /// </summary>
        /// <returns>The retrieved login data</returns>
        public static LoginData[] RetrieveAll() {
            WindowsPasswordVault vault = new WindowsPasswordVault();
            IReadOnlyList<PasswordCredential> passwords = vault.RetrieveAll();

            return LoginData.ConvertList(passwords);
        }
    }
}