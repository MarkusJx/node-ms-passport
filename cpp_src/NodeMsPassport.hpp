#ifndef PASSPORT_NODEMSPASSPORT_HPP
#define PASSPORT_NODEMSPASSPORT_HPP

#include "util.hpp"

/**
 * The dotNetBridge namespace
 */
namespace nodeMsPassport {
	/**
	 * A namespace for MS passport operations
	 */
	namespace passport {
		// A byte
		using byte = unsigned char;

		/**
		 * A passport exception
		 */
		class passportException : public std::exception {
		public:
			/**
			 * Create a passportException
			 * 
			 * @param err the error message
			 * @param errorCode the error code
			 */
			passportException(std::string err, int errorCode);

			/**
			 * Get the error message.
			 * Will be in the format {ERR_MSG}#{ERR_CODE}.
			 * 
			 * @return the error message
			 */
			const char* what() const noexcept override;

		private:
			std::string error;
		};

		/**
		 * Set where the C# dll is located
		 *
		 * @param location the location of the C# dll. Must end with an '/'.
		 */
		void setCSharpDllLocation(const std::string& location);

		/**
		 * Check if passport is supported
		 *
		 * @return true if passport is available
		 */
		bool passportAvailable();

		/**
		 * Check if a ms passport account exists
		 *
		 * @param accountId the id of the account to check
		 * @return true if the account exists
		 */
		bool passportAccountExists(const std::string& accountId);

		/**
		 * Get a passport public key
		 *
		 * @param accountId the id of the account to add
		 */
		void createPassportKey(const std::string& accountId);

		/**
		 * Sign a challenge with a users private key
		 *
		 * @param accountId the id of the account
		 * @param challenge the challenge to sign
		 * @return the result of the operation
		 */
		secure_vector<byte> passportSign(const std::string& accountId, const secure_vector<byte>& challenge);

		/**
		 * Get the public key
		 *
		 * @param accountId the id of the account
		 * @return the result of the operation
		 */
		secure_vector<byte> getPublicKey(const std::string& accountId);

		/**
		 * Get a SHA-256 hash of the public key
		 *
		 * @param accountId the id of the account
		 * @return the result of the operation
		 */
		secure_vector<byte> getPublicKeyHash(const std::string& accountId);

		/**
		 * Verify a challenge signed by the passport application
		 *
		 * @param challenge the challenge used
		 * @param the signature returned by passport
		 * @param the public key of the user
		 * @return true if the signature matched
		 */
		bool verifySignature(const secure_vector<byte>& challenge, const secure_vector<byte>& signature,
			const secure_vector<byte>& publicKey);

		/**
		 * Delete a passport account
		 *
		 * @param accountId the id of the account to delete
		 */
		void deletePassportAccount(const std::string& accountId);
	}

	/**
	 * Credentials namespace
	 */
	namespace credentials {
		/**
		 * Write data to the password storage
		 *
		 * @param target the account id
		 * @param user the user name to store
		 * @param password the password to store
		 * @param encrypt whether to encrypt the password
		 */
		void write(const std::wstring& target, const std::wstring& user, const secure_wstring& password,
			bool encrypt);

		/**
		 * Read data from the password storage
		 *
		 * @param target the account id
		 * @param user the user name
		 * @param password the password
		 * @param whether the password is encrypted
		 */
		void read(const std::wstring& target, std::wstring& user, secure_wstring& password, bool encrypt);

		/**
		 * Remove a entry from the credential storage
		 *
		 * @param target the account id to remove
		 */
		void remove(const std::wstring& target);

		/**
		 * Unprotect a credential
		 * 
		 * @param toUnprotect the string to decrypt
		 */
		void unprotectCredential(secure_wstring &toUnprotect);

		/**
		 * Protect a credential
		 * 
		 * @param toProtect the string to encrypt
		 */
		void protectCredential(secure_wstring &toProtect);

		/**
		 * Check if a password entry is encrypted
		 *
		 * @param target the account id to check
		 * @param ok if the operation was successful
		 * @return if the password entry is encrypted
		 */
		bool isEncrypted(const std::wstring& target);

		/**
		 * Check if a password vault account exists
		 * 
		 * @param target the target account name
		 * @return true if the account exists
		 */
		bool exists(const std::wstring &target);
	}

	/**
	 * Namespace for encrypting passwords
	 */
	namespace passwords {
		/**
		 * Encrypt data using CredProtectW function
		 *
		 * @param data the data to encrypt, will remain unchanged if the encryption failed
		 */
		void encrypt(secure_wstring& data);

		/**
		 * Decrypt data using CredUnprotectW function
		 *
		 * @param data the data to decrypt, will remain unchanged if the decryption failed
		 */
		void decrypt(secure_wstring& data);

		/**
		 * Check if data was protected using CredProtectW
		 *
		 * @param data the data to check
		 * @return if the data is encrypted
		 */
		bool isEncrypted(const secure_wstring& data);
	}

	/**
	 * Get the last win32 api error as a string
	 * 
	 * @returns the last error code as a string
	 */
	std::string get_last_error_as_string();

	/**
	 * Zero out a string
	 * 
	 * @tparam T the character type
	 * @tparam U the char_traits type
	 * @tparam R the allocator type
	 * @param str the string to zero out
	 */
	template<class T, class U, class R>
	void zero_string(std::basic_string<T, U, R>& str) {
        std::fill_n((volatile char *) str.data(), str.size() * sizeof(T), 0);
	}
}

#endif //PASSPORT_NODEMSPASSPORT_HPP