#pragma once

#include <vector>

#ifdef NODEMSPASSPORT_STATIC_DEFINE
#  define NODEMSPASSPORT_EXPORT
#  define NODEMSPASSPORT_NO_EXPORT
#else
#  ifndef NODEMSPASSPORT_EXPORT
#    ifdef NODEMSPASSPORT_EXPORTS
/* We are building this library */
#      define NODEMSPASSPORT_EXPORT __declspec(dllexport)
#    else
/* We are using this library */
#      define NODEMSPASSPORT_EXPORT __declspec(dllimport)
#    endif
#  endif
#endif

#if __cplusplus >= 201603L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201603L)
#   define NODEMSPASSPORT_NODISCARD [[nodiscard]]
#else
#   define NODEMSPASSPORT_NODISCARD
#endif

/**
 * The dotNetBridge namespace
 */
namespace nodeMsPassport {
	/**
	 * A namespace for MS passport operations
	 */
	namespace passport {
		/**
		 * The unmanaged namespace. Functions in here should not be used.
		 */
		namespace unmanaged {
			NODEMSPASSPORT_EXPORT void freeData(char* data);

			NODEMSPASSPORT_EXPORT char* createPassportKey(int& status, int& outSize, const char* accountId);

			NODEMSPASSPORT_EXPORT char* passportSign(int& status, int& outSize, const char* accountId, const char* challenge, int challengeSize);

			NODEMSPASSPORT_EXPORT char* getPublicKeyHash(int& status, int& outSize, const char* accountId);

			NODEMSPASSPORT_EXPORT bool verifyChallenge(const char* challenge, int challengeSize, const char* signature, int signatureSize, const char* publicKey, int publicKeySize);

			NODEMSPASSPORT_EXPORT int deletePassportAccount(const char* accountId);
		}

		/**
		 * A class to get results of any passport operations
		 */
		class OperationResult {
		public:
			/**
			 * The OperationResult constructor
			 */
			OperationResult(std::vector<char> d, int s) : data(std::move(d)), status(s) {}

			/**
			 * Check if the status is ok
			 *
			 * @return true if the operation was successful
			 */
			NODEMSPASSPORT_NODISCARD inline bool ok() const {
				return status == 0;
			}

			/**
			 * The data returned by the operation
			 */
			const std::vector<char> data;

			/**
			 * The status of the operation. If the operation was successful, the status equals to zero
			 */
			const int status;
		};

		/**
		 * Check if passport is supported
		 *
		 * @return true if passport is available
		 */
		NODEMSPASSPORT_EXPORT bool passportAvailable();

		/**
		 * Get a passport public key
		 *
		 * @param accountId the id of the account to add
		 * @return the result of the operation
		 */
		inline OperationResult createPassportKey(const std::string& accountId) {
			int status, size = 0;
			char* data = unmanaged::createPassportKey(status, size, accountId.c_str());

			std::vector<char> dt;
			if (status == 0) {
				dt.resize(size);
				memcpy(dt.data(), data, size);
			}

			unmanaged::freeData(data);
			return OperationResult(dt, status);
		}

		/**
		 * Sign a challenge with a users private key
		 *
		 * @param accountId the id of the account
		 * @param challenge the challenge to sign
		 * @return the result of the operation
		 */
		inline OperationResult passportSign(const std::string& accountId, const std::vector<char>& challenge) {
			int status, size = 0;
			char* data = unmanaged::passportSign(status, size, accountId.c_str(), challenge.data(), (int)challenge.size());

			std::vector<char> dt;
			if (status == 0) {
				dt.resize(size);
				memcpy(dt.data(), data, size);
			}

			unmanaged::freeData(data);
			return OperationResult(dt, status);
		}

		/**
		 * Get a SHA-256 hash of the public key
		 *
		 * @param accountId the id of the account
		 * @return the result of the operation
		 */
		inline OperationResult getPublicKeyHash(const std::string& accountId) {
			int status, size = 0;
			char* data = unmanaged::getPublicKeyHash(status, size, accountId.c_str());

			std::vector<char> dt;
			if (status == 0) {
				dt.resize(size);
				memcpy(dt.data(), data, size);
			}

			unmanaged::freeData(data);
			return OperationResult(dt, status);
		}

		/**
		 * Verify a challenge signed by the passport application
		 *
		 * @param challenge the challenge used
		 * @param the signature returned by passport
		 * @param the public key of the user
		 * @return if the signature matched
		 */
		inline bool verifySignature(const std::vector<char>& challenge, const std::vector<char>& signature, const std::vector<char>& publicKey) {
			return unmanaged::verifyChallenge(challenge.data(), (int)challenge.size(), signature.data(), (int)signature.size(), publicKey.data(), (int)publicKey.size());
		}

		/**
		 * Delete a passport account
		 *
		 * @param accountId the id of the account to delete
		 * @return 0, if the account could be deleted, 1, if a unknown error occured, 2,
		 *         if the access was denied and 3, if the key is already deleted
		 */
		inline int deletePassportAccount(const std::string& accountId) {
			return unmanaged::deletePassportAccount(accountId.c_str());
		}
	}

	/**
	 * Credentials namespace
	 */
	namespace credentials {
		namespace util {
			NODEMSPASSPORT_EXPORT void* read(const std::string& target, wchar_t*& username, char*& cred, int& size);

			NODEMSPASSPORT_EXPORT void freePcred(void* data);

			inline bool to_string(const std::wstring& in, std::string& out) {
				out.resize(in.size() + 1);
				size_t written = 0;
				errno_t err = wcstombs_s(&written, (char *) out.data(), out.size(), in.c_str(), in.size());
				if (err != 0 || written != out.size()) {
					return false;
				}
				else {
					out.resize(in.size());
					return true;
				}
			}
		}

		/**
		 * Write data to the password storage
		 *
		 * @param target the account id
		 * @param user the user name to store
		 * @param password the password to store
		 * @return if the operation was successful
		 */
		NODEMSPASSPORT_EXPORT bool write(const std::string& target, const std::string& user, const std::string& password);

		/**
		 * Read data from the password storage
		 *
		 * @param target the account id
		 * @param user the user name
		 * @param password the password
		 * @return if the operation was successful
		 */
		inline bool read(const std::string& target, std::string& user, std::string& password) {
			wchar_t* username;
			char* cred;
			int size;

			void* pcred = util::read(target, username, cred, size);
			if (pcred == nullptr) {
				return false;
			}
			else {
				if (!util::to_string(username, user)) return false;
				password = std::string(cred, size);
				util::freePcred(pcred);

				return true;
			}
		}

		/**
		 * Remove a entry from the credential storage
		 *
		 * @param target the account id to remove
		 * @return if the operation was successful
		 */
		NODEMSPASSPORT_EXPORT bool remove(const std::string& target);
	}
}