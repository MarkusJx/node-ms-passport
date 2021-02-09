#ifndef PASSPORT_NODEMSPASSPORT_HPP
#define PASSPORT_NODEMSPASSPORT_HPP

#include <vector>
#include <string>

#if __cplusplus >= 201603L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201603L)
#   define NODEMSPASSPORT_NODISCARD [[nodiscard]]
#else
#   define NODEMSPASSPORT_NODISCARD
#endif

#undef max

/**
 * The dotNetBridge namespace
 */
namespace nodeMsPassport {
	using byte = unsigned char;
	namespace util {
		/**
		 * zallocator struct
		 * Source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
		 * with additions from: https://stackoverflow.com/a/53207813
		 */
		template<typename T>
		struct zallocator {
		public:
			typedef T value_type;
			typedef value_type* pointer;
			typedef const value_type* const_pointer;
			typedef value_type& reference;
			typedef const value_type& const_reference;
			typedef std::size_t size_type;
			typedef std::ptrdiff_t difference_type;

			constexpr zallocator() noexcept = default;

			template<class U>
			constexpr zallocator(const zallocator<U>& other) noexcept {}

			pointer address(reference v) const { return &v; }

			const_pointer address(const_reference v) const { return &v; }

			pointer allocate(size_type n, const void* hint = 0) {
				if (n > std::numeric_limits<size_type>::max() / sizeof(T))
					throw std::bad_alloc();
				return static_cast<pointer> (::operator new(n * sizeof(value_type)));
			}

			void deallocate(pointer p, size_type n) {
				std::fill_n((volatile char*)p, n * sizeof(T), 0);
				::operator delete(p);
			}

			[[nodiscard]] size_type max_size() const {
				return std::numeric_limits<size_type>::max() / sizeof(T);
			}

			template<typename U>
			struct rebind {
				typedef zallocator<U> other;
			};

			void construct(pointer ptr, const T& val) {
				new(static_cast<T*>(ptr)) T(val);
			}

			void destroy(pointer ptr) {
				static_cast<T*>(ptr)->~T();
			}

			template<typename U>
			friend bool operator==(const zallocator<T>& a, const zallocator<U>& b) {
				return true;
			}

			template<typename U>
			friend bool operator!=(const zallocator<T>& a, const zallocator<U>& b) {
				return false;
			}

#   if __cpluplus >= 201103L
			template<typename U, typename... Args>
			void construct(U* ptr, Args&&  ... args) {
				::new (static_cast<void*> (ptr)) U(std::forward<Args>(args)...);
			}

			template<typename U>
			void destroy(U* ptr) {
				ptr->~U();
			}
#   endif
		};

		template<class T>
		using basic_secure_vector = std::vector<T, zallocator<T>>;
		using basic_secure_wstring = std::basic_string<wchar_t, std::char_traits<wchar_t>, zallocator<wchar_t>>;
	}

	template<typename T>
	class secure_vector : public util::basic_secure_vector<T> {
	public:
		using util::basic_secure_vector<T>::basic_secure_vector;

		secure_vector() : util::basic_secure_vector<T>() {}

		secure_vector(const std::vector<T>& vec) : util::basic_secure_vector<T>(vec.begin(), vec.end()) {}

		NODEMSPASSPORT_NODISCARD std::vector<T> to_vector() const {
			return std::vector<T>(this->begin(), this->end());
		}
	};

	class secure_wstring : public util::basic_secure_wstring {
	public:
		using util::basic_secure_wstring::basic_secure_wstring;

		secure_wstring() : util::basic_secure_wstring() {}

		secure_wstring(const std::wstring& str) : util::basic_secure_wstring(str.begin(), str.end()) {}

		secure_wstring(const std::string& str) : util::basic_secure_wstring(str.size() + 1, L' ') {
			size_t outSize;

			errno_t err = mbstowcs_s(&outSize, (wchar_t*)this->data(), this->size(), str.c_str(), str.size());
			if (err) perror("Error creating wide string");
			this->resize(outSize);
		}

		secure_wstring(const secure_vector<unsigned char>& data) : util::basic_secure_wstring(
			data.size() / sizeof(wchar_t), L' ') {
			bool ok = memcpy_s((wchar_t*)this->data(), this->size() * sizeof(wchar_t), data.data(), data.size()) == 0;
			if (!ok) this->resize(0);
		}

		NODEMSPASSPORT_NODISCARD std::wstring to_wstring() const {
			return std::wstring(this->begin(), this->end());
		}

		NODEMSPASSPORT_NODISCARD secure_vector<unsigned char> getBytes() const {
			secure_vector<unsigned char> tmp;
			tmp.resize(this->size() * sizeof(wchar_t));

			bool ok = memcpy_s(tmp.data(), tmp.size(), this->c_str(), this->size() * sizeof(wchar_t)) == 0;
			if (!ok) tmp.resize(0);

			return tmp;
		}

		NODEMSPASSPORT_NODISCARD inline std::string to_string() const {
			std::string out(this->size() + 1, ' ');
			size_t outSize;

			errno_t err = wcstombs_s(&outSize, (char*)out.data(), out.size(), this->c_str(), this->size());
			if (err) perror("Error creating string");
			out.resize(outSize);

			return out;
		}
	};

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
		 * @return if the operation was successful
		 */
		bool write(const std::wstring& target, const std::wstring& user, const secure_wstring& password,
			bool encrypt);

		/**
		 * Read data from the password storage
		 *
		 * @param target the account id
		 * @param user the user name
		 * @param password the password
		 * @param whether the password is encrypted
		 * @return if the operation was successful
		 */
		bool read(const std::wstring& target, std::wstring& user, secure_wstring& password, bool encrypt);

		/**
		 * Remove a entry from the credential storage
		 *
		 * @param target the account id to remove
		 * @return if the operation was successful
		 */
		bool remove(const std::wstring& target);

		/**
		 * Check if a password entry is encrypted
		 *
		 * @param target the account id to check
		 * @param ok if the operation was successful
		 * @return if the password entry is encrypted
		 */
		bool isEncrypted(const std::wstring& target);
	}

	/**
	 * Namespace for encrypting passwords
	 */
	namespace passwords {
		/**
		 * Encrypt data using CredProtectW function
		 *
		 * @param data the data to encrypt, will remain unchanged if the encryption failed
		 * @return if the operation was successful
		 */
		bool encrypt(secure_wstring& data);

		/**
		 * Decrypt data using CredUnprotectW function
		 *
		 * @param data the data to decrypt, will remain unchanged if the decryption failed
		 * @return if the operation was successful
		 */
		bool decrypt(secure_wstring& data);

		/**
		 * Check if data was protected using CredProtectW
		 *
		 * @param data the data to check
		 * @return if the data is encrypted
		 */
		bool isEncrypted(const secure_wstring& data);
	}
}

#endif //PASSPORT_NODEMSPASSPORT_HPP