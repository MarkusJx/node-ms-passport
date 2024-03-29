#ifndef PASSPORT_CREDENTIAL_STORE_HPP
#define PASSPORT_CREDENTIAL_STORE_HPP

#include <napi.h>

/**
 * A namespace for node classes
 */
namespace node_classes {
    /**
     * A class for managing the windows credential store
     */
    class credential_store : public Napi::ObjectWrap<credential_store> {
    public:
        /**
         * Initialize the class for use with node.js
         * 
         * @param env the environment to work in
         * @param exports the exports to write this class to
         */
        static void init(Napi::Env env, Napi::Object &exports);

        /**
         * Create a credential store instance
         *
         * @param info the callback info
         */
        explicit credential_store(const Napi::CallbackInfo &info);

    private:
        /**
         * Enumerate all stored passwords
         * 
         * @param info the callback info
         * @return a promise which resolves to an array containing all passwords
         */
        static Napi::Value enumerate(const Napi::CallbackInfo &info);

        /**
         * Get the account id
         *
         * @param info the callback info
         * @return the account id
         */
        Napi::Value get_account_id(const Napi::CallbackInfo &info);

        /**
         * Get whether to encrypt passwords
         *
         * @param info the callback info
         * @return true if the passwords are encrypted
         */
        Napi::Value get_encrypt_passwords(const Napi::CallbackInfo &info);

        /**
         * Write a password to the credential storage
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value write(const Napi::CallbackInfo &info);

        /**
         * Read data from the credential storage
         *
         * @param info the callback info
         * @return a credential promise
         */
        Napi::Value read(const Napi::CallbackInfo &info);

        /**
         * Remove the account from the credential store
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value remove(const Napi::CallbackInfo &info);

        /**
         * Check if the stored password is encrypted
         *
         * @param info the callback info
         * @return a boolean promise
         */
        Napi::Value is_encrypted(const Napi::CallbackInfo &info);

        /**
         * Check if the account exists
         *
         * @param info the callback info
         * @return a boolean promise
         */
        Napi::Value exists(const Napi::CallbackInfo &info);

        /// The account id
        std::wstring account_id;
        /// Whether to encrypt passwords
        bool encrypt_passwords;
    };
} // namespace node_classes

#endif // PASSPORT_CREDENTIAL_STORE_HPP
