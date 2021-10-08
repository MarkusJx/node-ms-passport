#ifndef PASSPORT_CREDENTIAL_HPP
#define PASSPORT_CREDENTIAL_HPP

#include <napi.h>

#include "../NodeMsPassport.hpp"

namespace node_classes {
    /**
     * A credential blob
     */
    class credential : public Napi::ObjectWrap<credential> {
    public:
        /**
         * Initialize the class to be used with node.js
         *
         * @param env the environment to work in
         * @param exports the exports to write the class to
         */
        static void init(Napi::Env env, Napi::Object &exports);

        /**
         * Create a new credential instance
         *
         * @param env the environment to work in
         * @param account_id the id of the account
         * @param encrypt whether to encrypt passwords
         * @return the created instance
         */
        static Napi::Value createInstance(Napi::Env env, const std::wstring &account_id, bool encrypt);

        /**
         * Enumerate all accounts.
         * Returns a promise which resolves to an array of credentials.
         * 
         * @param env the environment to work in
         * @param target the account to search for. May be nullptr.
         * @return the promise
         */
        static Napi::Value enumerate(Napi::Env env, const std::shared_ptr<std::wstring> &target);

        /**
         * Create a new credential instance from node.js
         *
         * @param info the callback info
         */
        explicit credential(const Napi::CallbackInfo &info);

        /// The constructor function reference
        static Napi::FunctionReference *constructor;

    private:
        /**
         * Get the account id
         *
         * @param info the callback info
         * @return the account id Napi::String
         */
        Napi::Value get_account_id(const Napi::CallbackInfo &info);

        /**
         * Get the username
         *
         * @param info the callback info
         * @return the username Napi::String
         */
        Napi::Value get_username(const Napi::CallbackInfo &info);

        /**
         * Get the password
         *
         * @param info the callback info
         * @return Napi::Null if the password is not loaded or the password Napi::String
         */
        Napi::Value get_password(const Napi::CallbackInfo &info);

        /**
         * Get whether to store the password encrypted
         *
         * @param info the callback info
         * @return a Napi::Boolean determining whether the password is stored in encrypted form
         */
        Napi::Value get_encrypt(const Napi::CallbackInfo &info);

        /**
         * Check if the password could be decrypted
         *
         * @param info the callback info
         * @return true if the credential is valid
         */
        Napi::Value get_valid(const Napi::CallbackInfo &info);

        /**
         * Load the password.
         * Just decrypts the password and makes is available for reading.
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value load_password(const Napi::CallbackInfo &info);

        /**
         * Unload the password.
         * Just encrypts the password and disables reading.
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value unload_password(const Napi::CallbackInfo &info);

        /**
         * Refresh the data
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value refresh_data(const Napi::CallbackInfo &info);

        /**
         * Update the data
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value update(const Napi::CallbackInfo &info);

        /**
         * Set whether to encrypt the password when storing
         *
         * @param info the callback info
         * @return a void promise
         */
        Napi::Value set_encrypted(const Napi::CallbackInfo &info);

        /**
         * Check if the password is stored in an encrypted form.
         * Fetches the password in order to check it.
         *
         * @param info the callback info
         * @return a boolean promise
         */
        Napi::Value is_encrypted(const Napi::CallbackInfo &info);

        /**
         * Get the password as a Napi::Buffer
         *
         * @param info the callback info
         * @return the password buffer or null if the password is not loaded
         */
        Napi::Value get_password_buffer(const Napi::CallbackInfo &info);

        /// The account id
        std::wstring account_id;
        /// The username
        std::wstring username;
        /// The password. Is encrypted if password_loaded is false
        nodeMsPassport::secure_wstring password;
        /// Whether to encrypt the password
        bool encrypt;
        /// Whether the password is decrypted
        bool password_loaded;
        /// Whether the password could be decrypted
        bool valid;
        /// A mutex for synchronizing password operations
        std::mutex mtx;
    };
}// namespace node_classes

#endif//PASSPORT_CREDENTIAL_HPP