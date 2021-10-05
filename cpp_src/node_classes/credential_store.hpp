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

        explicit credential_store(const Napi::CallbackInfo &info);

    private:
        Napi::Value get_account_id(const Napi::CallbackInfo &info);

        Napi::Value get_encrypt_passwords(const Napi::CallbackInfo &info);

        Napi::Value write(const Napi::CallbackInfo &info);

        Napi::Value read(const Napi::CallbackInfo &info);

        Napi::Value remove(const Napi::CallbackInfo &info);

        Napi::Value is_encrypted(const Napi::CallbackInfo &info);

        Napi::Value exists(const Napi::CallbackInfo &info);

        std::wstring account_id;
        bool encrypt_passwords;
    };
} // namespace node_classes

#endif // PASSPORT_CREDENTIAL_STORE_HPP
