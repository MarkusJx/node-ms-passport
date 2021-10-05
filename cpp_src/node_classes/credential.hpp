#ifndef PASSPORT_CREDENTIAL_HPP
#define PASSPORT_CREDENTIAL_HPP

#include <napi.h>

#include "../NodeMsPassport.hpp"

namespace node_classes {
    class credential : public Napi::ObjectWrap<credential> {
    public:
        static void init(Napi::Env env, Napi::Object &exports);

        static Napi::Object createInstance(Napi::Env env, const std::wstring &account_id, bool encrypt);

        explicit credential(const Napi::CallbackInfo &info);

        static Napi::FunctionReference *constructor;

    private:
        Napi::Value get_account_id(const Napi::CallbackInfo &info);

        Napi::Value get_username(const Napi::CallbackInfo &info);

        Napi::Value get_password(const Napi::CallbackInfo &info);

        Napi::Value get_encrypt(const Napi::CallbackInfo &info);

        Napi::Value load_password(const Napi::CallbackInfo &info);

        Napi::Value unload_password(const Napi::CallbackInfo &info);

        Napi::Value refresh_data(const Napi::CallbackInfo &info);

        Napi::Value update(const Napi::CallbackInfo &info);

        Napi::Value set_encrypted(const Napi::CallbackInfo &info);

        Napi::Value is_encrypted(const Napi::CallbackInfo &info);

        Napi::Value get_password_buffer(const Napi::CallbackInfo &info);

        std::wstring account_id;
        std::wstring username;
        nodeMsPassport::secure_wstring password;
        bool encrypt;
        bool password_loaded;
        std::mutex mtx;
    };
} // namespace node_classes

#endif //PASSPORT_CREDENTIAL_HPP