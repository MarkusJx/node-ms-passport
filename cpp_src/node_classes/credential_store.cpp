#include <napi_tools.hpp>

#include "../NodeMsPassport.hpp"
#include "credential.hpp"
#include "credential_store.hpp"

using namespace node_classes;
using namespace nodeMsPassport;

void credential_store::init(Napi::Env env, Napi::Object& exports) {
    Napi::Function func = DefineClass(env, "CredentialStore", {
        InstanceMethod("write", &write, napi_enumerable),
        InstanceMethod("read", &read, napi_enumerable),
        InstanceMethod("remove", &remove, napi_enumerable),
        InstanceMethod("exists", &exists, napi_enumerable),
        InstanceMethod("isEncrypted", &is_encrypted, napi_enumerable),
        InstanceAccessor("accountId", &get_account_id, nullptr, napi_enumerable),
        InstanceAccessor("encryptPasswords", &get_encrypt_passwords, nullptr, napi_enumerable)
    });

    auto *constructor = new Napi::FunctionReference();

    *constructor = Napi::Persistent(func);
    exports.Set("CredentialStore", func);

    env.SetInstanceData<Napi::FunctionReference>(constructor);
}

credential_store::credential_store(const Napi::CallbackInfo &info) : ObjectWrap(info) {
    CHECK_ARGS(napi_tools::napi_type::string);

    if (info.Length() > 2) {
        throw Napi::TypeError::New(info.Env(), "CredentialStore requires 1 or 2 arguments");
    }

    if (info.Length() == 2 && !info[1].IsUndefined()) {
        if (!info[1].IsBoolean()) {
            throw Napi::TypeError::New(info.Env(), "If set, the second argument must be of type boolean");
        }

        encrypt_passwords = info[1].ToBoolean();
    } else {
        encrypt_passwords = true;
    }

    {
        std::u16string id = info[0].ToString().Utf16Value();
        account_id = std::wstring(id.begin(), id.end());
    }
}

Napi::Value credential_store::get_account_id(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), reinterpret_cast<const char16_t *>(account_id.c_str()));
}

Napi::Value credential_store::get_encrypt_passwords(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), encrypt_passwords);
}

Napi::Value credential_store::write(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::napi_type::string, napi_tools::napi_type::string);

    std::u16string user_u16 = info[0].ToString();
    std::u16string password_u16 = info[1].ToString();

    std::wstring user(user_u16.begin(), user_u16.end());
    secure_wstring password(password_u16.begin(), password_u16.end());

    return napi_tools::promises::promise<void>(info.Env(), [user, password, acc = account_id, encrypt = encrypt_passwords] {
        if (!credentials::write(acc, user, password, encrypt)) {
            throw std::runtime_error("Could not store the credentials. Error: " + get_last_error_as_string());
        }
    });
}

Napi::Value credential_store::read(const Napi::CallbackInfo& info) {
    return credential::createInstance(info.Env(), account_id, encrypt_passwords);
}

Napi::Value credential_store::remove(const Napi::CallbackInfo& info) {
    return napi_tools::promises::promise<void>(info.Env(), [account_id = account_id] {
        if (!credentials::remove(account_id)) {
            throw std::runtime_error(get_last_error_as_string());
        }
    });
}

Napi::Value credential_store::is_encrypted(const Napi::CallbackInfo& info) {
    return napi_tools::promises::promise<bool>(info.Env(), [account_id = account_id] {
        return credentials::isEncrypted(account_id);
    });
}

Napi::Value credential_store::exists(const Napi::CallbackInfo& info) {
    return napi_tools::promises::promise<bool>(info.Env(), [account_id = account_id] {
        return credentials::exists(account_id);
    });
}