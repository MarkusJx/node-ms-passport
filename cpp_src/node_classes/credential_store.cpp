#include <napi_tools.hpp>

#include "../NodeMsPassport.hpp"
#include "credential.hpp"
#include "credential_store.hpp"

using namespace node_classes;
using namespace nodeMsPassport;

void credential_store::init(Napi::Env env, Napi::Object& exports) {
    Napi::Function func = DefineClass(env, "CredentialStore", {
        InstanceMethod("write", &credential_store::write, napi_enumerable),
        InstanceMethod("read", &credential_store::read, napi_enumerable),
        InstanceMethod("remove", &credential_store::remove, napi_enumerable),
        InstanceMethod("exists", &credential_store::exists, napi_enumerable),
        InstanceMethod("isEncrypted", &credential_store::is_encrypted, napi_enumerable),
        InstanceAccessor("accountId", &credential_store::get_account_id, nullptr, napi_enumerable),
        InstanceAccessor("encryptPasswords", &credential_store::get_encrypt_passwords, nullptr, napi_enumerable),
        StaticMethod("enumerateAccounts", &enumerate, napi_enumerable)
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
        encrypt_passwords = false;
    }

    {
        std::u16string id = info[0].ToString().Utf16Value();
        account_id = std::wstring(id.begin(), id.end());
    }
}

Napi::Value credential_store::enumerate(const Napi::CallbackInfo &info) {
    std::shared_ptr<std::wstring> target = nullptr;
    if (info.Length() >= 1) {
        if (info[0].IsString()) {
            std::u16string t = info[0].ToString().Utf16Value();
            target = std::make_shared<std::wstring>(t.begin(), t.end());
        } else if (!info[0].IsNull()) {
            throw Napi::TypeError::New(info.Env(), "The target name must be either of type string or null");
        }
    }

    return credential::enumerate(info.Env(), target);
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
        credentials::write(acc, user, password, encrypt);
    });
}

Napi::Value credential_store::read(const Napi::CallbackInfo& info) {
    return credential::createInstance(info.Env(), account_id, encrypt_passwords);
}

Napi::Value credential_store::remove(const Napi::CallbackInfo& info) {
    return napi_tools::promises::promise<void>(info.Env(), [account_id = account_id] {
        credentials::remove(account_id);
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
