#include <napi_tools.hpp>

#include "credential.hpp"

using namespace node_classes;
using namespace nodeMsPassport;

class credential_creator {
public:
    credential_creator() : encrypt(false), pass(nullptr) {}

    credential_creator(std::wstring acc, bool encrypt) :
        account(std::move(acc)), encrypt(encrypt), pass(std::make_shared<secure_wstring>()) {}

    std::wstring account;
    std::wstring user;
    std::shared_ptr<secure_wstring> pass;
    bool encrypt;

    static Napi::Value toNapiValue(const Napi::Env& env, const credential_creator& c) {
        Napi::Buffer<char16_t> pass = Napi::Buffer<char16_t>::New(env, (char16_t *) c.pass->data(), c.pass->size(),
            [p = c.pass] (const Napi::Env &, char16_t *) {});

        Napi::String account = Napi::String::New(env, (char16_t *) c.account.c_str());
        Napi::String user = Napi::String::New(env, (char16_t *) c.user.c_str());

        Napi::Boolean encrypt = Napi::Boolean::New(env, c.encrypt);

        return credential::constructor->New({
            Napi::String::New(env, (char16_t *) c.account.c_str()),
            Napi::String::New(env, (char16_t *) c.user.c_str()),
            pass,
            Napi::Boolean::New(env, c.encrypt)
        });
    }
};

void credential::init(Napi::Env env, Napi::Object &exports) {
    Napi::Function func = DefineClass(env, "Credential", {
        InstanceAccessor("accountId", &get_account_id, nullptr, napi_enumerable),
        InstanceAccessor("username", &get_username, nullptr, napi_enumerable),
        InstanceAccessor("password", &get_password, nullptr, napi_enumerable),
        InstanceAccessor("encrypted", &get_encrypt, nullptr, napi_enumerable),
        InstanceMethod("loadPassword", &load_password, napi_enumerable),
        InstanceMethod("unloadPassword", &unload_password, napi_enumerable),
        InstanceMethod("refreshData", &refresh_data, napi_enumerable),
        InstanceMethod("update", &update, napi_enumerable),
        InstanceMethod("setEncrypted", &set_encrypted, napi_enumerable),
        InstanceMethod("isEncrypted", &is_encrypted, napi_enumerable)
    });

    constructor = new Napi::FunctionReference();

    *constructor = Napi::Persistent(func);
    exports.Set("Credential", func);

    env.SetInstanceData<Napi::FunctionReference>(constructor);
}

Napi::Object credential::createInstance(Napi::Env env, const std::wstring &account_id, bool encrypt) {
    return napi_tools::promises::promise<credential_creator>(env, [account_id, encrypt] {
        credential_creator res(account_id, encrypt);

        if (!credentials::read(account_id, res.user, *res.pass, false)) {
            throw std::runtime_error("Could not read the credentials. Error: " + get_last_error_as_string());
        }

        if (!encrypt && !credentials::protectCredential(*res.pass)) {
            throw std::runtime_error("Could not encrypt the password. Error: " + get_last_error_as_string());
        }

        return res;
    });
}

credential::credential(const Napi::CallbackInfo &info) : ObjectWrap(info), mtx() {
    CHECK_ARGS(napi_tools::napi_type::string, napi_tools::napi_type::string, napi_tools::napi_type::buffer, napi_tools::napi_type::boolean);

    std::u16string acc = info[0].ToString().Utf16Value();
    account_id = std::wstring(acc.begin(), acc.end());

    std::u16string user = info[1].ToString().Utf16Value();
    username = std::wstring(user.begin(), user.end());

    auto pass = info[2].As<Napi::Buffer<char16_t>>();
    password = secure_wstring(reinterpret_cast<wchar_t *>(pass.Data()), pass.Length());

    encrypt = info[3].ToBoolean();
    password_loaded = false;
}

Napi::Value credential::get_account_id(const Napi::CallbackInfo &info) {
    return Napi::String::New(info.Env(), (char16_t *) account_id.c_str());
}

Napi::Value credential::get_username(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), (char16_t *) username.c_str());
}

Napi::Value credential::get_password(const Napi::CallbackInfo &info) {
    std::unique_lock lock(mtx);
    if (password_loaded) {
        return Napi::String::New(info.Env(), (char16_t *) password.c_str());
    } else {
        return info.Env().Null();
    }
}

Napi::Value credential::get_encrypt(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), encrypt);
}

Napi::Value credential::load_password(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<void>(info.Env(), [this] {
        std::unique_lock lock(mtx);
        if (!password_loaded) {
            if (credentials::unprotectCredential(password)) {
                password_loaded = true;
            } else {
                throw std::runtime_error("Could not load the password. Error: " + get_last_error_as_string());
            }
        }
    });
}

Napi::Value credential::unload_password(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<void>(info.Env(), [this] {
        std::unique_lock lock(mtx);
        if (password_loaded) {
            if (credentials::protectCredential(password)) {
                password_loaded = false;
            } else {
                password.clear();
                throw std::runtime_error("Could not unload the password. Error: " + get_last_error_as_string());
            }
        }
    });
}

Napi::Value credential::refresh_data(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<void>(info.Env(), [this] {
        std::unique_lock lock(mtx);
        
        if (!credentials::read(account_id, username, password, false)) {
            password.clear();
            throw std::runtime_error("Could not read the credentials. Error: " + get_last_error_as_string());
        }

        if (!encrypt && !credentials::protectCredential(password)) {
            password.clear();
            throw std::runtime_error("Could not encrypt the password. Error: " + get_last_error_as_string());
        }

        password_loaded = false;
    });
}

Napi::Value credential::update(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::napi_type::string, napi_tools::napi_type::string);

    std::u16string user = info[0].ToString().Utf16Value();
    auto u = std::wstring(user.begin(), user.end());

    std::u16string pass = info[0].ToString().Utf16Value();
    auto p = secure_wstring(pass.begin(), pass.end());
    zero_string(pass);

    return napi_tools::promises::promise<void>(info.Env(), [this, u, p] {
        std::unique_lock lock(mtx);
        if (!credentials::write(account_id, u, p, encrypt)) {
            throw std::runtime_error("Could not store the credentials. Error: " + get_last_error_as_string());
        }

        username = u;
        password = p;
        if (!credentials::protectCredential(password)) {
            password.clear();
            throw std::runtime_error("Could not encrypt the password. Error: " + get_last_error_as_string());
        } else {
            password_loaded = false;
        }
    });
    
}

Napi::Value credential::set_encrypted(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::napi_type::boolean);

    const bool e = info[0].ToBoolean();

    return napi_tools::promises::promise<void>(info.Env(), [e, this] {
        std::unique_lock lock(mtx);
        if (encrypt == e) {
            return;
        }

        if (!credentials::read(account_id, username, password, encrypt)) {
            password.clear();
            throw std::runtime_error("Could not read the credentials. Error: " + get_last_error_as_string());
        }

        if (!credentials::write(account_id, username, password, e)) {
            throw std::runtime_error("Could not store the credentials. Error: " + get_last_error_as_string());
        }

        encrypt = e;
        if (!credentials::protectCredential(password)) {
            password.clear();
            throw std::runtime_error("Could not encrypt the password. Error: " + get_last_error_as_string());
        } else {
            password_loaded = false;
        }
    });
}

Napi::Value credential::is_encrypted(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<bool>(info.Env(), [acc = account_id] {
        return credentials::isEncrypted(acc);
    });
}

Napi::FunctionReference *credential::constructor = nullptr;