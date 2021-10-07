#include <windows.h>
#include <napi_tools.hpp>

#include "credential.hpp"

using namespace node_classes;
using namespace nodeMsPassport;

class credential_creator {
public:
    credential_creator() : encrypt(false), pass(nullptr) {}

    credential_creator(std::wstring acc, bool _encrypt) :
        account(std::move(acc)), encrypt(_encrypt), pass(std::make_shared<secure_wstring>()) {}

    std::wstring account;
    std::wstring user;
    std::shared_ptr<secure_wstring> pass;
    bool encrypt;

    static Napi::Value toNapiValue(const Napi::Env& env, const credential_creator& c) {
        Napi::Buffer<char16_t> pass = Napi::Buffer<char16_t>::New(env, (char16_t *) c.pass->data(), c.pass->size(),
            [p = c.pass] (const Napi::Env &, char16_t *) {});

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
        InstanceAccessor("passwordBuffer", &get_password_buffer, nullptr, napi_enumerable),
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

Napi::Value credential::createInstance(Napi::Env env, const std::wstring &account_id, bool encrypt) {
    return napi_tools::promises::promise<credential_creator>(env, [account_id, encrypt] {
        credential_creator res(account_id, encrypt);

        auto data = credentials::read(account_id);
        res.pass = std::make_shared<secure_wstring>(data.password);
        res.user = data.username;
        credentials::protectCredential(*res.pass);

        return res;
    });
}

Napi::Value credential::enumerate(Napi::Env env, const std::shared_ptr<std::wstring> &target) {
    return napi_tools::promises::promise<std::vector<credential_creator>>(env, [target] {
        std::vector<credentials::credential_read_result> data = credentials::enumerate(target);

        std::vector<credential_creator> res;
        res.reserve(data.size());
        for (const auto &c : data) {
            credential_creator creator(c.target, c.encrypted);
            creator.user = c.username;
            creator.pass = std::make_shared<secure_wstring>(c.password);
            if (!c.encrypted && !creator.pass->empty()) {
                credentials::protectCredential(*creator.pass);
            }

            res.push_back(creator);
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
            if (!password.empty())
                credentials::unprotectCredential(password);
            password_loaded = true;
        }
    });
}

Napi::Value credential::unload_password(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<void>(info.Env(), [this] {
        std::unique_lock lock(mtx);
        if (password_loaded) {
            try {
                if (!password.empty())
                    credentials::protectCredential(password);
            } catch (const std::exception& e) {
                password.clear();
                throw e;
            }

            password_loaded = false;
        }
    });
}

Napi::Value credential::refresh_data(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<void>(info.Env(), [this] {
        std::unique_lock lock(mtx);

        credentials::credential_read_result read;
        try {
            read = credentials::read(account_id);
            username = read.username;
            password = read.password;
        } catch (const std::exception& e) {
            password.clear();
            throw e;
        }

        try {
            credentials::protectCredential(password);
        } catch (const std::exception &e) {
            password.clear();
            throw e;
        }

        password_loaded = false;
    });
}

Napi::Value credential::update(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::napi_type::string, napi_tools::napi_type::string);

    std::u16string user = info[0].ToString().Utf16Value();
    auto u = std::wstring(user.begin(), user.end());

    std::u16string pass = info[1].ToString().Utf16Value();
    auto p = secure_wstring(pass.begin(), pass.end());
    zero_string(pass);

    return napi_tools::promises::promise<void>(info.Env(), [this, u, p] {
        std::unique_lock lock(mtx);
        credentials::write(account_id, u, p, encrypt);

        username = u;
        password = p;
        try {
            credentials::protectCredential(password);
        } catch (const std::exception& e) {
            password.clear();
            throw e;
        }

        password_loaded = false;
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

        credentials::credential_read_result read;
        try {
            read = credentials::read(account_id);
            username = read.username;
            password = read.password;
        } catch (const std::exception &e) {
            password.clear();
            throw e;
        }

        credentials::write(account_id, username, password, e);
        encrypt = e;

        try {
            credentials::protectCredential(password);
        } catch (const std::exception& e) {
            password.clear();
            throw e;
        }

        password_loaded = false;
    });
}

Napi::Value credential::is_encrypted(const Napi::CallbackInfo &info) {
    return napi_tools::promises::promise<bool>(info.Env(), [acc = account_id] {
        return credentials::isEncrypted(acc);
    });
}

Napi::Value credential::get_password_buffer(const Napi::CallbackInfo &info) {
    std::unique_lock lock(mtx);
    if (password_loaded) {
        const size_t size = password.size();
        auto *data = new char16_t[size];
        memcpy(data, password.c_str(), size * sizeof(char16_t));

        return Napi::Buffer<char16_t>::New(info.Env(), data, size, [size](const Napi::Env &, char16_t *data) {
            SecureZeroMemory(data, size * sizeof(char16_t));
            delete[] data;
        });
    } else {
        return info.Env().Null();
    }
}

Napi::FunctionReference *credential::constructor = nullptr;