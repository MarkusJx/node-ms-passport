#include <napi.h>
#include <sstream>
#include <random>
#include <NodeMsPassport.h>

#define CHECK_ARGS(...) ::util::checkArgs(info, ::util::removeNamespace(__FUNCTION__), {__VA_ARGS__})
#define CHECK_INDEX(index, size) if (index < 0) throw Napi::RangeError::New(env, "Negative index requested"); \
                    else if (((size_t) index) >= size) throw Napi::RangeError::New(env, "Index out of range. Requested index: " + std::to_string(index) + ", array size: " + std::to_string(size))
#define CATCH_EXCEPTIONS catch (const std::exception &e) {throw Napi::Error::New(info.Env(), e.what());} catch (...) {throw Napi::Error::New(info.Env(), "An unknown exception occurred");}
#define EXPORT(function) "js_" + ::util::removeNamespace(#function), Napi::Function::New(env, function)

using namespace nodeMsPassport;

enum type {
    STRING,
    NUMBER,
    FUNCTION,
    OBJECT,
    BOOLEAN
};

class exception : public std::exception {
public:
#ifdef __APPLE__
    explicit exception(const char *msg) : std::exception(), msg(msg) {}

        [[nodiscard]] const char *what() const noexcept override {
            return msg;
        }

    private:
        const char *msg;
#else
    using std::exception::exception;
#endif
};

namespace util {
    std::string removeNamespace(const std::string &str) {
        return str.substr(str.rfind(':') + 1);
    }

    void checkArgs(const Napi::CallbackInfo &info, const std::string &funcName, const std::vector<type> &types) {
        Napi::Env env = info.Env();
        if (info.Length() < types.size()) {
            throw Napi::TypeError::New(env, funcName + " requires " + std::to_string(types.size()) + " arguments");
        }

        for (size_t i = 0; i < types.size(); i++) {
            if (types[i] == STRING) {
                if (!info[i].IsString()) {
                    throw Napi::TypeError::New(env, "Argument type mismatch: " + funcName +
                                                    " requires type string at position " + std::to_string(i + 1));
                }
            } else if (types[i] == NUMBER) {
                if (!info[i].IsNumber()) {
                    throw Napi::TypeError::New(env, "Argument type mismatch: " + funcName +
                                                    " requires type number at position " + std::to_string(i + 1));
                }
            } else if (types[i] == FUNCTION) {
                if (!info[i].IsFunction()) {
                    throw Napi::TypeError::New(env, "Argument type mismatch: " + funcName +
                                                    " requires type function at position " + std::to_string(i + 1));
                }
            } else if (types[i] == OBJECT) {
                if (!info[i].IsObject()) {
                    throw Napi::TypeError::New(env, "Argument type mismatch: " + funcName +
                                                    " requires type object at position " + std::to_string(i + 1));
                }
            } else if (types[i] == BOOLEAN) {
                if (!info[i].IsBoolean()) {
                    throw Napi::TypeError::New(env, "Argument type mismatch: " + funcName +
                                                    " requires type boolean at position " + std::to_string(i + 1));
                }
            }
        }
    }
}

std::vector<char> string_to_binary(const std::string &source) {
    static unsigned int nibbles[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15};
    std::vector<char> retval;
    for (std::string::const_iterator it = source.begin(); it < source.end(); it += 2) {
        unsigned char v = 0;
        if (isxdigit(*it))
            v = nibbles[toupper(*it) - '0'] << (unsigned) 4;
        if (it + 1 < source.end() && isxdigit(*(it + 1)))
            v += nibbles[toupper(*(it + 1)) - '0'];
        retval.push_back(v);
    }
    return retval;
}

std::string binary_to_string(const std::vector<char> &source) {
    static char syms[] = "0123456789ABCDEF";
    std::stringstream ss;
    for (std::_Vector_const_iterator<std::_Vector_val<std::_Simple_types<char> > >::value_type it : source)
        ss << syms[(((unsigned) it >> (unsigned) 4) & (unsigned) 0xf)] << syms[(unsigned) it & (unsigned) 0xf];

    return ss.str();
}

Napi::Object convertToObject(const Napi::Env &env, const passport::OperationResult &res) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("status", Napi::Number::New(env, res.status));
    if (res.status == 0) {
        obj.Set("data", Napi::String::New(env, binary_to_string(res.data)));
    } else {
        obj.Set("data", env.Null());
    }

    return obj;
}

Napi::Boolean passportAvailable(const Napi::CallbackInfo &info) {
    try {
        return Napi::Boolean::New(info.Env(), passport::passportAvailable());
    } CATCH_EXCEPTIONS
}

Napi::Object createPassportKey(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING);

    try {
        std::string account = info[0].As<Napi::String>();
        passport::OperationResult res = passport::createPassportKey(account);

        return convertToObject(info.Env(), res);
    } CATCH_EXCEPTIONS
}

Napi::Object passportSign(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING, STRING);

    try {
        std::string account = info[0].As<Napi::String>();
        std::vector<char> challenge = string_to_binary(info[1].As<Napi::String>().Utf8Value());

        passport::OperationResult res = passport::passportSign(account, challenge);

        return convertToObject(info.Env(), res);
    } CATCH_EXCEPTIONS
}

Napi::Number deletePassportAccount(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING);

    try {
        std::string account = info[0].As<Napi::String>();

        return Napi::Number::New(info.Env(), passport::deletePassportAccount(account));
    } CATCH_EXCEPTIONS
}

Napi::Object getPublicKey(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING);

    try {
        std::string account = info[0].As<Napi::String>();

        passport::OperationResult res = passport::getPublicKey(account);

        return convertToObject(info.Env(), res);
    } CATCH_EXCEPTIONS
}

Napi::Object getPublicKeyHash(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING);

    try {
        std::string account = info[0].As<Napi::String>();

        passport::OperationResult res = passport::getPublicKeyHash(account);

        return convertToObject(info.Env(), res);
    } CATCH_EXCEPTIONS
}

Napi::Boolean verifySignature(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING, STRING, STRING);

    try {
        std::vector<char> challenge = string_to_binary(info[0].As<Napi::String>().Utf8Value());
        std::vector<char> signature = string_to_binary(info[1].As<Napi::String>().Utf8Value());
        std::vector<char> publicKey = string_to_binary(info[2].As<Napi::String>().Utf8Value());

        return Napi::Boolean::New(info.Env(), passport::verifySignature(challenge, signature, publicKey));
    } CATCH_EXCEPTIONS
}

Napi::Boolean writeCredential(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING, STRING, STRING);

    try {
        std::string target = info[0].As<Napi::String>();
        std::string user = info[1].As<Napi::String>();
        std::string password = info[2].As<Napi::String>();

        return Napi::Boolean::New(info.Env(), credentials::write(target, user, password));
    } CATCH_EXCEPTIONS
}

Napi::Value readCredential(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING);

    try {
        Napi::Env env = info.Env();
        std::string target = info[0].As<Napi::String>();
        std::string user, password;

        if (credentials::read(target, user, password)) {
            Napi::Object obj = Napi::Object::New(env);

            obj.Set("username", Napi::String::New(env, user));
            obj.Set("password", Napi::String::New(env, password));
            return obj;
        } else {
            return env.Null();
        }
    } CATCH_EXCEPTIONS
}

Napi::Boolean removeCredential(const Napi::CallbackInfo &info) {
    CHECK_ARGS(STRING);

    try {
        std::string target = info[0].As<Napi::String>();

        return Napi::Boolean::New(info.Env(), credentials::remove(target));
    } CATCH_EXCEPTIONS
}

Napi::String generateRandom(const Napi::CallbackInfo &info) {
    CHECK_ARGS(NUMBER);

    try {
        int numChars = info[0].As<Napi::Number>();

        std::random_device dev;
        std::mt19937 rng(dev());
        std::uniform_int_distribution<> dist(0, UCHAR_MAX);

        std::vector<char> buffer;
        buffer.reserve(numChars);
        for (int i = 0; i < numChars; i++) {
            buffer.push_back((char) dist(rng));
        }

        return Napi::String::New(info.Env(), binary_to_string(buffer));
    } CATCH_EXCEPTIONS
}

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
    exports.Set(EXPORT(passportAvailable));
    exports.Set(EXPORT(createPassportKey));
    exports.Set(EXPORT(passportSign));
    exports.Set(EXPORT(deletePassportAccount));
    exports.Set(EXPORT(getPublicKey));
    exports.Set(EXPORT(getPublicKeyHash));
    exports.Set(EXPORT(verifySignature));

    exports.Set(EXPORT(writeCredential));
    exports.Set(EXPORT(readCredential));
    exports.Set(EXPORT(removeCredential));

    exports.Set(EXPORT(generateRandom));

    return exports;
}

NODE_API_MODULE(passport, InitAll)