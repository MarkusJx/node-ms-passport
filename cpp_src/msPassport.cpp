#include <napi.h>
#include <random>
#include <utility>
#include <iostream>
#include <napi_tools.hpp>

#include "node_classes/credential_store.hpp"
#include "node_classes/credential.hpp"
#include "util.hpp"

using namespace nodeMsPassport;

class exception : public std::exception {
public:
#ifdef __APPLE__
	explicit exception(const char* msg) : std::exception(), msg(msg) {}

	[[nodiscard]] const char* what() const noexcept override {
		return msg;
	}

private:
	const char* msg;
#else
	using std::exception::exception;
#endif
};

template<class T>
class node_secure_vector {
public:
	node_secure_vector() : data() {}

    explicit node_secure_vector(const Napi::Value &val) {
		auto buffer = val.As<Napi::Buffer<T>>();
		this->data = secure_vector<T>(buffer.Data(), buffer.Data() + buffer.Length());
    }

	explicit node_secure_vector(secure_vector<T> &&dt) : data(std::move(dt)) {}

	PASSPORT_UNUSED static Napi::Value toNapiValue(const Napi::Env &env, const node_secure_vector &c) {
		return Napi::Buffer<T>::Copy(env, c.data.data(), c.data.size());
	}

    secure_vector<T> data;
};

secure_vector<byte> string_to_binary(const std::string& source) {
	static unsigned int nibbles[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };
	secure_vector<byte> res;
	for (std::string::const_iterator it = source.begin(); it < source.end(); it += 2) {
		unsigned char v;
		if (isxdigit(*it))
			v = nibbles[toupper(*it) - '0'] << (unsigned)4;
		else {
			std::string err = "Invalid character: '";
			err += (char)*it;
			err.append("' is not a valid hex digit");
			throw std::exception(err.c_str());
		}
		if (it + 1 < source.end() && isxdigit(*(it + 1)))
			v += nibbles[toupper(*(it + 1)) - '0'];
		res.push_back(v);
	}
	return res;
}

std::string binary_to_string(const secure_vector<byte>& source) {
	static char syms[] = "0123456789ABCDEF";
	std::stringstream ss;
	for (auto it : source)
		ss << syms[(((unsigned)it >> (unsigned)4) & (unsigned)0xf)] << syms[(unsigned)it & (unsigned)0xf];

	return ss.str();
}

Napi::Boolean passportAvailable(const Napi::CallbackInfo& info) {
	TRY
		return Napi::Boolean::New(info.Env(), passport::passportAvailable());
	CATCH_EXCEPTIONS
}

Napi::Promise createPassportKey(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);
	std::string account = info[0].ToString();

	return napi_tools::promises::promise<void>(info.Env(), [account] {
		passport::createPassportKey(account);
	});
}

Napi::Promise passportSignHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string, napi_tools::string);

	std::string account = info[0].ToString();
	secure_vector<byte> challenge = string_to_binary(info[1].ToString().Utf8Value());
	return napi_tools::promises::promise<std::string>(info.Env(), [account, challenge] {
		secure_vector<byte> res = passport::passportSign(account, challenge);

		return binary_to_string(res);
	});
}

Napi::Promise passportSign(const Napi::CallbackInfo& info) {
    CHECK_ARGS(napi_tools::string, napi_tools::buffer);

    std::string account = info[0].ToString();

    node_secure_vector<byte> challenge(info[1]);
    return napi_tools::promises::promise<node_secure_vector<byte>>(info.Env(), [account, challenge] {
        secure_vector<byte> res = passport::passportSign(account, challenge.data);

        return node_secure_vector<byte>(std::move(res));
    });
}

Napi::Promise deletePassportAccount(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
	return napi_tools::promises::promise<void>(info.Env(), [account] {
		try {
			passport::deletePassportAccount(account);
		} catch (const std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
	});
}

std::string get_pk_encoding(const Napi::CallbackInfo &info) {
    std::string encoding;
    if (info.Length() >= 2 && !info[1].IsNull()) {
        if (info[1].IsString()) {
            encoding = info[1].ToString();
            if (encoding.empty()) {
                throw Napi::TypeError::New(info.Env(), "If supplied, the second argument must not be empty");
            }
        } else {
            throw Napi::TypeError::New(info.Env(), "If supplied, the second argument must be of type string");
        }
    }

    return encoding;
}

secure_vector<byte> get_pk(const std::string &account, const std::string &encoding) {
    secure_vector<byte> res;
    if (encoding.empty()) {
        res = passport::getPublicKey(account);
    } else {
        res = passport::getPublicKey(account, encoding);
    }

    return res;
}

Napi::Promise getPublicKey(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
    std::string encoding = get_pk_encoding(info);

	return napi_tools::promises::promise<node_secure_vector<byte>>(info.Env(), [account, encoding] {
		return node_secure_vector<byte>(get_pk(account, encoding));
	});
}

Napi::Promise getPublicKeyHex(const Napi::CallbackInfo& info) {
    CHECK_ARGS(napi_tools::string);

    std::string account = info[0].ToString();
    std::string encoding = get_pk_encoding(info);
    return napi_tools::promises::promise<std::string>(info.Env(), [account, encoding] {
        return binary_to_string(get_pk(account, encoding));
    });
}

Napi::Promise getPublicKeyHashHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
	return napi_tools::promises::promise<std::string>(info.Env(), [account] {
		return binary_to_string(passport::getPublicKeyHash(account));
	});
}

Napi::Promise getPublicKeyHash(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
	return napi_tools::promises::promise<node_secure_vector<byte>>(info.Env(), [account] {
		secure_vector<byte> res = passport::getPublicKeyHash(account);
		return node_secure_vector<byte>(std::move(res));
	});
}

Napi::Promise requestVerification(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::string);
    std::string message = info[0].ToString();

    return napi_tools::promises::promise<int>(info.Env(), [message] {
        return passport::requestVerification(message);
    });
}

Napi::Promise verifySignatureHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string, napi_tools::string, napi_tools::string);

	secure_vector<byte> challenge = string_to_binary(info[0].ToString().Utf8Value());
	secure_vector<byte> signature = string_to_binary(info[1].ToString().Utf8Value());
	secure_vector<byte> publicKey = string_to_binary(info[2].ToString().Utf8Value());

	return napi_tools::promises::promise<bool>(info.Env(), [challenge, signature, publicKey] {
		return passport::verifySignature(challenge, signature, publicKey);
	});
}

Napi::Promise verifySignature(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::buffer, napi_tools::buffer, napi_tools::buffer);

	node_secure_vector<byte> challenge(info[0]);
	node_secure_vector<byte> signature(info[1]);
	node_secure_vector<byte> publicKey(info[2]);

	return napi_tools::promises::promise<bool>(info.Env(), [challenge, signature, publicKey] {
		return passport::verifySignature(challenge.data, signature.data, publicKey.data);
	});
}

Napi::Boolean passportAccountExists(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	TRY
		std::string account = info[0].ToString();
	return Napi::Boolean::New(info.Env(), passport::passportAccountExists(account));
	CATCH_EXCEPTIONS
}

Napi::Promise encryptPasswordHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::u16string data_u16 = info[0].ToString();
	secure_wstring data(data_u16.begin(), data_u16.end());

	return napi_tools::promises::promise<std::string>(info.Env(), [data] {
		secure_wstring data_cpy(data);
		passwords::encrypt(data_cpy);

		return binary_to_string(data_cpy.getBytes());
	});
}

Napi::Promise encryptPassword(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::u16string data_u16 = info[0].ToString();
	secure_wstring data(data_u16.begin(), data_u16.end());

	return napi_tools::promises::promise<node_secure_vector<byte>>(info.Env(), [data] {
		secure_wstring data_cpy(data);
		passwords::encrypt(data_cpy);

		return node_secure_vector<byte>(std::move(data_cpy.getBytes()));
	});
}

Napi::Promise decryptPasswordHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string data_str = info[0].ToString();

	return napi_tools::promises::promise<std::u16string>(info.Env(), [data_str] {
		secure_wstring data_cpy(string_to_binary(data_str));
		passwords::decrypt(data_cpy);

		return std::u16string(data_cpy.begin(), data_cpy.end());
	});
}

Napi::Promise decryptPassword(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::buffer);

	node_secure_vector<byte> data_vec(info[0]);

	return napi_tools::promises::promise<std::u16string>(info.Env(), [data_vec] {
		secure_wstring data_cpy(secure_wstring(data_vec.data));
		passwords::decrypt(data_cpy);

		return std::u16string(data_cpy.begin(), data_cpy.end());
	});
}

Napi::Boolean passwordEncryptedHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	TRY
		Napi::Env env = info.Env();
		std::string password = info[0].As<Napi::String>();

		secure_vector<unsigned char> data_vec = string_to_binary(password);
		secure_wstring data(data_vec);

		bool res = passwords::isEncrypted(data);

		return Napi::Boolean::New(env, res);
	CATCH_EXCEPTIONS
}

Napi::Boolean passwordEncrypted(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::buffer);

	TRY
		Napi::Env env = info.Env();
		node_secure_vector<byte> password(info[0]);
		secure_wstring data(password.data);

		bool res = passwords::isEncrypted(data);

		return Napi::Boolean::New(env, res);
	CATCH_EXCEPTIONS
}

void setCSharpDllLocation(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	TRY
		passport::setCSharpDllLocation(info[0].ToString().Utf8Value());
	CATCH_EXCEPTIONS
}

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
	EXPORT_FUNCTION(exports, env, passportAvailable);
	EXPORT_FUNCTION(exports, env, createPassportKey);
	EXPORT_FUNCTION(exports, env, passportSignHex);
	EXPORT_FUNCTION(exports, env, passportSign);
	EXPORT_FUNCTION(exports, env, getPublicKeyHex);
	EXPORT_FUNCTION(exports, env, getPublicKey);
    EXPORT_FUNCTION(exports, env, getPublicKeyHash);
    EXPORT_FUNCTION(exports, env, getPublicKeyHashHex);
	EXPORT_FUNCTION(exports, env, deletePassportAccount);
    EXPORT_FUNCTION(exports, env, requestVerification);
	EXPORT_FUNCTION(exports, env, verifySignatureHex);
	EXPORT_FUNCTION(exports, env, verifySignature);
	EXPORT_FUNCTION(exports, env, passportAccountExists);

	EXPORT_FUNCTION(exports, env, encryptPasswordHex);
	EXPORT_FUNCTION(exports, env, encryptPassword);
	EXPORT_FUNCTION(exports, env, decryptPasswordHex);
	EXPORT_FUNCTION(exports, env, decryptPassword);
	EXPORT_FUNCTION(exports, env, passwordEncryptedHex);
	EXPORT_FUNCTION(exports, env, passwordEncrypted);

	EXPORT_FUNCTION(exports, env, setCSharpDllLocation);

	node_classes::credential_store::init(env, exports);
    node_classes::credential::init(env, exports);

	return exports;
}

NODE_API_MODULE(passport, InitAll)