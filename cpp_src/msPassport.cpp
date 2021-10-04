#include <napi.h>
#include <sstream>
#include <random>
#include <utility>
#include <iostream>
#include <napi_tools.hpp>

#include "NodeMsPassport.hpp"

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

	static Napi::Value toNapiValue(const Napi::Env &env, const node_secure_vector &c) {
		return Napi::Buffer<T>::Copy(env, c.data.data(), c.data.size());
	}

    secure_vector<T> data;
};

secure_vector<byte> string_to_binary(const std::string& source) {
	static unsigned int nibbles[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };
	secure_vector<byte> retval;
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
		retval.push_back(v);
	}
	return retval;
}

std::string binary_to_string(const secure_vector<byte>& source) {
	static char syms[] = "0123456789ABCDEF";
	std::stringstream ss;
	for (std::_Vector_const_iterator<std::_Vector_val<std::_Simple_types<char> > >::value_type it : source)
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

Napi::Promise getPublicKeyHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
	return napi_tools::promises::promise<std::string>(info.Env(), [account] {
		secure_vector<byte> res = passport::getPublicKey(account);
		return binary_to_string(res);
	});
}

Napi::Promise getPublicKey(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
	return napi_tools::promises::promise<node_secure_vector<byte>>(info.Env(), [account] {
		secure_vector<byte> res = passport::getPublicKey(account);
		return node_secure_vector<byte>(std::move(res));
	});
}

Napi::Promise getPublicKeyHashHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::string account = info[0].ToString();
	return napi_tools::promises::promise<std::string>(info.Env(), [account] {
		secure_vector<byte> res = passport::getPublicKeyHash(account);
		return binary_to_string(res);
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

Napi::Promise writeCredential(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string, napi_tools::string, napi_tools::string, napi_tools::boolean);

	std::u16string target_u16 = info[0].ToString();
	std::u16string user_u16 = info[1].ToString();
	std::u16string password_u16 = info[2].ToString();

	std::wstring target(target_u16.begin(), target_u16.end());
	std::wstring user(user_u16.begin(), user_u16.end());
	secure_wstring password(password_u16.begin(), password_u16.end());
	bool encrypt = info[3].ToBoolean();

	return napi_tools::promises::promise<bool>(info.Env(), [target, user, password, encrypt] {
		return credentials::write(target, user, password, encrypt);
	});
}

class credentialReadResult {
public:
	std::wstring user;
	secure_wstring password;
	bool ok;

	static Napi::Value toNapiValue(const Napi::Env& env, const credentialReadResult& res) {
		if (res.ok) {
			Napi::Object obj = Napi::Object::New(env);

			std::u16string username(res.user.begin(), res.user.end());
			std::u16string password(res.password.begin(), res.password.end());

			obj.Set("username", Napi::String::New(env, username));
			obj.Set("password", Napi::String::New(env, password));

			return obj;
		} else {
			return env.Null();
		}
	}
};

Napi::Promise readCredential(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string, napi_tools::boolean);

	Napi::Env env = info.Env();
	std::u16string target_utf16 = info[0].As<Napi::String>().Utf16Value();
	std::wstring target(target_utf16.begin(), target_utf16.end());
	bool encrypted = info[1].ToBoolean();

	return napi_tools::promises::promise<credentialReadResult>(info.Env(), [target, encrypted] {
		credentialReadResult res;
		res.ok = credentials::read(target, res.user, res.password, encrypted);

		return res;
	});
}

Napi::Promise removeCredential(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::u16string target_u16 = info[0].ToString();
	std::wstring target(target_u16.begin(), target_u16.end());

	return napi_tools::promises::promise<bool>(info.Env(), [target] {
		return credentials::remove(target);
	});
}

Napi::Promise credentialEncrypted(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::u16string target_u16 = info[0].ToString();
	std::wstring target(target_u16.begin(), target_u16.end());

	return napi_tools::promises::promise<bool>(info.Env(), [target] {
		return credentials::isEncrypted(target);
	});
}

Napi::Promise encryptPasswordHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::u16string data_u16 = info[0].ToString();
	secure_wstring data(data_u16.begin(), data_u16.end());

	return napi_tools::promises::promise<std::string>(info.Env(), [data] {
		secure_wstring data_cpy(data);
		bool ok = passwords::encrypt(data_cpy);
		if (!ok) throw exception("Could not encrypt the data");
		else return binary_to_string(data_cpy.getBytes());
	});
}

Napi::Promise encryptPassword(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	std::u16string data_u16 = info[0].ToString();
	secure_wstring data(data_u16.begin(), data_u16.end());

	return napi_tools::promises::promise<node_secure_vector<byte>>(info.Env(), [data] {
		secure_wstring data_cpy(data);
		bool ok = passwords::encrypt(data_cpy);
		if (!ok) throw exception("Could not encrypt the data");
		else return node_secure_vector<byte>(std::move(data_cpy.getBytes()));
	});
}

Napi::Promise decryptPasswordHex(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::string);

	Napi::Env env = info.Env();
	std::string data_str = info[0].ToString();

	return napi_tools::promises::promise<std::u16string>(info.Env(), [data_str] {
		secure_wstring data_cpy(string_to_binary(data_str));
		bool ok = passwords::decrypt(data_cpy);

		if (!ok) throw exception("Could not decrypt the data");
		else return std::u16string(data_cpy.begin(), data_cpy.end());
	});
}

Napi::Promise decryptPassword(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::buffer);

	Napi::Env env = info.Env();
	node_secure_vector<byte> data_vec(info[0]);

	return napi_tools::promises::promise<std::u16string>(info.Env(), [data_vec] {
		secure_wstring data_cpy(secure_wstring(data_vec.data));
		bool ok = passwords::decrypt(data_cpy);

		if (!ok) throw exception("Could not decrypt the data");
		else return std::u16string(data_cpy.begin(), data_cpy.end());
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

Napi::Boolean passwordVaultAccountExists(const Napi::CallbackInfo& info) {
    CHECK_ARGS(napi_tools::string, napi_tools::string);

	TRY
        std::u16string resource = info[0].ToString().Utf16Value();
		std::u16string username = info[1].ToString().Utf16Value();
		bool res = password_vault::accountExists(
			std::wstring(resource.begin(), resource.end()),
			std::wstring(username.begin(), username.end())
		);

		return Napi::Boolean::New(info.Env(), res);
	CATCH_EXCEPTIONS
}

void passwordVaultStore(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::string, napi_tools::string, napi_tools::string);

	TRY
		std::u16string resource = info[0].ToString().Utf16Value();
		std::u16string username = info[1].ToString().Utf16Value();
		std::u16string password = info[2].ToString().Utf16Value();

		password_vault::login_data login(
			std::wstring(username.begin(), username.end()),
			secure_wstring(password.begin(), password.end())
		);

		password_vault::store(std::wstring(resource.begin(), resource.end()), login);
	CATCH_EXCEPTIONS
}

Napi::Object loginToNapiObject(const Napi::Env& env, const password_vault::login_data& login) {
    Napi::Object res = Napi::Object::New(env);
    res.Set("username", Napi::String::New(env, (char16_t *) login.username.c_str()));
    res.Set("password", Napi::String::New(env, (char16_t *) login.password.c_str()));

    return res;
}

Napi::Object passwordVaultRetrieve(const Napi::CallbackInfo& info) {
    CHECK_ARGS(napi_tools::string, napi_tools::string);

	TRY
		std::u16string resource = info[0].ToString().Utf16Value();
		std::u16string username = info[1].ToString().Utf16Value();

		password_vault::login_data login = password_vault::retrieve(
			std::wstring(resource.begin(), resource.end()),
			std::wstring(username.begin(), username.end())
		);

        return loginToNapiObject(info.Env(), login);
	CATCH_EXCEPTIONS
}

void passwordVaultRemove(const Napi::CallbackInfo& info) {
    CHECK_ARGS(napi_tools::string, napi_tools::string);

	TRY
		std::u16string resource = info[0].ToString().Utf16Value();
		std::u16string username = info[1].ToString().Utf16Value();

		password_vault::remove(
			std::wstring(resource.begin(), resource.end()),
			std::wstring(username.begin(), username.end())
		);
	CATCH_EXCEPTIONS
}

Napi::Array passwordVaultRetrieveByResource(const Napi::CallbackInfo& info) {
    CHECK_ARGS(napi_tools::string);

	TRY
        std::u16string resource = info[0].ToString().Utf16Value();

		std::vector<password_vault::login_data> res =
			password_vault::retrieveByResource(std::wstring(resource.begin(), resource.end()));

		Napi::Env env = info.Env();
        Napi::Array arr = Napi::Array::New(env, res.size());
		for (size_t i = 0; i < res.size(); ++i) {
            arr.Set(static_cast<uint32_t>(i), loginToNapiObject(env, res.at(i)));
		}

		return arr;
	CATCH_EXCEPTIONS
}

Napi::Array passwordVaultRetrieveByUsername(const Napi::CallbackInfo &info) {
    CHECK_ARGS(napi_tools::string);

    TRY
		std::u16string username = info[0].ToString().Utf16Value();

		std::vector<password_vault::login_data> res =
            password_vault::retrieveByUsername(std::wstring(username.begin(), username.end()));

		Napi::Env env = info.Env();
		Napi::Array arr = Napi::Array::New(env, res.size());
		for (size_t i = 0; i < res.size(); ++i) {
			arr.Set(static_cast<uint32_t>(i), loginToNapiObject(env, res.at(i)));
		}

		return arr;
    CATCH_EXCEPTIONS
}

Napi::Array passwordVaultRetrieveAll(const Napi::CallbackInfo &info) {
    TRY
		std::vector<password_vault::login_data> res = password_vault::retrieveAll();

		Napi::Env env = info.Env();
		Napi::Array arr = Napi::Array::New(env, res.size());
		for (size_t i = 0; i < res.size(); ++i) {
			arr.Set(static_cast<uint32_t>(i), loginToNapiObject(env, res.at(i)));
		}

		return arr;
    CATCH_EXCEPTIONS
}

Napi::String generateRandom(const Napi::CallbackInfo& info) {
	CHECK_ARGS(napi_tools::number);

	TRY
		int numChars = info[0].As<Napi::Number>();

		std::random_device dev;
		std::mt19937 rng(dev());
		std::uniform_int_distribution<> dist(0, UCHAR_MAX);

		secure_vector<byte> buffer;
		buffer.reserve(numChars);
		for (int i = 0; i < numChars; i++) {
			buffer.push_back((unsigned char)dist(rng));
		}

		return Napi::String::New(info.Env(), binary_to_string(buffer));
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
	EXPORT_FUNCTION(exports, env, deletePassportAccount);
	EXPORT_FUNCTION(exports, env, verifySignatureHex);
	EXPORT_FUNCTION(exports, env, verifySignature);
	EXPORT_FUNCTION(exports, env, passportAccountExists);

	EXPORT_FUNCTION(exports, env, writeCredential);
	EXPORT_FUNCTION(exports, env, readCredential);
	EXPORT_FUNCTION(exports, env, removeCredential);
	EXPORT_FUNCTION(exports, env, credentialEncrypted);

	EXPORT_FUNCTION(exports, env, encryptPasswordHex);
	EXPORT_FUNCTION(exports, env, encryptPassword);
	EXPORT_FUNCTION(exports, env, decryptPasswordHex);
	EXPORT_FUNCTION(exports, env, decryptPassword);
	EXPORT_FUNCTION(exports, env, passwordEncryptedHex);
	EXPORT_FUNCTION(exports, env, passwordEncrypted);

	EXPORT_FUNCTION(exports, env, passwordVaultAccountExists);
    EXPORT_FUNCTION(exports, env, passwordVaultStore);
    EXPORT_FUNCTION(exports, env, passwordVaultRetrieve);
    EXPORT_FUNCTION(exports, env, passwordVaultRemove);
    EXPORT_FUNCTION(exports, env, passwordVaultRetrieveByResource);
    EXPORT_FUNCTION(exports, env, passwordVaultRetrieveByUsername);
    EXPORT_FUNCTION(exports, env, passwordVaultRetrieveAll);

	EXPORT_FUNCTION(exports, env, generateRandom);
	EXPORT_FUNCTION(exports, env, setCSharpDllLocation);

	return exports;
}

NODE_API_MODULE(passport, InitAll)