#include <string>
#include <iostream>
#include <windows.h>
#include <wincred.h>
#include <tchar.h>
#include <comutil.h>

#pragma hdrstop
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "comsuppw.lib")

#include "NodeMsPassport.hpp"

using namespace System;
using namespace System::Reflection;
using namespace nodeMsPassport;

char cSharpDllLocation[MAX_PATH + 1];

/**
 * Convert a std::wstring to a std::string
 *
 * @param in the string to convert
 * @return the converted string
 */
std::string wstring_to_string(const std::wstring& in) {
	std::string out(in.size() + 1, '\0');
	size_t outSize;

	errno_t err = wcstombs_s(&outSize, (char*)out.data(), out.size(), in.c_str(), in.size());
	if (err) {
		perror("Error creating string");
		return std::string();
	}

	out.resize(outSize);
	return out;
}

/**
 * Convert a managed System::String to a std::string
 *
 * @param s the string to convert
 * @return the converted C++ std::string
 */
std::string string_to_std_string(String^ s) {
	array<wchar_t>^ arr = s->ToCharArray();
	int size = arr->Length;
	std::wstring out(size, '\0');
	for (int i = 0; i < size; i++) {
		out[i] = arr[i];
	}

	return wstring_to_string(out);
}

/**
 * Convert a unmanaged character array to a managed string.
 * Does not delete the character array.
 * Source: https://stackoverflow.com/a/39249779
 *
 * @param char_array the char array to convert
 * @return the System::String
 */
String^ std_string_to_string(const std::string& in) {
	std::wstring w_str = std::wstring(in.begin(), in.end());
	return gcnew String(w_str.c_str());
}

/**
* Convert a managed byte array to a character array.
*
* @param data the array to convert
* @return the converted char array
*/
secure_vector<byte> byteArrayToVector(array<byte>^ data) {
	secure_vector<byte> out(data->Length, 0);
	for (int i = 0; i < data->Length; i++) {
		out[i] = data[i];
	}

	return out;
}

/**
* Convert a char array to a managed byte array.
* Does not delete the input array
*
* @param data the array to convert
* @param len the length of the input array
* @return the managed byte array
*/
array<unsigned char>^ byteVectorToArray(const secure_vector<byte>& in) {
	array<unsigned char>^ out = gcnew array<unsigned char>(in.size());
	for (int i = 0; i < in.size(); i++) {
		out[i] = in[i];
	}

	return out;
}

/**
 * Convert a managed boolean to an unmanaged boolean
 *
 * @param val the value to convert
 * @return the converted boolean
 */
bool convertBoolean(Boolean val) {
	return val ? true : false;
}

/**
 * Call a passport function
 *
 * @tparam T the output type
 * @param name the name of the function to call
 * @param data the data to pass on to the function
 * @return the function return value
 */
template<class T>
T callPassportFunction(String^ name, array<Object^ >^ data) {
	String^ dll = std_string_to_string(cSharpDllLocation) + "CSNodeMsPassport.dll";
	Assembly^ assembly = Assembly::LoadFrom(dll);
	MethodInfo^ m = assembly->GetType("CSNodeMsPassport.Passport")->GetMethod(name);

	return static_cast<T>(m->Invoke(nullptr, data));
}

/**
 * Call a passport void function
 *
 * @param name the name of the function to call
 * @param data the data to pass on to the function
 */
void callVoidPassportFunction(String^ name, array<Object^>^ data) {
	String^ dll = std_string_to_string(cSharpDllLocation) + "CSNodeMsPassport.dll";
	Assembly^ assembly = Assembly::LoadFrom(dll);
	MethodInfo^ m = assembly->GetType("CSNodeMsPassport.Passport")->GetMethod(name);

	m->Invoke(nullptr, data);
}

/**
 * Zero out a managed byte array
 *
 * @param arr the array to zero out
 */
void clearArray(array<byte>^ arr) {
	for (int i = 0; i < arr->Length; i++) {
		arr[i] = 0;
	}
}

passport::passportException::passportException(std::string err, int code) : error(std::move(err)) {
	error.append("#").append(std::to_string(code));
}

const char* passport::passportException::what() const noexcept {
	return error.c_str();
}

/**
 * Convert a managed Exception to a passportException.
 * If the Exception is typeof TargetInvocationException,
 * the exception will be the inner exception of the exception.
 *
 * @param e the exception to convert
 * @return the converted Exception as a passportException
 */
passport::passportException convertException(Exception^ e) {
	// If the exception is typeof TargetInvocationException,
	// the actual exception is the inner exception of e
	if (e->GetType() == TargetInvocationException::typeid) {
		e = e->InnerException;
	}

	// Get the error code. If the code is not any of the
	// custom codes, set the error code to -1 == any
	int code = e->HResult;
	if (code < 1 || code > 8) {
		code = -1;
	}

	// Return a passportException
	return passport::passportException(string_to_std_string(e->Message), code);
}

void passport::setCSharpDllLocation(const std::string& location) {
	memset(cSharpDllLocation, '\0', sizeof(cSharpDllLocation));
	strcpy_s(cSharpDllLocation, location.c_str());
}

bool passport::passportAvailable() {
	try {
		Boolean ret = callPassportFunction<Boolean>("PassportAvailable", nullptr);
		return convertBoolean(ret);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

bool passport::passportAccountExists(const std::string& accountId) {
	try {
		Boolean ret = callPassportFunction<Boolean>("PassportAccountExists", gcnew array<Object^>(1) {
			std_string_to_string(accountId)
		});
		return convertBoolean(ret);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

void passport::createPassportKey(const std::string& accountId) {
	try {
		callVoidPassportFunction("CreatePassportKey", gcnew array<Object^ >(1) {
			std_string_to_string(accountId)
		});
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<byte> passport::passportSign(const std::string& accountId, const secure_vector<byte>& challenge) {
	try {
		array<byte>^ ret = callPassportFunction<array<byte>^>("PassportSign", gcnew array<Object^ >(2) {
			std_string_to_string(accountId), byteVectorToArray(challenge)
		});

		secure_vector<byte> out = byteArrayToVector(ret);
		clearArray(ret);
		return out;
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<byte> passport::getPublicKey(const std::string& accountId) {
	try {
		array<byte>^ ret = callPassportFunction<array<byte>^>("GetPublicKey", gcnew array<Object^ >(1) {
			std_string_to_string(accountId)
		});

		secure_vector<byte> out = byteArrayToVector(ret);
		clearArray(ret);
		return out;
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<byte> passport::getPublicKeyHash(const std::string& accountId) {
	try {
		array<byte>^ ret = callPassportFunction<array<byte>^>("GetPublicKeyHash", gcnew array<Object^ >(1) {
			std_string_to_string(accountId)
		});

		secure_vector<byte> out = byteArrayToVector(ret);
		clearArray(ret);
		return out;
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

bool passport::verifySignature(const secure_vector<byte>& challenge, const secure_vector<byte>& signature,
	const secure_vector<byte>& publicKey) {
	try {
		Boolean ret = callPassportFunction<Boolean>("VerifyChallenge", gcnew array<Object^>(3) {
			byteVectorToArray(challenge),
				byteVectorToArray(signature),
				byteVectorToArray(publicKey)
		});
		return convertBoolean(ret);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

void passport::deletePassportAccount(const std::string& accountId) {
	try {
		callVoidPassportFunction("DeletePassportAccount", gcnew array<Object^ >(1) {
			std_string_to_string(accountId)
		});
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<unsigned char> copyToChar(const secure_wstring& data, bool& ok) {
	secure_vector<unsigned char> tmp;
	tmp.resize(data.size() * sizeof(wchar_t));

	ok = memcpy_s(tmp.data(), tmp.size(), data.c_str(), data.size() * sizeof(wchar_t)) == 0;

	return tmp;
}

secure_wstring copyToWChar(char* ptr, int sizeInBytes, bool& ok) {
	secure_wstring out;
	out.resize(sizeInBytes / sizeof(wchar_t));

	ok = memcpy_s((wchar_t*)out.data(), out.size() * sizeof(wchar_t), ptr, sizeInBytes) == 0;
	return out;
}

// Source: https://github.com/microsoft/Windows-classic-samples/blob/master/Samples/CredentialProvider/cpp/helpers.cpp#L456
bool unprotectCredential(secure_wstring& toUnprotect) {
	CRED_PROTECTION_TYPE protectionType;
	secure_vector<wchar_t> toUnprotect_cpy(toUnprotect.begin(), toUnprotect.end());
	if (CredIsProtectedW(toUnprotect_cpy.data(), &protectionType)) {
		if (protectionType != CredUnprotected) {
			toUnprotect_cpy = secure_vector<wchar_t>(toUnprotect.begin(), toUnprotect.end());
			DWORD unprotectedSize = 0;
			if (!CredUnprotectW(false, toUnprotect_cpy.data(), (DWORD)toUnprotect_cpy.size(), nullptr,
				&unprotectedSize)) {
				DWORD dwErr = GetLastError();
				if (dwErr == ERROR_INSUFFICIENT_BUFFER && unprotectedSize > 0) {
					secure_vector<wchar_t> outData;
					outData.resize(unprotectedSize);

					if (CredUnprotectW(false, toUnprotect_cpy.data(), (DWORD)toUnprotect_cpy.size(), outData.data(),
						&unprotectedSize)) {
						toUnprotect = secure_wstring(outData.begin(), outData.end());
						return true;
					}
				}
			}
		}
	}

	return false;
}

bool protectCredential(secure_wstring& toProtect) {
	CRED_PROTECTION_TYPE protectionType;
	secure_vector<wchar_t> toProtect_cpy(toProtect.begin(), toProtect.end());
	if (CredIsProtectedW(toProtect_cpy.data(), &protectionType)) {
		if (protectionType == CredUnprotected) {
			toProtect_cpy = secure_vector<wchar_t>(toProtect.begin(), toProtect.end());
			DWORD protectedSize = 0;
			if (!CredProtectW(false, toProtect_cpy.data(), (DWORD)toProtect_cpy.size(), nullptr, &protectedSize,
				nullptr)) {
				DWORD dwErr = GetLastError();

				if (dwErr == ERROR_INSUFFICIENT_BUFFER && protectedSize > 0) {
					secure_vector<wchar_t> outData;
					outData.resize(protectedSize);

					if (CredProtectW(false, toProtect_cpy.data(), (DWORD)toProtect_cpy.size(), outData.data(),
						&protectedSize, nullptr)) {
						toProtect = secure_wstring(outData.begin(), outData.end());
						return true;
					}
				}
			}
		}
	}

	return false;
}

bool
credentials::write(const std::wstring& target, const std::wstring& user, const secure_wstring& password,
	bool encrypt) {
	bool ok;
	secure_wstring pass = password;
	if (encrypt) {
		if (!protectCredential(pass)) return false;
	}

	secure_vector<unsigned char> passData = copyToChar(pass, ok);
	if (!ok) return false;

	DWORD cbCreds = (DWORD)passData.size();

	CREDENTIALW cred = { 0 };
	cred.Type = CRED_TYPE_GENERIC;

	// Copy target as a non-const qualified wchar array is required
	std::wstring target_cpy = target;
	cred.TargetName = (wchar_t*)target_cpy.data();

	cred.CredentialBlobSize = cbCreds;
	cred.CredentialBlob = passData.data();
	cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

	// Copy user as a non-const qualified wchar array is required
	std::wstring user_cpy = user;
	cred.UserName = (wchar_t*)user_cpy.data();

	return ::CredWriteW(&cred, 0);
}

bool credentials::read(const std::wstring& target, std::wstring& username, secure_wstring& password, bool encrypt) {
	PCREDENTIALW pcred;

	bool ok = ::CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred);
	if (!ok) return false;

	secure_wstring pass = copyToWChar((char*)pcred->CredentialBlob, pcred->CredentialBlobSize, ok);
	if (ok) {
		if (encrypt) {
			ok = unprotectCredential(pass);
		}

		if (ok) {
			username = std::wstring(pcred->UserName);
			password = secure_wstring(pass.begin(), pass.end());
		}
	}

	::CredFree(pcred);
	return ok;
}

bool credentials::remove(const std::wstring& target) {
	return ::CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
}

bool credentials::isEncrypted(const std::wstring& target) {
	PCREDENTIALW pcred;
	bool ok;

	ok = ::CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred);
	if (!ok) throw encryptionException("Could not check if data is encrypted");

	secure_wstring pass = copyToWChar((char*)pcred->CredentialBlob, pcred->CredentialBlobSize, ok);
	::CredFree(pcred);
	if (!ok) throw encryptionException("Could not check if data is encrypted");

	CRED_PROTECTION_TYPE protectionType;
	secure_vector<wchar_t> pass_cpy(pass.begin(), pass.end());
	ok = CredIsProtectedW(pass_cpy.data(), &protectionType);
	if (ok) {
		if (protectionType == CredUnprotected) {
			return false;
		} else {
			return true;
		}
	} else {
		throw encryptionException("Could not check if data is encrypted");
	}
}

bool passwords::encrypt(secure_wstring& data) {
	secure_wstring copy = data;
	bool ok = protectCredential(copy);
	if (!ok) {
		return false;
	} else {
		data = copy;
		return true;
	}
}

bool passwords::decrypt(secure_wstring& data) {
	secure_wstring copy = data;
	bool ok = unprotectCredential(copy);
	if (!ok) {
		return false;
	} else {
		data = copy;
		return true;
	}
}

bool passwords::isEncrypted(const secure_wstring& data) {
	CRED_PROTECTION_TYPE protectionType;
	secure_vector<wchar_t> pass_cpy(data.begin(), data.end());
	bool ok = CredIsProtectedW(pass_cpy.data(), &protectionType);
	if (ok) {
		if (protectionType == CredUnprotected) {
			return false;
		} else {
			return true;
		}
	} else {
		throw std::runtime_error("Could not check if the password is encrypted");
	}
}