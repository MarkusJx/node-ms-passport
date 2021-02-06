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
* Convert a managed string to a char array.
* Must be freed using delete[].
* Source: https://stackoverflow.com/a/39249779
*
* @param s the strin to convert
* @return the unmanaged character array
*/
char* StringToChar(String^ s) {
	auto W = s->ToCharArray();
	int Size = W->Length;
	char* CString = new char[Size + 1];
	CString[Size] = 0;
	for (int y = 0; y < Size; y++) {
		CString[y] = (char)W[y];
	}
	return CString;
}

/**
* Convert a unmanaged character array to a managed string.
* Does not delete the character array.
* Source: https://stackoverflow.com/a/39249779
*
* @param char_array the char array to convert
* @return the System::String
*/
String^ CharToString(const char* char_array) {
	std::string s_str = std::string(char_array);
	std::wstring wid_str = std::wstring(s_str.begin(), s_str.end());
	const wchar_t* w_char = wid_str.c_str();
	return gcnew String(w_char);
}

/**
* Convert a managed byte array to a character array.
* Must be freed using delete[]
*
* @param data the array to convert
* @return the converted char array
*/
char* byteArrayToChar(array<unsigned char>^ data) {
	int size = data->Length;
	char* out = new char[size];
	for (int i = 0; i < size; i++) {
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
array<unsigned char>^ charToByteArray(const unsigned char* data, int len) {
	array<unsigned char>^ out = gcnew array<unsigned char>(len);
	for (int i = 0; i < len; i++) {
		out[i] = data[i];
	}

	return out;
}

/**
 * Convert a managed boolean to an unmanaged boolean
 *
 * @param val the value to convert
 * @return the converted boolean
 */
bool convertBoolean(bool^ val) {
	return val ? true : false;
}

/**
 * Convert a passportResult into a c++ 'readable' form
 *
 * @param obj the object to convert
 * @param outStatus the status value to write to
 * @param outSize the size of the output array
 * @return the buffer
 */
char* convertToPassportResult(Object^ obj, int& outStatus, int& outSize) {
	int^ status = static_cast<int^>(obj->GetType()->GetField("status")->GetValue(obj));

	outStatus = (int)status;
	if (outStatus == 0) {
		array<unsigned char>^ buffer =
			static_cast<array<unsigned char>^>(obj->GetType()->GetField("buffer")->GetValue(obj));
		outSize = buffer->Length;
		return byteArrayToChar(buffer);
	} else {
		return nullptr;
	}
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
T^ callPassportFunction(String^ name, array<Object^ >^ data) {
	String^ dll = CharToString(cSharpDllLocation) + "CSNodeMsPassport.dll";
	Assembly^ assembly = Assembly::LoadFrom(dll);
	MethodInfo^ m = assembly->GetType("CSNodeMsPassport.Passport")->GetMethod(name);
	return static_cast<T^>(m->Invoke(nullptr, data));
}

void passport::unmanaged::freeData(char* data) {
	delete[] data;
}

void passport::setCSharpDllLocation(const std::string& location) {
	memset(cSharpDllLocation, '\0', sizeof(cSharpDllLocation));
	strcpy_s(cSharpDllLocation, location.c_str());
}

bool passport::passportAvailable() {
	bool^ ret = callPassportFunction<bool>("PassportAvailable", nullptr);
	return convertBoolean(ret);
}

int passport::passportAccountExists(const std::string& accountId) {
	String^ acc = CharToString(accountId.c_str());
	return (int)callPassportFunction<int>("PassportAccountExists", gcnew array<Object^>(1) { acc });
}

char* passport::unmanaged::createPassportKey(int& status, int& outSize, const char* accountId) {
	Object^ ret = callPassportFunction<Object>("CreatePassportKey", gcnew array<Object^ >(1) {
		CharToString(accountId)
	});
	return convertToPassportResult(ret, status, outSize);
}

char* passport::unmanaged::passportSign(int& status, int& outSize, const char* accountId, const util::byte* challenge,
	int challengeSize) {
	Object^ ret = callPassportFunction<Object>("PassportSign", gcnew array<Object^ >(2) {
		CharToString(accountId),
			charToByteArray(challenge, challengeSize)
	});
	return convertToPassportResult(ret, status, outSize);
}

char* passport::unmanaged::getPublicKey(int& status, int& outSize, const char* accountId) {
	Object^ ret = callPassportFunction<Object>("GetPublicKey", gcnew array<Object^ >(1) {
		CharToString(accountId)
	});
	return convertToPassportResult(ret, status, outSize);
}

char* passport::unmanaged::getPublicKeyHash(int& status, int& outSize, const char* accountId) {
	Object^ ret = callPassportFunction<Object>("GetPublicKeyHash", gcnew array<Object^ >(1) {
		CharToString(accountId)
	});
	return convertToPassportResult(ret, status, outSize);
}

bool passport::unmanaged::verifyChallenge(const util::byte* challenge, int challengeSize, const util::byte* signature,
	int signatureSize, const util::byte* publicKey, int publicKeySize) {
	bool^ ret = callPassportFunction<bool>("VerifyChallenge", gcnew array<Object^>(3) {
		charToByteArray(challenge, challengeSize),
			charToByteArray(signature, signatureSize),
			charToByteArray(publicKey, publicKeySize)
	});
	return convertBoolean(ret);
}

int passport::unmanaged::deletePassportAccount(const char* accountId) {
	return (int)callPassportFunction<int>("DeletePassportAccount", gcnew array<Object^ >(1) {
		CharToString(accountId)
	});
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
	bool encrypt) noexcept {
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

void*
credentials::util::read(const std::wstring& target, wchar_t*& username, secure_wstring*& password, bool encrypt) {
	PCREDENTIALW pcred;

	bool ok = ::CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred);
	if (!ok) return nullptr;

	secure_wstring pass = copyToWChar((char*)pcred->CredentialBlob, pcred->CredentialBlobSize, ok);
	if (ok) {
		if (encrypt) {
			ok = unprotectCredential(pass);
		}

		if (ok) {
			username = pcred->UserName;
			password = new secure_wstring(pass.begin(), pass.end());
		}
	}

	if (!ok) {
		::CredFree(pcred);
		return nullptr;
	}

	return pcred;
}

void credentials::util::deleteWstring(secure_wstring* in) {
	delete in;
}

void credentials::util::freePcred(void* data) {
	::CredFree((PCREDENTIALW)data);
}

bool credentials::remove(const std::wstring& target) noexcept {
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

void passwords::util::deleteWstring(secure_wstring* in) {
	delete in;
}

bool passwords::util::encrypt(const secure_wstring& data, secure_wstring*& out) {
	secure_wstring copy = data;
	bool ok = protectCredential(copy);
	if (!ok) return false;

	out = new secure_wstring(copy.begin(), copy.end());
	return true;
}

bool passwords::util::decrypt(const secure_wstring& data, secure_wstring*& out) {
	secure_wstring copy = data;
	bool ok = unprotectCredential(copy);
	if (!ok) return false;

	out = new secure_wstring(copy.begin(), copy.end());
	return true;
}

bool passwords::util::isEncrypted(const secure_wstring& data, bool& ok) {
	CRED_PROTECTION_TYPE protectionType;
	secure_vector<wchar_t> pass_cpy(data.begin(), data.end());
	ok = CredIsProtectedW(pass_cpy.data(), &protectionType);
	if (ok) {
		if (protectionType == CredUnprotected) {
			return false;
		} else {
			return true;
		}
	} else {
		return false;
	}
}