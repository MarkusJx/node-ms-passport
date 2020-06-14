#include "pch.h"
#include <string>
#include <iostream>
#include <windows.h>
#include <wincred.h>
#include <tchar.h>
#include <comutil.h>

#pragma hdrstop
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "comsuppw.lib")

#define NODEMSPASSPORT_EXPORTS
#include "NodeMsPassport.hpp"

using namespace System;
using namespace System::Reflection;
using namespace nodeMsPassport;

// Source: https://stackoverflow.com/a/39249779
char* StringToChar(String^ s) {
	auto W = s->ToCharArray();
	int Size = W->Length;
	char* CString = new char[Size + 1];
	CString[Size] = 0;
	for (int y = 0; y < Size; y++)
	{
		CString[y] = (char)W[y];
	}
	return CString;
}

// Source: https://stackoverflow.com/a/39249779
String^ CharToString(const char* char_array) {
	std::string s_str = std::string(char_array);
	std::wstring wid_str = std::wstring(s_str.begin(), s_str.end());
	const wchar_t* w_char = wid_str.c_str();
	return gcnew String(w_char);
}

char* byteArrayToChar(array<unsigned char>^ data) {
	int size = data->Length;
	char* out = new char[size];
	for (int i = 0; i < size; i++) {
		out[i] = data[i];
	}

	return out;
}

array<unsigned char>^ charToByteArray(const unsigned char* data, int len) {
	array<unsigned char>^ out = gcnew array<unsigned char>(len);
	for (int i = 0; i < len; i++) {
		out[i] = data[i];
	}

	return out;
}

NODEMSPASSPORT_EXPORT void passport::unmanaged::freeData(char* data) {
	delete[] data;
}

NODEMSPASSPORT_EXPORT bool passport::passportAvailable() {
	return CSNodeMsPassport::Passport::PassportAvailable();
}

NODEMSPASSPORT_EXPORT char* passport::unmanaged::createPassportKey(int& status, int& outSize, const char* accountId) {
	CSNodeMsPassport::Passport::PassportResult res = CSNodeMsPassport::Passport::CreatePassportKey(CharToString(accountId));
	status = res.status;

	if (res.status == 0) {
		outSize = res.buffer->Length;
		return byteArrayToChar(res.buffer);
	}
	else {
		return nullptr;
	}
}

NODEMSPASSPORT_EXPORT char* passport::unmanaged::passportSign(int& status, int& outSize, const char* accountId, const util::byte* challenge, int challengeSize) {
	CSNodeMsPassport::Passport::PassportResult res = CSNodeMsPassport::Passport::PassportSign(CharToString(accountId), charToByteArray(challenge, challengeSize));
	status = res.status;

	if (res.status == 0) {
		outSize = res.buffer->Length;
		return byteArrayToChar(res.buffer);
	}
	else {
		return nullptr;
	}
}

NODEMSPASSPORT_EXPORT char* passport::unmanaged::getPublicKey(int& status, int& outSize, const char* accountId) {
	CSNodeMsPassport::Passport::PassportResult res = CSNodeMsPassport::Passport::GetPublicKey(CharToString(accountId));
	status = res.status;

	if (res.status == 0) {
		outSize = res.buffer->Length;
		return byteArrayToChar(res.buffer);
	}
	else {
		return nullptr;
	}
}

NODEMSPASSPORT_EXPORT char* passport::unmanaged::getPublicKeyHash(int& status, int& outSize, const char* accountId) {
	CSNodeMsPassport::Passport::PassportResult res = CSNodeMsPassport::Passport::GetPublicKeyHash(CharToString(accountId));
	status = res.status;

	if (res.status == 0) {
		outSize = res.buffer->Length;
		return byteArrayToChar(res.buffer);
	}
	else {
		return nullptr;
	}
}

NODEMSPASSPORT_EXPORT bool passport::unmanaged::verifyChallenge(const util::byte* challenge, int challengeSize, const util::byte* signature, int signatureSize, const util::byte* publicKey, int publicKeySize) {
	return CSNodeMsPassport::Passport::VerifyChallenge(charToByteArray(challenge, challengeSize), charToByteArray(signature, signatureSize), charToByteArray(publicKey, publicKeySize));
}

NODEMSPASSPORT_EXPORT int passport::unmanaged::deletePassportAccount(const char* accountId) {
	return CSNodeMsPassport::Passport::DeletePassportAccount(CharToString(accountId));
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
			if (!CredUnprotectW(false, toUnprotect_cpy.data(), (DWORD)toUnprotect_cpy.size(), nullptr, &unprotectedSize)) {
				DWORD dwErr = GetLastError();
				if (dwErr == ERROR_INSUFFICIENT_BUFFER && unprotectedSize > 0) {
					secure_vector<wchar_t> outData;
					outData.resize(unprotectedSize);

					if (CredUnprotectW(false, toUnprotect_cpy.data(), (DWORD)toUnprotect_cpy.size(), outData.data(), &unprotectedSize)) {
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
			if (!CredProtectW(false, toProtect_cpy.data(), (DWORD)toProtect_cpy.size(), nullptr, &protectedSize, nullptr)) {
				DWORD dwErr = GetLastError();

				if (dwErr == ERROR_INSUFFICIENT_BUFFER && protectedSize > 0) {
					secure_vector<wchar_t> outData;
					outData.resize(protectedSize);

					if (CredProtectW(false, toProtect_cpy.data(), (DWORD)toProtect_cpy.size(), outData.data(), &protectedSize, nullptr)) {
						toProtect = secure_wstring(outData.begin(), outData.end());
						return true;
					}
				}
			}
		}
	}

	return false;
}

NODEMSPASSPORT_EXPORT bool credentials::write(const std::wstring& target, const std::wstring& user, const secure_wstring& password, bool encrypt) {
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

NODEMSPASSPORT_EXPORT void* credentials::util::read(const std::wstring& target, wchar_t*& username, secure_wstring*& password, bool encrypt) {
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

NODEMSPASSPORT_EXPORT void credentials::util::deleteWstring(secure_wstring* in) {
	delete in;
}

NODEMSPASSPORT_EXPORT void credentials::util::freePcred(void* data) {
	::CredFree((PCREDENTIALW)data);
}

NODEMSPASSPORT_EXPORT bool credentials::remove(const std::wstring& target) {
	return ::CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
}

NODEMSPASSPORT_EXPORT bool credentials::isEncrypted(const std::wstring& target, bool& ok) {
	PCREDENTIALW pcred;

	ok = ::CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred);
	if (!ok) return false;

	secure_wstring pass = copyToWChar((char*)pcred->CredentialBlob, pcred->CredentialBlobSize, ok);
	::CredFree(pcred);
	if (!ok) {
		return false;
	}

	CRED_PROTECTION_TYPE protectionType;
	secure_vector<wchar_t> pass_cpy(pass.begin(), pass.end());
	ok = CredIsProtectedW(pass_cpy.data(), &protectionType);
	if (ok) {
		if (protectionType == CredUnprotected) {
			return false;
		}
		else {
			return true;
		}
	}
	else {
		return false;
	}
}