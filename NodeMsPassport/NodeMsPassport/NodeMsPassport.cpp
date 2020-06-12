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
#include "NodeMsPassport.h"

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

array<unsigned char>^ charToByteArray(const char* data, int len) {
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

NODEMSPASSPORT_EXPORT char* passport::unmanaged::passportSign(int& status, int& outSize, const char* accountId, const char* challenge, int challengeSize) {
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

NODEMSPASSPORT_EXPORT bool passport::unmanaged::verifyChallenge(const char* challenge, int challengeSize, const char* signature, int signatureSize, const char* publicKey, int publicKeySize) {
	return CSNodeMsPassport::Passport::VerifyChallenge(charToByteArray(challenge, challengeSize), charToByteArray(signature, signatureSize), charToByteArray(publicKey, publicKeySize));
}

NODEMSPASSPORT_EXPORT int passport::unmanaged::deletePassportAccount(const char* accountId) {
	return CSNodeMsPassport::Passport::DeletePassportAccount(CharToString(accountId));
}

bool to_wstring(const std::string& in, std::wstring& out) {
	out.resize(in.size() + 1);
	size_t written = 0;
	errno_t err = mbstowcs_s(&written, (wchar_t*)out.data(), out.size(), in.c_str(), in.size());
	if (err != 0 || written != out.size()) {
		return false;
	}
	else {
		return true;
	}
}

std::vector<unsigned char> copyToChar(const std::wstring& data) {
	std::vector<unsigned char> tmp;
	tmp.resize(data.size() * sizeof(wchar_t));

	memcpy_s(tmp.data(), tmp.size(), data.c_str(), data.size() * sizeof(wchar_t));

	return tmp;
}

std::wstring copyToWChar(char* ptr, int sizeInBytes) {
	std::wstring out;
	out.resize(sizeInBytes / sizeof(wchar_t));

	memcpy_s((wchar_t*) out.data(), out.size() * sizeof(wchar_t), ptr, sizeInBytes);
	return out;
}

NODEMSPASSPORT_EXPORT bool credentials::write(const std::wstring& target, const std::wstring& user, const std::wstring& password) {
	std::vector<unsigned char> passData = copyToChar(password);
	DWORD cbCreds = (DWORD)passData.size();

	CREDENTIALW cred = { 0 };
	cred.Type = CRED_TYPE_GENERIC;

	cred.TargetName = (LPWSTR)target.c_str();
	cred.CredentialBlobSize = cbCreds;
	cred.CredentialBlob = (LPBYTE)passData.data();
	cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

	cred.UserName = (LPWSTR)user.c_str();

	return ::CredWriteW(&cred, 0);
}

NODEMSPASSPORT_EXPORT void* credentials::util::read(const std::wstring& target, wchar_t*& username, std::wstring& password) {
	PCREDENTIALW pcred;

	BOOL ok = ::CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred);
	if (!ok) return nullptr;

	username = pcred->UserName;
	char *credential = (char*)pcred->CredentialBlob;
	int credSize = pcred->CredentialBlobSize;

	password = copyToWChar(credential, credSize);

	return pcred;
}

NODEMSPASSPORT_EXPORT void credentials::util::freePcred(void* data) {
	::CredFree((PCREDENTIALW)data);
}

NODEMSPASSPORT_EXPORT bool credentials::remove(const std::wstring& target) {
	return ::CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
}