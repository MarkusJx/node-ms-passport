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
#include "CLITools.hpp"

using namespace System;
using namespace System::Reflection;
using namespace nodeMsPassport;

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
	return passport::passportException(CLITools::string_to_std_string(e->Message), code);
}

void passport::setCSharpDllLocation(const std::string& location) {
	CLITools::setDllLocation(location);
}

bool passport::passportAvailable() {
	try {
		return CLITools::callFunc<bool>("PassportAvailable");
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

bool passport::passportAccountExists(const std::string& accountId) {
	try {
		return CLITools::callFunc<bool>("PassportAccountExists", accountId);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

void passport::createPassportKey(const std::string& accountId) {
	try {
		CLITools::callFunc<void>("CreatePassportKey", accountId);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<byte> passport::passportSign(const std::string& accountId, const secure_vector<byte>& challenge) {
	try {
		return CLITools::callFunc<secure_vector<byte>>("PassportSign", accountId, challenge);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<byte> passport::getPublicKey(const std::string& accountId) {
	try {
		return CLITools::callFunc<secure_vector<byte>>("GetPublicKey", accountId);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

secure_vector<byte> passport::getPublicKeyHash(const std::string& accountId) {
	try {
		return CLITools::callFunc<secure_vector<byte>>("GetPublicKeyHash", accountId);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

bool passport::verifySignature(const secure_vector<byte>& challenge, const secure_vector<byte>& signature,
	const secure_vector<byte>& publicKey) {
	try {
		return CLITools::callFunc<bool>("VerifyChallenge", challenge, signature, publicKey);
	} catch (Exception^ e) {
		throw convertException(e);
	}
}

void passport::deletePassportAccount(const std::string& accountId) {
	try {
		CLITools::callFunc<void>("DeletePassportAccount", accountId);
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
bool credentials::unprotectCredential(secure_wstring& toUnprotect) {
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

bool credentials::protectCredential(secure_wstring &toProtect) {
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
		if (!protectCredential(pass)) {
            throw std::runtime_error("Could not encrypt credentials. Error: " + get_last_error_as_string());
		}
	}

	secure_vector<unsigned char> passData = copyToChar(pass, ok);
    if (!ok) {
        throw std::runtime_error("Could not copy the password data");
    }

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
	if (!ok) throw std::runtime_error("Could not check if data is encrypted");

	secure_wstring pass = copyToWChar((char*)pcred->CredentialBlob, pcred->CredentialBlobSize, ok);
	::CredFree(pcred);
	if (!ok) throw std::runtime_error("Could not check if data is encrypted");

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
		throw std::runtime_error("Could not check if data is encrypted");
	}
}

bool credentials::exists(const std::wstring& target) {
    PCREDENTIALW pcred;
    if (::CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred)) {
        CredFree(pcred);
		return true;
    } else {
		if (GetLastError() == ERROR_NOT_FOUND) {
            return false;
        } else {
            throw std::runtime_error("Could not check if the account exists. Error: " + get_last_error_as_string());
		}
	}
}

bool passwords::encrypt(secure_wstring& data) {
	secure_wstring copy = data;
	bool ok = credentials::protectCredential(copy);
	if (!ok) {
		return false;
	} else {
		data = copy;
		return true;
	}
}

bool passwords::decrypt(secure_wstring& data) {
	secure_wstring copy = data;
    bool ok = credentials::unprotectCredential(copy);
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

std::string nodeMsPassport::get_last_error_as_string() {
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string();//No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}
