#include <windows.h>
#include <wincred.h>
#include <stdexcept>

#include "credential_reader.hpp"

using namespace credential_reader;

secure_wstring string_to_wstring(char* str, size_t length) {
    secure_wstring ws;

    size_t out;
    if (mbstowcs_s(&out, nullptr, 0, str, length) != 0) {
        throw std::runtime_error("Could not convert the string");
    }

    ws.resize(out, L'\0');
    if (mbstowcs_s(&out, ws.data(), ws.size(), str, length) != 0) {
        throw std::runtime_error("Could not convert the string");
    }

    return ws;
}

secure_wstring unprotect_cred_u8(char *data, size_t length, bool &valid) {
    CRED_PROTECTION_TYPE protectionType;

    DWORD sz = 0;
    if (!CredUnprotectA(false, data, (DWORD) length, nullptr, &sz)) {
        DWORD dwErr = GetLastError();
        if (dwErr == ERROR_INSUFFICIENT_BUFFER && sz > 0) {
            secure_vector<char> outData(sz, '\0');
            if (CredUnprotectA(false, data, (DWORD) length, outData.data(), &sz)) {
                return string_to_wstring(outData.data(), outData.size());
            }
        }
    }

    valid = false;
    return {};
}

secure_wstring unprotect_cred_u16(char* data, size_t length, bool &valid) {
    CRED_PROTECTION_TYPE protectionType;

    length /= sizeof(wchar_t);
    DWORD sz = 0;
    if (!CredUnprotectW(false, (wchar_t *) data, (DWORD) length, nullptr, &sz)) {
        DWORD dwErr = GetLastError();
        if (dwErr == ERROR_INSUFFICIENT_BUFFER && sz > 0) {
            secure_wstring outData(sz, '\0');
            if (CredUnprotectW(false, (wchar_t *) data, (DWORD) length, outData.data(), &sz)) {
                return outData;
            }
        }
    }

    valid = false;
    return {};
}

// Source: https://stackoverflow.com/a/1031773
bool is_utf8(const char *string, size_t length) {
    if (!string)
        return false;

    const unsigned char *bytes = (const unsigned char *) string;
    while (bytes < (bytes + length)) {
        if ((       // ASCII
                    // use bytes[0] <= 0x7F to allow ASCII control characters
                    bytes[0] == 0x09 ||
                    bytes[0] == 0x0A ||
                    bytes[0] == 0x0D ||
                    (0x20 <= bytes[0] && bytes[0] <= 0x7E))) {
            bytes += 1;
            continue;
        }

        if ((// non-overlong 2-byte
                    (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
                    (0x80 <= bytes[1] && bytes[1] <= 0xBF))) {
            bytes += 2;
            continue;
        }

        if ((// excluding overlongs
                    bytes[0] == 0xE0 &&
                    (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
                    (0x80 <= bytes[2] && bytes[2] <= 0xBF)) ||
                (// straight 3-byte
                        ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
                                bytes[0] == 0xEE ||
                                bytes[0] == 0xEF) &&
                        (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                        (0x80 <= bytes[2] && bytes[2] <= 0xBF)) ||
                (// excluding surrogates
                        bytes[0] == 0xED &&
                        (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
                        (0x80 <= bytes[2] && bytes[2] <= 0xBF))) {
            bytes += 3;
            continue;
        }

        if ((// planes 1-3
                    bytes[0] == 0xF0 &&
                    (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
                    (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                    (0x80 <= bytes[3] && bytes[3] <= 0xBF)) ||
                (// planes 4-15
                        (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
                        (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                        (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                        (0x80 <= bytes[3] && bytes[3] <= 0xBF)) ||
                (// plane 16
                        bytes[0] == 0xF4 &&
                        (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
                        (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                        (0x80 <= bytes[3] && bytes[3] <= 0xBF))) {
            bytes += 4;
            continue;
        }

        return false;
    }

    return true;
}

bool is_protected_u16(char* data) {
    CRED_PROTECTION_TYPE protectionType = CredUserProtection;
    return CredIsProtectedW((wchar_t *) data, &protectionType) && protectionType != CredUnprotected;
}

bool is_protected_u8(char* data) {
    CRED_PROTECTION_TYPE protectionType = CredUserProtection;
    return CredIsProtectedA(data, &protectionType) && protectionType != CredUnprotected;
}

secure_wstring credential_reader::parse_credential(unsigned char *_data, size_t length, bool &encrypted, bool &valid) {
    if (length == 0 || _data == nullptr) return secure_wstring();
    auto *data = reinterpret_cast<char *>(_data);
    valid = true;

    if (is_protected_u16(data)) {
        encrypted = true;
        return unprotect_cred_u16(data, length, valid);
    } else if (is_protected_u8(data)) {
        encrypted = true;
        return unprotect_cred_u8(data, length, valid);
    } else if (is_utf8(data, length)) {
        encrypted = false;
        return string_to_wstring(data, length);
    } else {
        encrypted = false;
        return secure_wstring((wchar_t *) data, length / sizeof(wchar_t));
    }
}