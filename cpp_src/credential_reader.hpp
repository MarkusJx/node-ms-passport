#ifndef PASSPORT_CREDENTIAL_READER_HPP
#define PASSPORT_CREDENTIAL_READER_HPP

#include "util.hpp"

/**
 * A credential reader
 */
namespace credential_reader {
	using namespace nodeMsPassport;

    /**
     * Parse a credential read either using
     * CredReadW, CredReadA, CredEnumerateW
     * or CredEnumerateA. Checks if the data was
     * encrypted using CredProtect and determines
     * if it was encoded in utf-8/ascii or utf-16.
     * Decrypts the password if it is encrypted and
     * converts it to utf-16 if it isn't already.
     *
     * @param data the data to parse
     * @param length the length of the data
     * @param encrypted is set to true if the given data is encrypted
     * @param valid is set to true if the data could be encrypted
     * @return the unencrypted data converted to a wide string
     */
	secure_wstring parse_credential(unsigned char *data, size_t length, bool &encrypted, bool &valid);
}

#endif //PASSPORT_CREDENTIAL_READER_HPP