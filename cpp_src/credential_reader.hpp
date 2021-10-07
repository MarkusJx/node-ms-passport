#ifndef PASSPORT_CREDENTIAL_READER_HPP
#define PASSPORT_CREDENTIAL_READER_HPP

#include "util.hpp"

namespace credential_reader {
	using namespace nodeMsPassport;

	secure_wstring parse_credential(unsigned char *data, size_t length, bool &encrypted);
}

#endif //PASSPORT_CREDENTIAL_READER_HPP