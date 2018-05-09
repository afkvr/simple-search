#ifndef _UTILS_INCLUDED_
#define _UTILS_INCLUDED_


extern "C" {
	#include "sodium.h"
}

namespace bitmile {
inline bool quickCompareStr(const char* str1, const char* str2) {
	if (!str1 || !str2)
		return false;

	while (*str1 != '\0' && *str2 != '\0') {
		if (*str1 != *str2)
			return false;
		
		str1++;
		str2++;
	}

	if (*str1 != *str2)
		return false;

	return true;
}

inline std::string convertToBase64(const unsigned char *input, size_t input_len) {

    if (input == NULL) {
        return std::string ("");
    }

    size_t b64_maxlen = sodium_base64_ENCODED_LEN(input_len, sodium_base64_VARIANT_ORIGINAL);
    //encode len = string_length + '\0' character

    char* b64 = new char [b64_maxlen];

    sodium_bin2base64(b64, b64_maxlen,
                      input, input_len,
                      sodium_base64_VARIANT_ORIGINAL);

    //b64_maxlen is string length plus '\0' char => discard the '\0' char before
    //puting it to result string
    std::string result (b64, b64_maxlen - 1);

    delete[] b64;
    return result;
}

inline std::string convertFromB64ToBin(const char *input, unsigned long long input_len) {
    if (input == NULL) {
        return std::string ("");
    }
    size_t bin_maxlen = input_len * 2;
    char* bin = new char [bin_maxlen];
    size_t bin_len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*> (bin), bin_maxlen,
                          input, input_len,
                          NULL, &bin_len,
                          NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        delete[] bin;
        return std::string ("");
    }
    std::string result (bin, bin_len);
    delete[] bin;
    return result;
}
}

#endif // UTILS 