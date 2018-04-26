#ifndef _UTILS_INCLUDED_
#define _UTILS_INCLUDED_

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
}

#endif // UTILS 