#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <sstream>
#include <iomanip>

extern "C" {
#include "sodium.h"
}
class Utils
{
public:
    Utils();
    static std::string convertToBase64 (const unsigned char* input, size_t input_len);
    static std::string convertFromB64ToBin (const char* input, unsigned long long input_len);


    // interact with file and folder
    static bool createFolder (std::string folderPath);
    static bool createFile (std::string filePath);
    static bool isExists(std::string path);

    static std::string convertToHex (const unsigned char* input, size_t input_len);
    static std::string convertToHex (long long x);

    static void convertFromHex (std::string x, long long & result);
    static void convertFromHex (std::string x, std::string & result);

    static std::string zeroLeadPad (std::string input, size_t length);
    static std::string zeroTrailPad (std::string input, size_t length);
    static std::string trimZeroLead (std::string s);

};

#endif // UTILS_H
