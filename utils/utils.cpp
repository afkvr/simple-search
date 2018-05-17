#include "utils.h"
#include <iostream>
#include <fstream>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem.hpp>

Utils::Utils()
{

}

std::string Utils::convertToBase64(const unsigned char *input, size_t input_len) {

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

std::string Utils::convertFromB64ToBin(const char *input, unsigned long long input_len) {
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


bool Utils::createFolder (std::string folderPath) {
    //dont continuous process if exists before
    if (Utils::isExists(folderPath)) {
        std::cerr << "Util::createFolder " << folderPath << " was exists" << std::endl;
        return true;
    }

    boost::filesystem::path path(folderPath);
    return boost::filesystem::create_directory(path);
}

bool Utils::createFile (std::string filePath) {
    // dont continuous process if exists before
    if (Utils::isExists(filePath)) {
        std::cerr << "Util::createFile " << filePath << " was exists" << std::endl;
        return true;
    }

    std::ofstream of(filePath);
    bool status = of.is_open();
    of.close();
    return status;
}

bool Utils::isExists(std::string path) {
    boost::filesystem::path fp(path);

    try {
        if (boost::filesystem::exists(fp))
            return true;
    } catch (boost::filesystem::filesystem_error &e) {
        std::cerr << e.what() << std::endl;
    }

    return false;
}

std::string Utils::convertToHex (const unsigned char* input, size_t input_len) {
    size_t hex_maxlen = input_len * 2 + 1;
    char* hex = new char[hex_maxlen];
    sodium_bin2hex(hex, hex_maxlen, input, input_len);
    return std::string (hex, hex_maxlen - 1);
}

std::string Utils::convertToHex(long long x) {
    std::stringstream stream;
    stream << std::hex << x;
    return stream.str();
}

std::string Utils::zeroLeadPad(std::string input, size_t length) {
    std::string result;
    if (input.length() < length) {
        std::stringstream stream;
        stream << std::setfill ('0') << std::setw(length) << input;
        result = stream.str();
    }else {
        result = input;
    }
    return result;
}

std::string Utils::zeroTrailPad(std::string input, size_t length) {
    std::string result;
    if (length > input.length()) {
        result = input.append(std::string (length - input.length(), '0'));
    }else{
        result = input;
    }
    return result;
}

void Utils::convertFromHex(std::string x, long long & result) {
    std::stringstream ss;
    ss << std::hex << x;
    ss >> result;
}

void Utils::convertFromHex(std::string hex, std::string & result) {

    size_t bin_max_len = hex.length();
    char* bin = new char[bin_max_len];
    size_t bin_len = 0;
    int code = sodium_hex2bin(reinterpret_cast<unsigned char*> (bin), bin_max_len,
                           hex.c_str(), hex.length(),
                           NULL, &bin_len,
                           NULL);
    if (code == 0) {
        result = std::string (bin, bin_len);
    }
    delete[] bin;

}

std::string Utils::trimZeroLead(std::string s) {
    s.erase(0, s.find_first_not_of('0'));
    return s;
}
