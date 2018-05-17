#ifndef KEYMANAGER_H
#define KEYMANAGER_H

#include <iostream>
#include <string>
#include <fstream>

#include "nlohmann/json.hpp"
#include "utils/utils.h"

extern "C" {
#include "sodium.h"
}

class KeyManager
{
public:
    KeyManager();
    static bool getKey (std::string& file_path, std::string& passphrase,
                        char** secret_key, size_t &secret_key_len,
                        char** public_key, size_t &public_key_len,
                        char** o_sign_sec_key, size_t& sign_sec_key_len,
                        char** o_sign_pub_key, size_t& sign_pub_key_len);
    static bool createKey (std::string& file_path, std::string& passphrase);
};

#endif // KEYMANAGER_H
