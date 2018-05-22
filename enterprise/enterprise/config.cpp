#include "config.h"

Config::Config()
{
    deal_contract_address_ = "0xb6b29ef90120bec597939e0eda6b8a9164f75deb";
    user_key_contract_address_ = "0x54a3ecc66008a40bd05988272b484c7d5f6359a5";
}

Config* Config::getInstance() {
    static Config* instance = NULL;

    if (instance == NULL) {
        instance = new Config();
    }

    return instance;
}


std::string Config::getDealContractAddress() {
    return deal_contract_address_;
}

std::string Config::getOwnerKeyContractAddress(){
    return user_key_contract_address_;
}
