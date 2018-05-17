#include "config.h"

Config::Config()
{
    deal_contract_address_ = "0xf7b53bbb8ce29406a6a65848bc291b518fbdca1d";
    user_key_contract_address_ = "0xbeb5865637f9860daa9d407e9ad66b531b9f5932";
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
