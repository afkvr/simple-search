#include "config.h"

Config::Config()
{
    deal_contract_address_ = "0x70f94d58cc3fdcbeac7140f35a087da9fcd09b94";
    user_key_contract_address_ = "0xb6b29ef90120bec597939e0eda6b8a9164f75deb";
    wallet_address_ = "0xc3f59a489644a299fb16b712c5f295f96d6dc0c0";
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

std::string Config::getWalletAddress() {
    return wallet_address_;
}

