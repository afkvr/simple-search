#include "config.h"

Config::Config()
{
    deal_contract_address_ = "0xb6b29ef90120bec597939e0eda6b8a9164f75deb";
    user_key_contract_address_ = "0x70f94d58cc3fdcbeac7140f35a087da9fcd09b94";
    wallet_address_ = "0x74bec5006191365e3238d6c7664aa05dd4450be9";
    passpharse_ = "123";
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

std::string Config::getPassPharse() {
    return passpharse_;
}
