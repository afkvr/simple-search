#ifndef CONFIG_H
#define CONFIG_H

#include <string>

class Config
{
public:
    static Config* getInstance();

    std::string getDealContractAddress();
    std::string getOwnerKeyContractAddress();
    std::string getWalletAddress();
    std::string getPassPharse();
private:
    Config();

    std::string deal_contract_address_;
    std::string user_key_contract_address_;
    std::string wallet_address_;
    std::string passpharse_;
};

#endif // CONFIG_H
