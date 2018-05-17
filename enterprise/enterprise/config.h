#ifndef CONFIG_H
#define CONFIG_H

#include <string>

class Config
{
public:
    static Config* getInstance();

    std::string getDealContractAddress();
    std::string getOwnerKeyContractAddress();
private:
    Config();

    std::string deal_contract_address_;
    std::string user_key_contract_address_;
};

#endif // CONFIG_H
