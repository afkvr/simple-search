#include "blockchain_interface.h"

namespace bitmile {
  namespace blockchain {

    BlockchainInterface::BlockchainInterface () {
      curl_.add<CURLOPT_URL>("http://192.168.1.167");
      curl_.add<CURLOPT_PORT>(8545);
    }

    BlockchainInterface::ApiDef BlockchainInterface::api_def_ = {
        {RPC_API::UNLOCK_ACCOUNT, "personal_unlockAccount"},
        {RPC_API::CALL, "eth_call"},
        {RPC_API::SEND_TRANSACTION, "eth_sendTransaction"},
        {RPC_API::ESTIMATE_GAS, "eth_estimateGas"},
        {RPC_API::CREATE_FILTER, "eth_newFilter"},
        {RPC_API::GET_FILTER_LOGS, "eth_getFilterLogs"},
        {RPC_API::GET_BLOCK_NUMBER, "eth_blockNumber"}
    };


    size_t BlockchainInterface::CurlWriteCallbackStdString(void *contents, size_t size, size_t nmemb, void *s) {
        std::string* str = static_cast <std::string*> (s);
        size_t newLength = size*nmemb;
        size_t oldLength = str->size();

        str->resize(oldLength + newLength);

        std::copy((char*)contents,(char*)contents+newLength,str->begin()+oldLength);

        return size*nmemb;
    }


    bool BlockchainInterface::UnlockAccount (std::string account, std::string passphrase, int time) {
      std::cout << "BlockchainInterface::UnlockAccount " << account << std::endl;
      nlohmann::json reply = CreateMessage(api_def_[RPC_API::UNLOCK_ACCOUNT], nlohmann::json::array({account, passphrase, time}), "1");
      if (reply.count("result") == 1) {
          if (reply["result"]) {
              std::cout << "BlockchainInterface::UnlockAccount true" << std::endl;
              return true;
          }
      }
      std::cout << "BlockchainInterface::UnlockAccount false" << std::endl;
      return false;
    }


    bool BlockchainInterface::SendTransaction(std::string sender,
                                              std::string receiver,
                                              std::string value,
                                              std::string gas,
                                              std::string data,
                                              std::string id,
                                              nlohmann::json& result) {

        nlohmann::json param;
        param["from"] = sender;
        param["to"] = receiver;
        param["gas"] = gas;
        param["value"] = value;
        param["data"] = data;

        result = CreateMessage(api_def_[RPC_API::SEND_TRANSACTION], nlohmann::json::array({param}), id);

        if (result.count("result") == 1) {
            return true;
        }
        return false;
    }

    bool BlockchainInterface::SendCall(std::string sender, std::string receiver, std::string data, std::string id, nlohmann::json& result) {

        nlohmann::json param;
        param["from"] = sender;
        param["to"] = receiver;
        param["data"] = data;

        result = CreateMessage(api_def_[RPC_API::CALL], nlohmann::json::array({param, "latest"}), id);
        if (result.count("result") == 1) {
            return true;
        }
        return false;
    }

    bool BlockchainInterface::EstimateGas(std::string sender, std::string receiver, std::string value, std::string gas, std::string data, std::string id, nlohmann::json& result) {

        nlohmann::json param;
        param["from"] = sender;
        param["to"] = receiver;
        param["gas"] = gas;
        param["value"] = value;
        param["data"] = data;

        result = CreateMessage(api_def_[RPC_API::ESTIMATE_GAS], nlohmann::json::array({param}), id);
        if (result.count("result") == 1) {
            return true;
        }
        return false;
    }

    bool BlockchainInterface::Createfilter (std::string from, std::string to, std::string address, std::vector<std::string> topics, std::string id, nlohmann::json& result){

        nlohmann::json param;
        param["fromBlock"] = from;
        param["toBlock"] = to;
        param["address"] = address;
        if (topics.size() > 0) {
            nlohmann::json topic_json (topics);
            param["topics"] = topic_json;
        }


        result = CreateMessage(api_def_[RPC_API::CREATE_FILTER], nlohmann::json::array({param}), id);

        if (result.count("result") == 1) {
            return true;
        }
        return false;
    }


    bool BlockchainInterface::GetFilterLogs(std::string filter, std::string id, nlohmann::json& result) {
        result = CreateMessage(api_def_[RPC_API::GET_FILTER_LOGS], nlohmann::json::array({filter}), id);
        if (result.count("result") == 1) {
            return true;
        }
        return false;
    }

    bool BlockchainInterface::GetBlockNumber(std::string id, nlohmann::json &result) {
        result = CreateMessage(api_def_[RPC_API::GET_BLOCK_NUMBER], nlohmann::json::array(), id);
        if (result.count("result") == 1) {
            return true;
        }
        return false;
    }

    nlohmann::json BlockchainInterface::CreateMessage(std::string method, nlohmann::json params, std::string id) {
        nlohmann::json request;
        request["jsonrpc"] = "2.0";
        request["method"] = method;
        request["params"] = params;
        request["id"] = id;

        std::string request_str = request.dump(0);

        std::string result;
        curl_.add<CURLOPT_POST>(1L);
        curl_.add<CURLOPT_POSTFIELDSIZE> (request_str.length());
        curl_.add<CURLOPT_POSTFIELDS> (request_str.c_str());
        curl_.add<CURLOPT_WRITEFUNCTION> (CurlWriteCallbackStdString);
        curl_.add<CURLOPT_WRITEDATA> (&result);

        try {
            // Execute the request.
            curl_.perform();
        } catch (curl::curl_easy_exception error) {
            // Otherwise we could print the stack like this:
            error.print_traceback();
        }
        nlohmann::json reply  = nlohmann::json::parse(result);
        return reply;
    }

    DealContract::FunctionDefinition DealContract::functions_ = {
        {Functions::CREAT_DEAL, "createDeal(uint256,uint256,string)"},
        {Functions::GET_ANSWER_NUMB, "getTheNumberOfAnswers(uint256)"},
        {Functions::GET_ANSWER, "getAnswer(uint256,uint256)"},
        {Functions::PAY_FOR_KEY, "payForRequestKeys(uint256,address[])"},
        {Functions::GET_KEY_NUMB, "getTheNumberOfSecKeys(uint256)"},
        {Functions::GET_KEY, "getSecKey(uint256,uint256)"},
        {Functions::LOG_DEAL_CREATED, "LogDealCreated(uint256,address,uint256,string)"}
    };

    std::string DealContract::GetFunctionHash(Functions def) {
        //get function hash
        CryptoPP::Keccak_256 keck_256;
        char* function_hash = new char [keck_256.DigestSize()];
        keck_256.CalculateDigest(reinterpret_cast <unsigned char*> (function_hash),
                                reinterpret_cast<const CryptoPP::byte*> (functions_[def].c_str()),
                                functions_[def].length());
        std::string result (function_hash, keck_256.DigestSize());
        delete[] function_hash;
        return result;
    }

    std::string DealContract::GetFunctionABI(Functions def) {
        //get first 4 bytes
        std::string result (GetFunctionHash(def).c_str(), 4);
        return result;
    }

    std::string DealContract::CreateDeal(unsigned long long prize,
                                         unsigned long long expired_time,
                                         std::string public_key) {
        /*
         * create binary parameter from data
         *
         * the result is represented in hex so, all length should be doubled
         */
        int prize_byte_len = 32;
        int expired_time_byte_len = 32;

        std::string func_hash = GetFunctionABI(Functions::CREAT_DEAL);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        //prize: uint256
        std::string prize_str = Utils::zeroLeadPad(Utils::convertToHex(prize), prize_byte_len * 2);
        std::cout << "prize hex " << prize_str<< std::endl;

        //expired time: uint256
        std::string expired_time_str = Utils::zeroLeadPad(Utils::convertToHex(expired_time), expired_time_byte_len * 2);
        std::cout << "expired_time_str hex " << expired_time_str << std::endl;

        std::cout << "prize_byte_len + expired_time_byte_len "  << Utils::zeroLeadPad(Utils::convertToHex(prize_byte_len + expired_time_byte_len + 32), 32 * 2) << std::endl;

        std::stringstream stream;
        stream << "0x"
               << abi_hash
               << prize_str
               << expired_time_str
               << Utils::zeroLeadPad(Utils::convertToHex(prize_byte_len + expired_time_byte_len + 32), 32 * 2);

        std::string public_key_hex = Utils::convertToHex(reinterpret_cast<const unsigned char*> (public_key.c_str()), 32);
        std::cout << "public_key_hex " << public_key_hex << std::endl;

        std::cout << "public_key.length() " << public_key.length() << std::endl;
        stream << Utils::zeroLeadPad(Utils::convertToHex(public_key_hex.length()), 32 * 2);

        size_t block_size = 32;
        while (block_size < public_key.length()) {
            block_size += 32;
        }

        stream << Utils::zeroTrailPad(Utils::convertToHex(reinterpret_cast<const unsigned char*> (public_key_hex.c_str()), public_key_hex.length()), block_size * 2);

        return stream.str();
    }

    std::string DealContract::GetNumberOfAnswer(unsigned long long deal_id){
        std::string func_hash = GetFunctionABI(Functions::GET_ANSWER_NUMB);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        int deal_id_byte_len = 32;

        std::stringstream stream;

        stream << "0x"
               << abi_hash
               << Utils::zeroLeadPad(Utils::convertToHex(deal_id), deal_id_byte_len * 2);
        return stream.str();
    }

    std::string DealContract::GetAnswer(unsigned long long deal_id, unsigned long long index) {
        int deal_id_byte_len = 32,
                index_byte_len = 32;
        std::string func_hash = GetFunctionABI(Functions::GET_ANSWER);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        std::stringstream stream;
        stream << "0x"
               << abi_hash
               << Utils::zeroLeadPad(Utils::convertToHex(deal_id), deal_id_byte_len * 2)
               << Utils::zeroLeadPad(Utils::convertToHex(index), index_byte_len * 2);
        return stream.str();
    }

    std::string DealContract::PayForKey(unsigned long long deal_id, std::vector<std::string> users) {
        int deal_id_byte_len = 32;

        std::string func_hash = GetFunctionABI(Functions::PAY_FOR_KEY);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        std::stringstream stream;
        stream << "0x"
               << abi_hash
               << Utils::zeroLeadPad(Utils::convertToHex(deal_id), deal_id_byte_len * 2);

        stream << Utils::zeroLeadPad(Utils::convertToHex(deal_id_byte_len + 32), 32 * 2)
               << Utils::zeroLeadPad(Utils::convertToHex(users.size()), 32 * 2);

        for (size_t i = 0; i < users.size(); i++) {
            stream << Utils::zeroLeadPad(users[i].substr(2, users[i].length() - 2), 32* 2);
        }
        return stream.str();
    }

    std::string DealContract::GetNumberOfKey(unsigned long long deal_id) {
        std::string func_hash = GetFunctionABI(Functions::GET_KEY_NUMB);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        int deal_id_byte_len = 32;

        std::stringstream stream;

        stream << "0x"
        << abi_hash
        << Utils::zeroLeadPad(Utils::convertToHex(deal_id), deal_id_byte_len * 2);

        return stream.str();
    }

    std::string DealContract::GetKey(unsigned long long deal_id, unsigned long long index) {
        int deal_id_byte_len = 32,
                index_byte_len = 32;
        std::string func_hash = GetFunctionABI(Functions::GET_KEY);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        std::stringstream stream;
        stream << "0x"
               << abi_hash
               << Utils::zeroLeadPad(Utils::convertToHex(deal_id), deal_id_byte_len * 2)
               << Utils::zeroLeadPad(Utils::convertToHex(index), index_byte_len * 2);
        return stream.str();
    }

    nlohmann::json DealContract::ParseLogCreateDeal(nlohmann::json &log) {
        /*
         * [
         *  {
         *      "address" : "",
         *      "topics" : [""],
         *      "data" : {
         *          "dealId" : 1,
         *          "bidder" : "",
         *          "expire_time": 1,
         *          "pub_key" : ""
         *      },
         *      "transactionHash" : "",
         *      "blockNumber" : ""
         *  },
         * ]
         */
        nlohmann::json result;
        if (log.count("result") == 1) {
            for (nlohmann::json::iterator it = log["result"].begin(); it != log["result"].end(); it++) {
                nlohmann::json entry;
                entry["address"] = (*it)["address"];
                entry["topics"] = (*it)["topics"];
                entry["transactionHash"] = (*it)["transactionHash"];
                long long block_number;
                Utils::convertFromHex((*it)["blockNumber"], block_number);
                entry["blockNumber"] =  block_number;
                //handle data
                std::string data = (*it)["data"];
                data = data.substr(2, data.length() - 2);

                nlohmann::json data_json;

                //deal id
                std::string deal_id = data.substr(0, 32*2);

                long long deal_id_numb;
                Utils::convertFromHex(deal_id, deal_id_numb);
                data_json["dealId"] = deal_id_numb;

                std::string bidder = Utils::trimZeroLead(data.substr(32*2, 32*2));
                data_json["bidder"] = "0x" + bidder;

                std::string expire_time = data.substr(32*4, 32 * 2);

                long long expire_time_numb;
                Utils::convertFromHex(expire_time, expire_time_numb);
                data_json["expire_time"] = expire_time_numb;

                std::string pub_pos = data.substr(32 * 6, 64);

                long long pub_offset;
                Utils::convertFromHex(pub_pos, pub_offset);

                //get length
                long long pub_len;
                Utils::convertFromHex (data.substr(pub_offset * 2, 64), pub_len);
                //get content
                std::string pub_key = "0x" + data.substr(pub_offset * 2 + 64, pub_len * 2);

                data_json["pub_key"] = pub_key;

                entry["data"] = data_json;
                result.push_back(entry);
            }
        }

        return result;
    }

    nlohmann::json DealContract::ParseGetNumberOfAnswerResult(nlohmann::json &in) {
        nlohmann::json result;
        if (in.count("result") == 1) {
            std::string data = in["result"];
            data = data.substr(2, data.length() - 2);

            long long amount;
            Utils::convertFromHex(data, amount);
            result["amount"] = amount;
        }
        return result;
    }

    nlohmann::json DealContract::ParseGetAnswer(nlohmann::json &in) {
        nlohmann::json result;
        if (in.count("result") == 1) {
            std::string data = in["result"];
            data = data.substr(2, data.length() - 2);

            std::string user_address = data.substr(0, 32 * 2);
            result["user_address"] = "0x" + Utils::trimZeroLead(user_address);

            long long answer_offset;
            Utils::convertFromHex(data.substr(32 * 2, 32 * 2), answer_offset);
            long long answer_len;
            Utils::convertFromHex(data.substr(answer_offset * 2, 32 * 2), answer_len);

            std::string answer;
            Utils::convertFromHex(data.substr(answer_offset * 2 + 32*2, answer_len * 2), answer);
            result["answer"] = answer;

            long long doc_id_offset;
            Utils::convertFromHex(data.substr(32 * 4, 32 * 2), doc_id_offset);

            long long doc_id_len;
            Utils::convertFromHex(data.substr(doc_id_offset * 2, 32 * 2), doc_id_len);

            std::string doc_id;
            Utils::convertFromHex(data.substr(doc_id_offset * 2 + 32 * 2, doc_id_len * 2), doc_id);

            result["doc_id"] = doc_id;

        }
        return result;
    }

    nlohmann::json DealContract::ParseGetNumberOfKeyResult(nlohmann::json &in) {
        nlohmann::json result;
        if (in.count("result") == 1) {
            std::string data = in["result"];
            data = data.substr(2, data.length() - 2);

            long long amount;
            Utils::convertFromHex(data, amount);
            result["amount"] = amount;
        }
        return result;
    }

    nlohmann::json DealContract::ParseGetKey(nlohmann::json &in) {
        nlohmann::json result;
        if (in.count("result") == 1) {
            std::string data = in["result"];
            data = data.substr(2, data.length() - 2);

            std::string user_address = data.substr(0, 32 * 2);
            result["user_address"] = "0x" + Utils::trimZeroLead(user_address);

            long long doc_id_offset;
            Utils::convertFromHex(data.substr(32 * 2, 32 * 2), doc_id_offset);
            long long doc_id_len;
            Utils::convertFromHex(data.substr(doc_id_offset * 2, 32 * 2), doc_id_len);

            std::string doc_id;
            Utils::convertFromHex(data.substr(doc_id_offset * 2 + 32*2, doc_id_len * 2), doc_id);
            result["doc_id"] = doc_id;

            long long key_offset;
            Utils::convertFromHex(data.substr(32 * 4, 32 * 2), key_offset);

            long long key_len;
            Utils::convertFromHex(data.substr(key_offset * 2, 32 * 2), key_len);

            std::string key;
            Utils::convertFromHex(data.substr(key_offset * 2 + 32 * 2, key_len * 2), key);

            result["key"] = key;

            long long nonce_offset;
            Utils::convertFromHex(data.substr(32 * 6, 32 * 2), nonce_offset);

            long long nonce_len;
            Utils::convertFromHex(data.substr(nonce_offset * 2, 32 * 2), nonce_len);

            std::string nonce;
            Utils::convertFromHex(data.substr(nonce_offset * 2 + 32 * 2, nonce_len * 2), nonce);

            result["nonce"] = nonce;

        }
        return result;
    }

    OwnerKeyContract::FunctionDefinition OwnerKeyContract::functions_ = {
        {GET_PUB_KEY, "getPubKeyRSA(address)"},
        {GET_ALL_USER_KEY, "getAllUserKeyAddeds()"}
    };

    std::string OwnerKeyContract::GetFunctionHash(Functions def) {
        //get function hash
        CryptoPP::Keccak_256 keck_256;
        char* function_hash = new char [keck_256.DigestSize()];
        keck_256.CalculateDigest(reinterpret_cast <unsigned char*> (function_hash),
                                reinterpret_cast<const CryptoPP::byte*> (functions_[def].c_str()),
                                functions_[def].length());
        std::string result (function_hash, keck_256.DigestSize());
        delete[] function_hash;
        return result;
    }

    std::string OwnerKeyContract::GetFunctionABI(Functions def) {
        //get first 4 bytes
        std::string result (GetFunctionHash(def).c_str(), 4);
        return result;
    }

    std::string OwnerKeyContract::GetPubKey(std::string address) {
        std::string result;
        std::string function_hash = GetFunctionABI(Functions::GET_PUB_KEY);
        std::string abi = Utils::convertToHex(reinterpret_cast<const unsigned char*> (function_hash.c_str()),
                                              function_hash.length());

        if (address.length() > 2) {
            //get rid of "0x" from input address then pad it with 0
            address = Utils::zeroLeadPad(address.substr(2, address.length() - 2), 32 * 2);
            std::stringstream ss;
            ss << "0x" << abi << address;
            result = ss.str();
        }
        return result;
    }

    nlohmann::json OwnerKeyContract::ParseGetPubKeyResult(nlohmann::json &in) {
        nlohmann::json result;

        if (in.count("result") == 1) {
            std::string data = in["result"];
            data = data.substr(2, data.length() - 2);

            long long offset;
            Utils::convertFromHex(data.substr(0, 32 * 2), offset);

            long long len;
            Utils::convertFromHex(data.substr(32 * 2, 32 * 2), len);

            std::string key;
            Utils::convertFromHex(data.substr(32 * 4, len*2), key);

            result["key"] = key;
        }

        return result;
    }

    /*
     * Get All User Id on blockchain
     */
    std::string OwnerKeyContract::GetAllUserId() {
        std::string func_hash = GetFunctionABI(Functions::GET_ALL_USER_KEY);
        std::string abi_hash = Utils::convertToHex(reinterpret_cast<const unsigned char*> (func_hash.c_str()), func_hash.length());

        std::stringstream stream;
        stream << "0x"
               << abi_hash;
        return stream.str();
    }

    nlohmann::json OwnerKeyContract::ParseGetAllUserId(nlohmann::json& in) {
        nlohmann::json result;
        if (in.count("result") == 1) {
            std::string data = in["result"];
            data = data.substr(2, data.length() - 2);

            long long offset;
            Utils::convertFromHex(data.substr(0, 32*2), offset);
            std::cout << "DealContract::ParseGetAllUserKey offset " << offset << std::endl;

            long long len;
            Utils::convertFromHex(data.substr(32*2, 32 * 2), len);
            std::cout << "DealContract::ParseGetAllUserKey len " << len << std::endl;

            // add to array
            std::string public_key;
            for (int i = 1; i <= len; i++) {
                public_key = std::string("0x") + Utils::trimZeroLead(data.substr(32*(2 + 2*i), 32 * 2));
                std::cout << "DealContract::ParseGetAllUserKey public key content " << public_key << std::endl;
                result.push_back(public_key);
            }
        }

        return result;
    }

  }
}
