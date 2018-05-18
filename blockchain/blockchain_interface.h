#ifndef _BLOCKCHAIN_INTERFACE_
#define _BLOCKCHAIN_INTERFACE_

#include "curl_easy.h"
#include "curl_exception.h"
#include "nlohmann/json.hpp"
#include "utils/utils.h"
#include <keccak.h>

#include <sstream>
#include <string>
#include <map>

namespace bitmile {
  namespace blockchain {
    class BlockchainInterface {

    public:
      enum RPC_API {
        UNLOCK_ACCOUNT,
        CALL,
        SEND_TRANSACTION,
        ESTIMATE_GAS,
        CREATE_FILTER,
        GET_FILTER_LOGS,
        GET_BLOCK_NUMBER
      };

      typedef std::map<RPC_API, std::string> ApiDef;

      static ApiDef api_def_;

      BlockchainInterface ();
      bool UnlockAccount (std::string account, std::string passphrase, int time);

      bool SendTransaction(std::string sender, std::string receiver, std::string value, std::string gas, std::string data, std::string id, nlohmann::json& result);
      bool SendCall (std::string sender, std::string receiver, std::string data, std::string id, nlohmann::json& result);
      bool EstimateGas (std::string sender, std::string receiver, std::string value, std::string gas, std::string data, std::string id, nlohmann::json& result);
      bool Createfilter (std::string fromBlock, std::string toBlock, std::string address, std::vector<std::string> topics, std::string id, nlohmann::json& result);
      bool GetFilterLogs (std::string filter, std::string id, nlohmann::json& result);
      bool GetBlockNumber (std::string id, nlohmann::json& result);
    private:
      static size_t CurlWriteCallbackStdString (void *contents, size_t size, size_t nmemb, void *s);
      nlohmann::json CreateMessage (std::string method, nlohmann::json params, std::string id);

      curl::curl_easy curl_;
    };


    struct DealContract {
      enum Functions {
        CREAT_DEAL,
        GET_ANSWER_NUMB,
        GET_ANSWER,
        PAY_FOR_KEY,
        GET_KEY_NUMB,
        GET_KEY,
        LOG_DEAL_CREATED
      };

      typedef std::map<Functions, std::string> FunctionDefinition;

      static FunctionDefinition functions_;

      static std::string GetFunctionHash (Functions def);
      static std::string GetFunctionABI (Functions def);
      static std::string CreateDeal (unsigned long long prize, unsigned long long expired_time, std::string public_key);
      static std::string GetNumberOfAnswer (unsigned long long deal_id);
      static std::string GetAnswer (unsigned long long deal_id, unsigned long long index);
      static std::string PayForKey (unsigned long long deal_id, std::vector<std::string> users);
      static std::string GetNumberOfKey (unsigned long long deal_id);
      static std::string GetKey (unsigned long long deal_id, unsigned long long index);

      //parse log
      static nlohmann::json ParseGetNumberOfKeyResult(nlohmann::json& in);
      static nlohmann::json ParseGetKey (nlohmann::json& in);
      static nlohmann::json ParseLogCreateDeal (nlohmann::json& log);
      static nlohmann::json ParseGetNumberOfAnswerResult (nlohmann::json& in);
      static nlohmann::json ParseGetAnswer (nlohmann::json& in);
    };

    struct OwnerKeyContract {
        enum Functions{
            GET_PUB_KEY,
            GET_ALL_USER_KEY
        };

        typedef std::map<Functions, std::string> FunctionDefinition;

        static FunctionDefinition functions_;

        static std::string GetFunctionHash (Functions def);
        static std::string GetFunctionABI (Functions def);
        static std::string GetPubKey (std::string address);
        static std::string GetAllUserId();

        static nlohmann::json ParseGetPubKeyResult (nlohmann::json& in);
        static nlohmann::json ParseGetAllUserId(nlohmann::json& in);
    };

  }//namespace blockchain
}//namespace bitmile

#endif
