#include "accountmanager.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <QByteArray>
#include <cstdlib>
#include <bitset>

#define SOCKETIO_SERVER "https://192.168.1.167:3000"

AccountManager* AccountManager::getInstance() {
    static AccountManager* instance = NULL;

    if (instance == NULL) {
        instance = new AccountManager();
    }

    return instance;
}

AccountManager::AccountManager(QObject* parent): QObject(parent)
{
    username_ = "";
    password_ = "";

    secret_key_ = NULL;
    secret_key_len_ = 0;

    public_key_ = NULL;
    public_key_len_ = 0;

    // connect to file server
    // change if ip and port number is wrong
    socket_manager = new ZmqManager("localhost", "7777");

    /*std::map<std::string, std::string> config;
    config["secure"] = "true";
    config["agent"] = "https.globalAgent";*/

    proxy_socket_.connect(SOCKETIO_SERVER);
    if (proxy_socket_.opened())
        std::cout << "socket open " << std::endl;

    proxy_socket_.socket()->on("newDeal", std::bind( &AccountManager::onNewDealReply, this, std::placeholders::_1, std::placeholders::_2));
    proxy_socket_.socket()->on("newBidder", std::bind( &AccountManager::onNewBidder, this, std::placeholders::_1, std::placeholders::_2));

}

void AccountManager::onNewDealReply(const std::string& mes, sio::message::ptr const& data){
    qDebug() << QString(mes.c_str()) << " " << QString(data->get_string().c_str());
    if (QString(data->get_string().c_str()).compare(QString("OK")) == 0) {
        Q_EMIT newDealDone();
    }
}

void AccountManager::onNewBidder(const std::string& mess, sio::message::ptr const& data) {
    qDebug() << "onNewBidder " << QString(mess.c_str()) << " " << QString(data->get_string().c_str());
    if (QString(data->get_string().c_str()).compare(QString("OK")) == 0)
    {

    }
    else {
        std::string walletId = Config::getInstance()->getWalletAddress();
        std::string pk_hex = Utils::convertToHex(reinterpret_cast<unsigned char*> (this->sig_pub_key_), this->sig_pub_key_len_);
        std::string pri_hex = Utils::convertToHex(reinterpret_cast<unsigned char*> (this->sig_sec_key_), this->sig_sec_key_len_);

        std::cout << "rpi hex " << pri_hex << std::endl;
        std::cout << "pub hex " << pk_hex << std::endl;

        setSessionPublicKey(walletId, pk_hex);
    }
}

AccountManager::~AccountManager() {
    delete socket_manager;
}

void AccountManager::setPassword(std::string password) {
    password_ = password;
}

void AccountManager::setUsername(std::string username) {
    username_ = username;
}

bool AccountManager::authenticate() {
    if (username_ == "" || password_ == "") {
        return false;
    }

    std::string file_path = (QDir::currentPath() + "/keystore/" + QString(username_.c_str()) + ".key").toStdString();
    std::string passphrase = password_;

    if (!KeyManager::getKey(file_path, passphrase,
                            &this->secret_key_, this->secret_key_len_,
                            &this->public_key_, this->public_key_len_,
                            &this->sig_sec_key_, this->sig_sec_key_len_,
                            &this->sig_pub_key_, this->sig_pub_key_len_)) {
        qDebug() << "failed to get key";
        return false;
    }

    qDebug() << "success get key";
    qDebug() << "sec: " << QString(Utils::convertToBase64(reinterpret_cast<unsigned char*>(this->secret_key_), this->secret_key_len_).c_str());
    qDebug() << "public key: " << QString(Utils::convertToBase64(reinterpret_cast<unsigned char*> (this->public_key_), this->public_key_len_).c_str());
    return true;
}

void AccountManager::setSessionPublicKey(std::string& walletID, std::string publickey) {
    // try to connect to socket io server
    while(!proxy_socket_.opened()) {
        proxy_socket_.connect(SOCKETIO_SERVER);
    }

    // send public key
    nlohmann::json proxy_mess;
    proxy_mess["bidder"] = walletID;
    proxy_mess["publickey"] = publickey;

    std::string dump_mess = proxy_mess.dump();
    proxy_socket_.socket()->emit("newBidder", std::make_shared<std::string>(dump_mess.c_str(), dump_mess.length()));
}

bool AccountManager::registerNewUser() {
    QString folderContainKeys = QDir::currentPath() + "/keystore";

    // create folder contain key if not exists before
    Utils::createFolder(folderContainKeys.toStdString());

    //if it's ok then create key file
    std::string file_path = (folderContainKeys + "/" + QString(username_.c_str()) + ".key").toStdString();
    std::string passphrase = password_;

    if (!KeyManager::createKey(file_path, passphrase)) {
        return false;
    }

    if (!KeyManager::getKey(file_path, passphrase,
                            &this->secret_key_, this->secret_key_len_,
                            &this->public_key_, this->public_key_len_,
                            &this->sig_sec_key_, this->sig_sec_key_len_,
                            &this->sig_pub_key_, this->sig_pub_key_len_)) {
        qDebug() << "failed to get key";
        return false;
    }

    std::string walletId = Config::getInstance()->getWalletAddress();
    std::string pk_hex = Utils::convertToHex(reinterpret_cast<unsigned char*> (this->sig_pub_key_), this->sig_pub_key_len_);
    std::string pri_hex = Utils::convertToHex(reinterpret_cast<unsigned char*> (this->sig_sec_key_), this->sig_sec_key_len_);
    setSessionPublicKey(walletId, pk_hex);

    return true;
}

std::vector<std::string> AccountManager::getAllUserKey() {
    std::vector<std::string> rsa_keys(0);
    try {
        std::string blockchain_addr = "0xc3f59a489644a299fb16b712c5f295f96d6dc0c0"; // fake
        std::string blockchain_pass = "123"; // fake

        bool check = blockchain_.UnlockAccount(blockchain_addr, blockchain_pass, 30);

        deal_contract_addr_ = Config::getInstance()->getDealContractAddress();
        owner_key_addr_ = Config::getInstance()->getOwnerKeyContractAddress();

        std::string get_all_user_id_param = bitmile::blockchain::OwnerKeyContract::GetAllUserId();
        nlohmann::json result;
        blockchain_.SendCall(blockchain_addr, Config::getInstance()->getOwnerKeyContractAddress(), get_all_user_id_param, "1",  result);

        // parse result
        result = bitmile::blockchain::OwnerKeyContract::ParseGetAllUserId(result);
        std::string rsa_key_data;

        for (nlohmann::json::iterator i = result.begin(); i != result.end(); i++) {
            nlohmann::json get_RSA_PK_result;

            // get RSA public key from user_id
            rsa_key_data = bitmile::blockchain::OwnerKeyContract::GetPubKey(*i);
            blockchain_.SendCall(blockchain_addr, Config::getInstance()->getOwnerKeyContractAddress(), rsa_key_data, "1",  get_RSA_PK_result);

            get_RSA_PK_result = bitmile::blockchain::OwnerKeyContract::ParseGetPubKeyResult(get_RSA_PK_result);
            rsa_keys.push_back(get_RSA_PK_result["key"]);

            std::cout << "AccountManager::getAllUserKey public key  " << get_RSA_PK_result["key"]  << std::endl;
        }
    }
    catch (std::exception &e) {
        std::cout << "AccountManager::getAllUserKey have error " << e.what() << std::endl;
    }

    return rsa_keys;
}

void AccountManager::clearCredential(){
    username_ = "";
    password_ = "";

    secret_key_ = NULL;
    secret_key_len_ = 0;

    public_key_ = NULL;
    public_key_len_ = 0;
}

void AccountManager::addKeyword(std::string keyword) {
    //TODO: preprocessing keyword

    if (keywords_.find(keyword) != keywords_.end()) {
        return;
    }
    keywords_.insert(keyword);
    Q_EMIT keywords_array_changed();
}

void AccountManager::removeKeyword(std::string keyword) {
    std::set<std::string>::iterator pos = keywords_.find(keyword);

    if (pos != keywords_.end()) {
        keywords_.erase(pos);
        Q_EMIT keywords_array_changed();
    }
}

void AccountManager::clearKeywords() {
    keywords_.clear();
    Q_EMIT keywords_array_changed();
}

std::set<std::string> AccountManager::getKeywords() {
    return keywords_;
}

std::vector<bitmile::db::Document> AccountManager::getSearchedDoc() {
    return searched_docs_;
}
void AccountManager::search () {
    searched_docs_.clear();
    std::vector<std::string> result = this->getAllUserKey();

    std::cout << "AccountManager::search length " << result.size() << std::endl;

    // with each public key, encrypt and compare with file server
    std::vector<std::string> keywords;
    std::vector<bitmile::db::Document> searched_docs;

    for (std::vector<std::string>::iterator i = result.begin(); i != result.end(); i++) {
        if (*i == "")
            continue;

        searched_docs.clear();
        keywords.clear();

        BIO *bio = BIO_new_mem_buf(i->data(), i->length());
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        int rsa_key_size = RSA_size(rsa);

        for (std::set<std::string>::iterator j = keywords_.begin(); j != keywords_.end(); j++) {
            std::cout << "encrypt for key word " << j->data() << std::endl;

            std::vector<unsigned char> kw_input(rsa_key_size);
            memset(kw_input.data(), '0', rsa_key_size);
            memcpy(kw_input.data(), j->data(), j->length());

            std::vector<unsigned char> encrypted(rsa_key_size);

            RSA_public_encrypt(RSA_size(rsa),
                               reinterpret_cast<const unsigned char*>(kw_input.data()),
                               reinterpret_cast<unsigned char*>(encrypted.data()),
                               rsa, RSA_NO_PADDING);

            std::cout << "base64 after encript " << QByteArray(reinterpret_cast<char*>(encrypted.data()), encrypted.size()).toBase64().data() << std::endl;

            std::string encrypt_base64;
            encrypt_base64 = Utils::convertToBase64(reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size());

            keywords.push_back(encrypt_base64);
        }

        socket_manager->search(keywords, searched_docs);
        for(std::vector<bitmile::db::Document>::iterator k = searched_docs.begin(); k != searched_docs.end(); k++) {
            std::cout << "have result doc searched " << std::endl;

            // encrypt docid with owner publickey
            std::string docidEncrypt = encryptData(*i, k->GetOwnerDocId());
            k->SetOwnerDocId(docidEncrypt);

            searched_docs_.push_back(*k);
        }

        // clear openssl context
        RSA_free(rsa);
        BIO_free(bio);
    }

    if (searched_docs_.size() > 0) {

    }

    Q_EMIT search_done();
}

std::string AccountManager::encryptData(std::string publickey, std::string data) {
    BIO *bio = BIO_new_mem_buf(publickey.data(), publickey.length());
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    int rsa_key_size = RSA_size(rsa);

    std::vector<unsigned char> kw_input(rsa_key_size);
    memset(kw_input.data(), '0', rsa_key_size);
    memcpy(kw_input.data(), data.data(), data.length());

    std::vector<unsigned char> encrypted(rsa_key_size);

    RSA_public_encrypt(RSA_size(rsa),
                       reinterpret_cast<const unsigned char*>(kw_input.data()),
                       reinterpret_cast<unsigned char*>(encrypted.data()),
                       rsa, RSA_NO_PADDING);

    std::cout << "base64 after encript " << QByteArray(reinterpret_cast<char*>(encrypted.data()), encrypted.size()).toBase64().data() << std::endl;

    std::string encrypt_base64;
    encrypt_base64 = Utils::convertToBase64(reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size());

    // clear openssl context
    RSA_free(rsa);
    BIO_free(bio);

    return encrypt_base64;
}

std::string AccountManager::decryptData(std::string privateKey, std::string data) {
    BIO *bio = BIO_new_mem_buf(privateKey.c_str(), privateKey.length());
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    std::cout << "AccountManager decryptData " << rsa << std::endl;

    int rsa_key_size = RSA_size(rsa);

    std::vector<unsigned char> kw_input(rsa_key_size);
    memset(kw_input.data(), '0', rsa_key_size);
    memcpy(kw_input.data(), data.data(), data.length());

    std::vector<unsigned char> decrypted(rsa_key_size);

    RSA_public_decrypt(RSA_size(rsa),
                       reinterpret_cast<const unsigned char*>(kw_input.data()),
                       reinterpret_cast<unsigned char*>(decrypted.data()),
                       rsa, RSA_NO_PADDING);
    // clear openssl context
    RSA_free(rsa);
    BIO_free(bio);

    return std::string(decrypted.data(), decrypted.data() + decrypted.size());
}

bool AccountManager::createDeal(std::string blockchain_addr, std::string blockchain_pass, long long prize, QDateTime expiredTime, int &new_deal_id) {
    try {
        qDebug() << "create deal";

        bool check = blockchain_.UnlockAccount(blockchain_addr, blockchain_pass, 30);

        std::string latest_block;

        deal_contract_addr_ = Config::getInstance()->getDealContractAddress();
        owner_key_addr_ = Config::getInstance()->getOwnerKeyContractAddress();

        std::string transaction_hash;
        if (check) {
            std::string create_deal_param = bitmile::blockchain::DealContract::CreateDeal(prize, expiredTime.toSecsSinceEpoch(), std::string (public_key_, public_key_len_));
            std::cout << "create_deal_param " << create_deal_param << std::endl;

            nlohmann::json result;

            blockchain_.GetBlockNumber("1", result);
            latest_block = result["result"];

            blockchain_.EstimateGas(blockchain_addr, deal_contract_addr_, "0x0", "0x0", create_deal_param, "1", result);

            std::string gas = result["result"];
            blockchain_.SendTransaction(blockchain_addr, deal_contract_addr_, "0x0", gas, create_deal_param, "1", result);

            transaction_hash = result["result"];

            check &= (transaction_hash != "");
        }

        //get dealId
        long long dealId = 0;
        if (check) {
            nlohmann::json result;
            std::vector<std::string> topics;

            std::string topic_hash_str = bitmile::blockchain::DealContract::GetFunctionHash(
                        bitmile::blockchain::DealContract::Functions::LOG_DEAL_CREATED);

            topics.push_back("0x" + Utils::convertToHex(reinterpret_cast<unsigned const char*> (topic_hash_str.c_str()), topic_hash_str.length()));

            int log_count = 0;
            //wait for 1 second before get log

            //sleep (1000);
            int retries = 0;

            while (log_count < 1) {
                if (blockchain_.Createfilter (latest_block, "latest", deal_contract_addr_, topics,"1", result)) {
                    std::string log_id = result["result"];
                    result.clear();
                    blockchain_.GetFilterLogs(log_id, "1", result);

                    nlohmann::json log = bitmile::blockchain::DealContract::ParseLogCreateDeal(result);

                    for (nlohmann::json::iterator it = log.begin(); it != log.end(); it++) {
                        if ((*it)["transactionHash"] == transaction_hash) {
                            dealId = (*it)["data"]["dealId"];
                            new_deal_id = dealId;
                            log_count++;
                        }
                    }
                }
            }

            check &= (log_count == 1);

        }

        //send dealId and user list to proxy server
        if (check) {
            nlohmann::json data;
            data["dealId"] = dealId;
            data["bidder"] = blockchain_addr;

            std::vector<std::string> owner_arr,
                                     doc_id_arr;
            for (int i = 0; i < searched_docs_.size(); i++) {

                std::string owner_addr = searched_docs_[i].GetOwnerAddress();

                //get owner pub key
                std::string get_key = bitmile::blockchain::OwnerKeyContract::GetPubKey(owner_addr);
                nlohmann::json result;

                if (!blockchain_.SendCall(blockchain_addr, owner_key_addr_, get_key, "1", result)) {
                    //failed to get owner key
                    continue;
                }

                nlohmann::json key_json = bitmile::blockchain::OwnerKeyContract::ParseGetPubKeyResult(result);
                //get public key here
                std::string owner_key;
                Utils::convertFromHex(key_json["key"], owner_key);

                //TODO: use owner_key to encrypt doc id
                std::string doc_id_encrypted = searched_docs_[i].GetOwnerDocId();

                owner_arr.push_back(owner_addr);
                doc_id_arr.push_back(doc_id_encrypted);
            }
            data["userIds"] = nlohmann::json (owner_arr);
            data["listEncDocIds"] = nlohmann::json (doc_id_arr);
            data["complete"] = "1";

            std::string mes = data.dump();

            char* sig = new char[crypto_sign_BYTES];

            if(crypto_sign_detached(reinterpret_cast<unsigned char*> (sig), NULL,
                                     reinterpret_cast<const unsigned char*> (mes.c_str()),
                                     mes.length(),
                                     reinterpret_cast<unsigned char*> (sig_sec_key_)) == 0) {
                nlohmann::json proxy_mes_json;

                //success sign
                proxy_mes_json["data"] = mes;

                std::string sig_string (sig, crypto_sign_BYTES);
                proxy_mes_json["signature"] = Utils::convertToHex(reinterpret_cast<const unsigned char*> (sig_string.c_str()),
                                                                  sig_string.length());
                //convert json to std::string
                std::string proxy_mes = proxy_mes_json.dump();

                //TODO: send to lists to proxy server
                proxy_socket_.socket()->emit("newDeal", std::make_shared<std::string>(proxy_mes.c_str(), proxy_mes.length()));
                std::cout << "snd list to proxy success \n" << proxy_mes << "\n" << std::endl;
            }else{
                check = false;
            }

            delete [] sig;
        }
        return check;
    } catch (std::exception e) {
        std::cout << "AccountManager::createDeal throw exception " << e.what() << std::endl;
    }
}

bool AccountManager::payForRequestKey(unsigned long long deal_id) {
    InternalDB* db = InternalDB::getInstance();

    InternalDB::Deal deal = db->getDeal(deal_id);

    // if deal_id and timestamp is empty, so have error occurs when query from db
    if (deal.deal_id == 0 && deal.time == 0)
        return false;


    // get dealOwner
    std::vector<InternalDB::DealOwner> dealOwners = db->getDealOwner(deal.time, InternalDB::DEALOWNER_STATUS_VAL_ACCEPT);
    std::cout << "length of dealOwner have status is Accept " << dealOwners.size() << std::endl;

    // not continues process if dealOwner size if empty
    if (dealOwners.size() == 0)
        return true;

    // group keys from dealOwner
    std::vector<std::string> dealOwnerKeys;

    for (std::vector<InternalDB::DealOwner>::iterator i = dealOwners.begin(); i != dealOwners.end(); i++)
        dealOwnerKeys.push_back(i->owner_address.toStdString());

    bool check = blockchain_.UnlockAccount(Config::getInstance()->getWalletAddress(), Config::getInstance()->getPassPharse(), 30);

    std::string latest_block;

    deal_contract_addr_ = Config::getInstance()->getDealContractAddress();
    owner_key_addr_ = Config::getInstance()->getOwnerKeyContractAddress();

    std::string transaction_hash;
    if (check) {
        qreal price_for_pay = deal.price * dealOwners.size();

        // convert price value to hex
        std::string price_str = QString("%1").arg(price_for_pay).toStdString();
        price_str = Utils::convertToHex(reinterpret_cast<const unsigned char*>(const_cast<const char*>(price_str.data())), price_str.length());

        std::stringstream price_stream;
        price_stream << "0x" << price_str;

        nlohmann::json result;

        // create transaction
        std::string transaction_str = bitmile::blockchain::DealContract::PayForKey(deal_id, dealOwnerKeys);

        blockchain_.GetBlockNumber("1", result);
        latest_block = result["result"];

        blockchain_.EstimateGas(Config::getInstance()->getWalletAddress(), deal_contract_addr_, "0x0", "0x0", transaction_str, "1", result);

        std::string gas = result["result"];
        blockchain_.SendTransaction(Config::getInstance()->getWalletAddress(), deal_contract_addr_, price_stream.str(), gas, transaction_str, "1", result);

        transaction_hash = result["result"];

        std::cout << "transaction has result " << result.dump() << std::endl;

        check &= (transaction_hash != "");
    }

    // update to DB
    if (check) {
        deal.payment_status = DEAL_PAYMENT_SUCCESSED;
        check &= InternalDB::getInstance()->updateDealData(deal);
    }

    return check;
}

bool AccountManager::updateDocDecrypt(unsigned long long deal_id) {
    InternalDB* db = InternalDB::getInstance();

    InternalDB::Deal deal = db->getDeal(deal_id);

    // if deal_id and timestamp is empty, so have error occurs when query from db
    if (deal.deal_id == 0 && deal.time == 0)
        return false;

    try {
        std::string blockchain_addr = Config::getInstance()->getWalletAddress();
        std::string blockchain_pass = Config::getInstance()->getPassPharse();

        bool check = blockchain_.UnlockAccount(blockchain_addr, blockchain_pass, 30);

        deal_contract_addr_ = Config::getInstance()->getDealContractAddress();
        owner_key_addr_ = Config::getInstance()->getOwnerKeyContractAddress();

        std::string get_all_user_id_param = bitmile::blockchain::DealContract::GetNumberOfKey(deal_id);
        std::cout << "get_num_of_key hex " << get_all_user_id_param << std::endl;

        nlohmann::json result;
        blockchain_.SendCall(blockchain_addr, Config::getInstance()->getDealContractAddress(), get_all_user_id_param, "1",  result);

        // parse result
        result = bitmile::blockchain::DealContract::ParseGetNumberOfKeyResult(result);
        std::cout << result.dump() << std::endl;

        int amount = result["amount"].get<int>();

        std::string rsa_key_data_req;

        for (int i = 0; i < amount; i++) {
            nlohmann::json answer;

            // get RSA public key from user_id
            rsa_key_data_req = bitmile::blockchain::DealContract::GetKey(deal_id, i);
            blockchain_.SendCall(blockchain_addr, Config::getInstance()->getDealContractAddress(), rsa_key_data_req, "1",  answer);

            answer = bitmile::blockchain::DealContract::ParseGetKey(answer);

            std::cout << "full rsa infor " << answer.dump() << std::endl;

            // decrypt secret key and nonce key
            std::vector<unsigned char> decrypt_data(2048);
            memset(decrypt_data.data(), '\0', decrypt_data.size());

            std::string pk = getPublicKeyBin();
            std::string sk = getSecretKeyBin();

            std::string encrypt_sk_key_bin;
            std::string encrypt_nonce_key_bin;
            //std::strining raw_encrypt_doc_data;

            Utils::convertFromHex(answer["key"], encrypt_sk_key_bin);
            Utils::convertFromHex(answer["nonce"], encrypt_nonce_key_bin);
            //Utils::convertFromHex(answer["doc_id"]);

            std::string owner_sk;
            std::string owner_nonce;

            // for decrypt owner sk key
            {
                if (crypto_box_seal_open(reinterpret_cast<unsigned char*>(decrypt_data.data()),
                                         reinterpret_cast<unsigned char*>(const_cast<char*>(encrypt_sk_key_bin.data())),
                                         encrypt_sk_key_bin.length(),
                                         reinterpret_cast< unsigned char*>(const_cast<char*>(pk.data())),
                                         reinterpret_cast< unsigned char*>(const_cast<char*>(sk.data()))) != 0) {
                    /* message corrupted or not intended for this recipient */
                    std::cout << "decrypt_key message corrupted or not intended for this recipient " << std::endl;
                    continue;
                }

                owner_sk = std::string(reinterpret_cast<char*>(decrypt_data.data()));

                // reset decrypt key
                memset(decrypt_data.data(), '\0', owner_sk.size());
            }

            // for decrypt nonce key
            {
                if (crypto_box_seal_open(reinterpret_cast<unsigned char*>(decrypt_data.data()),
                                         reinterpret_cast<unsigned char*>(const_cast<char*>(encrypt_nonce_key_bin.data())),
                                         encrypt_nonce_key_bin.length(),
                                         reinterpret_cast< unsigned char*>(const_cast<char*>(pk.data())),
                                         reinterpret_cast< unsigned char*>(const_cast<char*>(sk.data()))) != 0) {
                    /* message corrupted or not intended for this recipient */
                    std::cout << "decrypt_nonce message corrupted or not intended for this recipient " << std::endl;
                    continue;
                }

                owner_nonce = std::string(reinterpret_cast<char*>(decrypt_data.data()));

                // reset decrypt key
                memset(decrypt_data.data(), '\0', owner_nonce.size());
            }

            // get DealOwner from owner address and DocId
            InternalDB::DealOwner dealOwner = db->getDealOwner(QString::fromStdString(answer["user_address"]));


            if (dealOwner.owner_doc_id.isEmpty() || dealOwner.owner_address.isEmpty())
                continue;

            // decrypt data
            std::string doc_data_base64 = answer["doc_id"].get<std::string>();

            // get data from file server
            bitmile::db::Document dealOwner_db;
            socket_manager->getData(dealOwner.elastic_id.toStdString(), dealOwner_db);

            std::string raw_doc_data = Utils::convertFromB64ToBin(doc_data_base64.data(), doc_data_base64.length());
            std::cout << "raw doc data " << raw_doc_data << std::endl;

            unsigned long long decrypted_len = 0;

            std::cout << "sk length " << owner_sk.length() << std::endl;
            std::cout << "real sk length " << crypto_aead_xchacha20poly1305_ietf_KEYBYTES << std::endl;

            std::cout << "nonce length " << owner_nonce.length() << std::endl;
            std::cout << "real nonce length " << crypto_aead_xchacha20poly1305_ietf_NPUBBYTES << std::endl;

            //std::string owner_nonce_key_hex = Utils::convertToHex(reinterpret_cast<unsigned char*>(const_cast<char*>(owner_nonce.data())), owner_nonce.length());
            //std::string owner_sk_hex= Utils::convertToHex(reinterpret_cast<unsigned char*>(const_cast<char*>(owner_sk.data())), owner_sk.length());

            std::string owner_nonce_key_base64 = Utils::convertToBase64(reinterpret_cast<unsigned char*>(const_cast<char*>(owner_nonce.data())), owner_nonce.length());
            std::string owner_sk_64= Utils::convertToBase64(reinterpret_cast<unsigned char*>(const_cast<char*>(owner_sk.data())), owner_sk.length());

            std::cout << "owner_sk_key_hex " << owner_sk_64 << std::endl;
            std::cout << "owner_nonce_hex " << owner_nonce_key_base64 << std::endl;

            //std::cout << "owner_sk_key_hex " << owner_sk_hex << std::endl;
            //std::cout << "owner_nonce_hex " << owner_nonce_key_hex << std::endl;

            // test
            std::string fserver_key_base64 = "M4mKWCmS6hlLOk92AjfVR9oDwFVDwXAqqDJcLyitWGw=";
            std::string fserver_nonce_base64 = "KCOTMhjfVJ0k4/4C9KC53cq0Se5VLb7G";

            owner_nonce = Utils::convertFromB64ToBin(fserver_nonce_base64.data(), fserver_nonce_base64.length());
            owner_sk    = Utils::convertFromB64ToBin(fserver_key_base64.data(), fserver_key_base64.length());

            std::cout << "leng of owner nonce " << owner_nonce.length() << std::endl;
            std::cout << "leng of owner_sk  " << owner_sk.length() << std::endl;

            if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*> (decrypt_data.data()),
                                                               &decrypted_len,
                                                               NULL,
                                                               reinterpret_cast<unsigned char*>(const_cast<char*>(raw_doc_data.data())),
                                                               raw_doc_data.size(),
                                                               NULL,
                                                               0,
                                                               reinterpret_cast<unsigned char*>(const_cast<char*>(owner_nonce.data())),
                                                               reinterpret_cast<unsigned char*>(const_cast<char*>(owner_sk.data()))) != 0) {

                 /*message corrupted or not intended for this recipient*/
                std::cout << "message corrupted or not intended for this recipient " << std::endl;
                continue;
            }
            else {
                std::string res_data(reinterpret_cast<char*>(decrypt_data.data()));
                std::cout << "res doc data result in string " << res_data << std::endl;
            }
        }
    }
    catch (std::exception &e) {
        std::cout << "AccountManager::updateDocDecrypt have error " << e.what() << std::endl;
    }
    return true;
}

QString AccountManager::getSecretKey () const {
    return QString(Utils::convertToBase64(reinterpret_cast<unsigned char*>(this->secret_key_), this->secret_key_len_).c_str());
}


QString AccountManager::getPublicKey () const{
    return QString(Utils::convertToBase64(reinterpret_cast<unsigned char*> (this->public_key_), this->public_key_len_).c_str());
}

QString AccountManager::getUsername() const {
    return QString::fromStdString(username_);
}

QString AccountManager::getPassword() const {
    return QString::fromStdString(password_);
}

