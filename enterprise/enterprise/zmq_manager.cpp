#include "zmq_manager.h"

ZmqManager::ZmqManager(std::string host_address, std::string port)
{
    context_ = new zmq::context_t(1);
    socket_ = new zmq::socket_t(*context_, ZMQ_REQ);

    host_address_ = host_address;
    host_port_ = port;

    //read server public key here

    std::ifstream fin ("server_public_key.key", std::ios::binary | std::ios::ate);
    assert (fin.is_open());
    //read file
    std::streamsize file_len = fin.tellg();
    fin.seekg(0, std::ios::beg);
    host_public_key_.resize (file_len);

    fin.read(host_public_key_.data(), file_len);

    initConnection(host_address, port);
    setupSecureConnection();
}

ZmqManager::~ZmqManager(){
    delete context_;
    delete socket_;
}

bool ZmqManager::initConnection(std::string host_address, std::string port) {
    //disconect from current session first

    //create address;
    std::string address= std::string("tcp://") + host_address + ":" + port;
    socket_->setsockopt(ZMQ_SNDTIMEO, 1000);
    socket_->connect(address);

    return socket_->connected();
}

bool ZmqManager::sendMessage(const char *dat, size_t size, std::vector<char>& reply) {
    zmq::message_t req (size);
    memcpy(req.data(), dat, size);

    int return_code = socket_->send(req);
    if (return_code == EAGAIN) {
        //time out
        return false;
    }

    zmq::message_t reply_mes;
    socket_->recv (&reply_mes);

    reply.resize(reply_mes.size());
    memcpy(reply.data(), reply_mes.data(), reply_mes.size());

    return true;
}

void ZmqManager::search(std::vector<std::string>& keywords,
                        std::vector<bitmile::db::Document>& results) {
    if (sec_key_.size() <= 0) {
        return;
    }

    //create search with keyword message
    bitmile::msg::KeywordQueryMes queryMes;
    queryMes.SetKeywords(keywords);

    std::vector <char> mes_data;

    std::vector <char> queryMesDat;
    queryMes.Serialize(queryMesDat);

    std::cout << "send: " << queryMesDat.size() << std::endl;
    //encrypt data
    unsigned long long ciphertext_len = queryMesDat.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<unsigned char> ciphertext;
    ciphertext.resize(ciphertext_len);
    qDebug() << "key: " << QString(Utils::convertToBase64(reinterpret_cast<unsigned char* > (sec_key_.data()), sec_key_.size()).c_str());
    qDebug() << "nonce: " << QString (Utils::convertToBase64(reinterpret_cast <unsigned char* > (nonce_.data()), nonce_.size()).c_str());
    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len,
                                               reinterpret_cast<unsigned char*> (queryMesDat.data()),
                                               queryMesDat.size(),
                                               NULL, 0,
                                               NULL,
                                               reinterpret_cast<unsigned char*> (nonce_.data()),
                                               reinterpret_cast<unsigned char*> (sec_key_.data()));


    //create request message

    mes_data.resize(sizeof (bitmile::msg::MessageType) + ciphertext_len);
    bitmile::msg::MessageType type = bitmile::msg::MessageType::KEYWORD_QUERY;
    memcpy (mes_data.data(), &type, sizeof (bitmile::msg::MessageType));
    int offset = sizeof (bitmile::msg::MessageType);
    memcpy(mes_data.data() + offset, ciphertext.data(), ciphertext_len);

    //send message to server
    std::vector <char> reply_data;
    sendMessage(mes_data.data(), mes_data.size(), reply_data);

    //parse reply
    if (reply_data.size() < sizeof (bitmile::msg::MessageType)) {
        return;
    }

    type = bitmile::msg::MessageType::BLANK;
    memcpy(&type, reply_data.data(), sizeof (bitmile::msg::MessageType));

    offset = sizeof (bitmile::msg::MessageType);

    //decrypt reply
    unsigned long long decrypted_len = 0;
    std::vector<char> raw_reply;
    raw_reply.resize (reply_data.size());
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*> (raw_reply.data()),
                                                   &decrypted_len,
                                                   NULL,
                                                   reinterpret_cast<unsigned char*>(reply_data.data() + offset),
                                                   reply_data.size() - offset,
                                                   NULL,
                                                   0,
                                                   reinterpret_cast<unsigned char*>(nonce_.data()),
                                                   reinterpret_cast<unsigned char*>(sec_key_.data())) == 0) {
          std::cout << "search keyword decrypted length " << decrypted_len << std::endl;
          raw_reply.resize (decrypted_len);
    }else {
        qDebug() << "failed to debug";
        return;
    }

    bitmile::msg::Message* reply_mes =
            mes_factory_.CreateMessage(type,
                                       raw_reply.data(),
                                       raw_reply.size());

    std::cout << "ZmqManager::search " << type << endl;

    if (reply_mes->Type() == bitmile::msg::MessageType::KEYWORD_QUERY_REPLY) {
        //success get result
        bitmile::msg::KeywordQueryReplyMes* keyword_reply = (bitmile::msg::KeywordQueryReplyMes*) reply_mes;
        results = std::vector<bitmile::db::Document> (keyword_reply->GetDocs());
    }

    delete reply_mes;
    return;
}

void ZmqManager::getData(std::string elastic_id, bitmile::db::Document& result) {
    if (sec_key_.size() <= 0 || elastic_id.empty()) {
        return;
    }

    //create search with keyword message
    nlohmann::json deserialize_data;
    deserialize_data["elastic_id"] = elastic_id;
    std::string dump = deserialize_data.dump();

    bitmile::msg::DocQueryMes queryMes(bitmile::msg::DOC_QUERY, dump.data(), dump.length());

    std::vector <char> mes_data;

    std::vector <char> queryMesDat;
    queryMes.Serialize(queryMesDat);

    //encrypt data
    unsigned long long ciphertext_len = queryMesDat.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;

    std::vector<unsigned char> ciphertext;
    ciphertext.resize(ciphertext_len);
    qDebug() << "key: " << QString(Utils::convertToBase64(reinterpret_cast<unsigned char* > (sec_key_.data()), sec_key_.size()).c_str());
    qDebug() << "nonce: " << QString (Utils::convertToBase64(reinterpret_cast <unsigned char* > (nonce_.data()), nonce_.size()).c_str());

    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len,
                                               reinterpret_cast<unsigned char*> (queryMesDat.data()),
                                               queryMesDat.size(),
                                               NULL, 0,
                                               NULL,
                                               reinterpret_cast<unsigned char*> (nonce_.data()),
                                               reinterpret_cast<unsigned char*> (sec_key_.data()));


    //create request message
    mes_data.resize(sizeof (bitmile::msg::MessageType) + ciphertext_len);
    bitmile::msg::MessageType type = bitmile::msg::MessageType::DOC_QUERY;
    memcpy (mes_data.data(), &type, sizeof (bitmile::msg::MessageType));

    int offset = sizeof (bitmile::msg::MessageType);
    memcpy(mes_data.data() + offset, ciphertext.data(), ciphertext_len);

    //send message to server
    std::vector <char> reply_data;
    sendMessage(mes_data.data(), mes_data.size(), reply_data);

    //parse reply
    if (reply_data.size() < sizeof (bitmile::msg::MessageType)) {
        return;
    }

    type = bitmile::msg::MessageType::BLANK;
    memcpy(&type, reply_data.data(), sizeof (bitmile::msg::MessageType));

    offset = sizeof (bitmile::msg::MessageType);

    //decrypt reply
    unsigned long long decrypted_len = 0;
    std::vector<char> raw_reply;
    raw_reply.resize (reply_data.size());

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*> (raw_reply.data()),
                                                   &decrypted_len,
                                                   NULL,
                                                   reinterpret_cast<unsigned char*>(reply_data.data() + offset),
                                                   reply_data.size() - offset,
                                                   NULL,
                                                   0,
                                                   reinterpret_cast<unsigned char*>(nonce_.data()),
                                                   reinterpret_cast<unsigned char*>(sec_key_.data())) == 0) {
        raw_reply.resize (decrypted_len);
    }else {
        qDebug() << "failed to debug";
        return;
    }

    bitmile::msg::Message* reply_mes =
            mes_factory_.CreateMessage(type,
                                       raw_reply.data(),
                                       raw_reply.size());

    std::cout << "DocHandleRequest successed " << reply_mes->Type() << std::endl;


    if (reply_mes->Type() == bitmile::msg::MessageType::DOC_QUERY_REPLY) {
        //success get result
        bitmile::msg::DocQueryReplyMes* keyword_reply = (bitmile::msg::DocQueryReplyMes*) reply_mes;
        result = keyword_reply->getDoc();
        std::cout << "parse success " << result.ToJson().dump() << std::endl;
    }

    delete reply_mes;
    return;
}

void ZmqManager::setupSecureConnection() {
    //check if server public key is valid
    if (host_public_key_.size() <= 0) {
        std::cout << "host public key not found" << std::endl;
        return;
    }

    //gen key and send it to server

    sec_key_.resize(crypto_aead_xchacha20poly1305_IETF_KEYBYTES);
    nonce_.resize(crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);

    crypto_aead_xchacha20poly1305_ietf_keygen(reinterpret_cast<unsigned char*>(sec_key_.data()));

    randombytes_buf(nonce_.data(), crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);

    //encode nonce and key to base 64
    std::string sec_key_b64 = Utils::convertToBase64(reinterpret_cast<unsigned char*> (sec_key_.data()),
                                                     sec_key_.size());
    std::string nonce_b64 = Utils::convertToBase64(reinterpret_cast<unsigned char*> (nonce_.data())
                                                   , nonce_.size());

    nlohmann::json secure_dat;
    secure_dat["key"] = sec_key_b64;
    secure_dat["nonce"] = nonce_b64;

    std::string secure_dat_str = secure_dat.dump();


    unsigned long long ciphertext_len = secure_dat_str.length() + crypto_box_SEALBYTES;
    std::vector<unsigned char> ciphertext;
    ciphertext.resize(ciphertext_len);


    //encrypt doc
    crypto_box_seal(ciphertext.data(), reinterpret_cast<const unsigned char*> (secure_dat_str.c_str()),
                    secure_dat_str.length(), reinterpret_cast<const unsigned char*>(host_public_key_.data()));

    //put encrypted doc to message data
    bitmile::msg::MessageType type = bitmile::msg::MessageType::SET_ENCRYPT_KEY;

    std::vector<char> mes_data;
    mes_data.resize(ciphertext_len + sizeof type);
    int offset = 0;
    memcpy (mes_data.data(), &type, sizeof type);
    offset += sizeof type;

    memcpy (mes_data.data() + offset, ciphertext.data(), ciphertext_len);

    std::vector<char> reply;
    sendMessage(mes_data.data(), mes_data.size(), reply);

}
