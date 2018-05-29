#ifndef ZMQ_MANAGER_H
#define ZMQ_MANAGER_H

#include "zmq.hpp"
#include "message/message.h"
#include "database/db_interface.h"
#include "utils/utils.h"
#include <QDebug>

extern "C" {
#include "sodium.h"
}

#include <fstream>
#include <assert.h>

class ZmqManager
{
public:
    ZmqManager(std::string host_address, std::string host_port);
    ~ZmqManager();

    void search (std::vector<std::string>& keywords,
                 std::vector<bitmile::db::Document>& result);

    void getData(std::string elastic_id, bitmile::db::Document& result);

private:
    bool initConnection(std::string host_address, std::string host_port);
    bool sendMessage (const char* dat, size_t size, std::vector<char>& reply);
    void setupSecureConnection  ();

private:

    std::string host_address_;
    std::string host_port_;

    zmq::context_t* context_;
    zmq::socket_t* socket_;

    bitmile::msg::MessageFactory mes_factory_;
    //encryption atribute
    std::vector<char> sec_key_;
    std::vector<char> nonce_;
    std::vector<char> host_public_key_;
};

#endif // ZMQ_MANAGER_H
