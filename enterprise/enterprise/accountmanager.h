#ifndef MainwindowController_H
#define MainwindowController_H

#include "keymanager.h"
#include "database/db_interface.h"
#include "message/message.h"
#include "zmq_manager.h"
#include "utils/utils.h"
#include "blockchain/blockchain_interface.h"
#include "config.h"

#include <sio_client.h>
#include <QDir>
#include <QDebug>
#include <QString>
#include <QObject>
#include <QDateTime>

#include <string>
#include <vector>
#include <set>
#include <functional>

class AccountManager : public QObject
{
    Q_OBJECT

public:
    AccountManager(QObject* parent = 0);

    static AccountManager* getInstance();
    //authentication function
    void setUsername (std::string username);
    void setPassword (std::string password_);
    bool authenticate ();
    bool registerNewUser ();
    void clearCredential ();
    std::vector<std::string> getAllUserKey();

    //new deal function
    void addKeyword (std::string keyword);
    void removeKeyword (std::string keyword);
    void clearKeywords();
    std::set<std::string> getKeywords();
    std::vector<bitmile::db::Document> getSearchedDoc();
    void search ();

    void setSessionPublicKey(std::string& walletID, std::string publickey);
    void onNewDealReply(const std::string& mes, sio::message::ptr const& data);
    void onNewBidder(const std::string& mess, sio::message::ptr const& data);

    bool createDeal(std::string blockchain_addr, std::string blockchain_pass, long long prize, QDateTime expireTime, int& global_id);

    // encrypt data and return base64 format
    std::string encryptData(std::string publickey, std::string data);
    QString getSecretKey () const;
    QString getPublicKey () const;

    QString getUsername() const;
    QString getPassword() const;
    ~AccountManager();

Q_SIGNALS:
    void keywords_array_changed ();
    void search_done ();
    Q_INVOKABLE void newDealDone ();

private:

    ZmqManager* socket_manager;

    //login page attribute
    std::string username_;
    std::string password_;

    //user is identified with two keys
    char* secret_key_;
    char* public_key_;

    size_t secret_key_len_;
    size_t public_key_len_;

    //key for signing
    char* sig_sec_key_;
    char* sig_pub_key_;

    size_t sig_sec_key_len_;
    size_t sig_pub_key_len_;

    //new deal atributes
    std::set<std::string> keywords_;
    std::vector<bitmile::db::Document> searched_docs_;

    bitmile::blockchain::BlockchainInterface blockchain_;
    std::string deal_contract_addr_;
    std::string owner_key_addr_;

    //socket for communicate with proxy server
    sio::client proxy_socket_;
};

#endif // MainwindowController_H
