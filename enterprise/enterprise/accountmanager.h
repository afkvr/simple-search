#ifndef MainwindowController_H
#define MainwindowController_H

#include "keymanager.h"
#include "database/db_interface.h"
#include "message/message.h"
#include "zmq_manager.h"
#include "utils/utils.h"
#include "blockchain/blockchain_interface.h"
#include "internaldb.h"
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
    Q_PROPERTY(QString proxyIp READ proxyIp WRITE setProxyIp NOTIFY proxyIpChanged)
    Q_PROPERTY(QString fileServerIp READ fileServerIp WRITE setFileServerIp NOTIFY fileServerIpChanged)

    Q_PROPERTY(QString proxyPort READ proxyPort WRITE setProxyPort NOTIFY proxyPortChanged)
    Q_PROPERTY(QString fileServerPort READ fileServerPort WRITE setFileServerPort NOTIFY fileServerPortChanged)

    Q_PROPERTY(QString proxyIp READ proxyIp WRITE setProxyIp NOTIFY proxyIpChanged)
    Q_PROPERTY(QString fileServerIp READ fileServerIp WRITE setFileServerIp NOTIFY fileServerIpChanged)

    Q_PROPERTY(QString blockchainIp WRITE setBlockchainIp)
    Q_PROPERTY(QString blockchainPort WRITE setBlockchainPort)

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

    // for proxy and file_server setting
    void setProxyIp (QString _proxyIp);
    void setFileServerIp (QString _fileServerIp);

    void setProxyPort (QString _proxyPort);
    void setFileServerPort (QString _fileServerPort);

    QString proxyIp () const;
    QString fileServerIp () const;

    QString proxyPort() const;
    QString fileServerPort() const;

    void setBlockchainIp (QString _blockchainIp);
    void setBlockchainPort (QString _blockchainPort);


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

    bool createDeal(std::string blockchain_addr, std::string blockchain_pass, long long prize, QDateTime expireTime, int& new_deal_id);

    bool updateDocDecrypt(unsigned long long deal_id);

    // pay for key
    Q_INVOKABLE bool payForRequestKey(unsigned long long deal_id);

    // establisted connection
    Q_INVOKABLE bool establisConnection();

    // encrypt data and return base64 format
    std::string encryptData(std::string publickey, std::string data);
    std::string decryptData(std::string privateKey, std::string data);
    QString getSecretKey () const;
    QString getPublicKey () const;

    QString getUsername() const;
    QString getPassword() const;

    std::string getSecretKeyBin() const {return std::string(secret_key_, secret_key_+ secret_key_len_);}
    std::string getPublicKeyBin() const {return std::string(public_key_, public_key_ + public_key_len_);}

    ~AccountManager();

Q_SIGNALS:
    void keywords_array_changed ();
    void search_done ();
    Q_INVOKABLE void newDealDone (); 

    Q_INVOKABLE void proxyIpChanged(QString);
    Q_INVOKABLE void fileServerIpChanged(QString);

    Q_INVOKABLE void proxyPortChanged(QString);
    Q_INVOKABLE void fileServerPortChanged(QString);

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

    // var for keep setting
    QString proxyIp_;
    QString fileServerIp_;

    QString proxyPort_;
    QString fileServerPort_;
};

#endif // MainwindowController_H
