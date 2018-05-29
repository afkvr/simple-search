#ifndef INTERNALDB_H
#define INTERNALDB_H

#include <QSqlDatabase>
#include <QObject>
#include <QSqlQuery>


#define DEFAULT_DB_NAME "internal.db"

/* table structure */
#define OWNER_TABLE "owner"
#define     OWNER_ADDRESS "address"                     // BLOB             <- TEXT

#define DEAL_TABLE "deal"
#define     DEAL_PRICE "price"                          // DOUBLE PRECISION
#define     DEAL_PUBLICKEY "public_key"                 // BLOB             <- BASE64
#define     DEAL_PRIVATEKEY "private_key"               // BLOB             <- BASE64
#define     DEAL_KEYWORDS "keywords"                    // BLOB             <- JSON format ["","",...]}
#define     DEAL_TIME "time"                            // BLOB             <- timestame
#define     DEAL_GLOBAL_ID "deal_id"                    // INT
#define     DEAL_PAYMENT_STATUS "payment_status"        // INT
#define         DEAL_PAYMENT_UNSUCCESSED  0
#define         DEAL_PAYMENT_SUCCESSED   1

#define DEALOWNER_TABLE "dealowner"
#define     DEALOWNER_DEAL_TIME "deal_time"             // BLOB
#define     DEALOWNER_OWNER_ADDRESS  "owner_address"    // BLOB             <- BASE64
#define     DEALOWNER_STATUS    "status"                // INT              <- ENUM {dont_accept:0, accept:1, waiting: 2}
#define         DEALOWNER_STATUS_DONTACCEPT  0
#define         DEALOWNER_STATUS_ACCEPT      1
#define         DEALOWNER_STATUS_WAITING     2
#define     DEALOWNER_ENCRYPT_DATA "encrypt_data"       // BLOB             <- BASE64
#define     DEALOWNER_DECRYPT_DATA "decrypt_data"       // BLOB             <- BASE64
#define     DEALOWNER_SECRETKEY "owner_secret_key"      // BLOB             <- BASE64
#define     DEALOWNER_DOC_ID "owner_doc_id"             // BLOB             <- TEXT
#define     DEALOWNER_ELASTICID  "elastic_id"           // BLOB             <- TEXT
#define     DEALOWNER_NONCE "nonce"

class InternalDB : public QObject {
    Q_OBJECT
public:
    InternalDB(QObject*);
    ~InternalDB();

    struct Deal {
       qreal    price;
       QString  public_key;
       QString  private_key;
       QString  keywords;
       qint64   time;
       qint64   deal_id;
       qint64      payment_status;
    };

    enum DEAL_PROPERTY_INDEX {
        DEAL_PRICE_INDEX = 0,
        DEAL_PUBLIC_KEY_INDEX,
        DEAL_PRIVATE_KEY_INDEX,
        DEAL_KEYWORDS_INDEX,
        DEAL_TIME_INDEX,
        DEAL_GLOBAL_ID_INDEX,
        DEAL_PAYMENT_STATUS_INDEX
    };

    struct Owner {
        QString address;
    };

    enum OWNER_PROPERTY_INDEX {
        OWNER_ADDRESS_INDEX = 0
    };

    struct DealOwner {
        qint64 deal_time;
        QString owner_address;
        int   status;
        QString encrypt_data;
        QString decrypt_data;
        QString owner_secret_key;
        QString owner_doc_id;
        QString elastic_id;
        QString nonce;
    };

    enum DEALOWNER_PROPERTY_INDEX {
        DEALOWNER_DEALTIME_INDEX = 0,
        DEALOWNER_OWNER_ADDRESS_INDEX,
        DEALOWNER_STATUS_INDEX,
        DEALOWNER_ENCRYPT_DATA_INDEX,
        DEALOWNER_DECRYPT_DATA_INDEX,
        DEALOWNER_SECRET_KEY_INDEX,
        DEALOWNER_DOC_ID_INDEX,
        DEALOWNER_ELASTIC_ID_INDEX,
        DEALOWNER_NONCE_INDEX
    };

    enum DEALOWNER_STATUS_VALUE {
        DEALOWNER_STATUS_VAL_IGNORE=0,
        DEALOWNER_STATUS_VAL_ACCEPT,
        DEALOWNER_STATUS_VAL_WAITING
    };

public:
    static InternalDB* getInstance();

    // interact with Deal table
    bool insertDealData(const Deal&);
    bool updateDealData(const Deal&);
    bool removeDealData(const Deal&);
    Deal getDeal (const qint64 id);

    // interact with Owner table
    bool insertOwnerData(const Owner&);
    bool updateOwnerData(const Owner&);
    bool removeOwnerData(const Owner&);

    // interact with DealOwner table
    bool insertDealOwnerData(const DealOwner&);
    bool updateDealOwnerData(const DealOwner&);
    bool removeDealOwnerData(const DealOwner&);

    DealOwner getDealOwner (const qint64 dealTime, QString owner_address);
    DealOwner getDealOwner (const QString owner_address);
    std::vector<DealOwner> getDealOwner (const qint64 dealTime, const int status);

    // utils
    bool establiseConnection();
    void disconnect();
    bool createDB();
    bool isExitsDB();
    bool query(QString _query);

    // get set properties
    void setSqlDbName(const QString& _sqlPathName);
    QString getSqlDbName() const;
    QSqlQuery* getSqlQuery();

private:
    QString convertToString(const qint64 arg) {return QString("%1").arg(arg);}
    QString convertToString(const qreal arg) {return QString("%1").arg(arg);}
    QString convertToString(const qint8 arg) {return QString("%1").arg(arg);}
    QString convertToString(const int arg) {return QString("%1").arg(arg);}
    QString convertToString(const QString arg) {return arg;}

private:
    QString sqlDbName;
    QSqlDatabase db;
    QSqlQuery sqlQuery;
};

#endif // INTERNALDB_H
