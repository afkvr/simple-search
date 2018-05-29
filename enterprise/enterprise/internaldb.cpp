#include "internaldb.h"
#include <QSqlQuery>
#include <QSqlDriver>
#include <QSqlError>
#include <QDebug>

InternalDB::InternalDB(QObject* parent = 0) : QObject(parent) {
}

InternalDB::~InternalDB() {
    db.close();
}

InternalDB* InternalDB::getInstance() {
    static InternalDB* instance = NULL;
    if (instance == NULL)
        instance = new InternalDB();
    return instance;
}

bool InternalDB::establiseConnection() {
    if (sqlDbName.isEmpty())
            sqlDbName.append(DEFAULT_DB_NAME);

    disconnect();

    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(sqlDbName);

    Q_ASSERT(db.open());

    // create db if not exists
    sqlQuery = QSqlQuery(db);
    createDB();
}

void InternalDB::disconnect() {
    if (db.isOpen())
        db.close();
}

void InternalDB::setSqlDbName(const QString& _sqlDbName) {
    if (_sqlDbName.isEmpty())
        return;

    sqlDbName = _sqlDbName;
}

QString InternalDB::getSqlDbName() const {
    return sqlDbName;
}


QSqlQuery* InternalDB::getSqlQuery() {
    return &sqlQuery;
}


bool InternalDB::createDB() {
    QString q;

    // create Owner table
    q = QString("CREATE TABLE IF NOT EXISTS %1 (%2 BLOB PRIMARY KEY)").arg(OWNER_TABLE, OWNER_ADDRESS);

    if (!query(q)) {
        qDebug() << "Have error when create OWNER_TABLE";
        return false;
    }

    // create Deal table
    q = QString ("CREATE TABLE IF NOT EXISTS %1 (%2 DOUBLE, "
                 "                 %3 BLOB, %4 BLOB, %5 BLOB, %6 BLOB PRIMARY KEY, %7 INT, %8 INT)"
                 ).arg(DEAL_TABLE, DEAL_PRICE,
                       DEAL_PUBLICKEY, DEAL_PRIVATEKEY,
                       DEAL_KEYWORDS, DEAL_TIME, DEAL_GLOBAL_ID, DEAL_PAYMENT_STATUS);

    if (!query(q)) {
        qDebug() << "Have error when create DEAL_TABLE";
        return false;
    }

    // create DealOwner Table
    q = QString ("CREATE TABLE IF NOT EXISTS %1 (%2 BLOB, %3 BLOB,"
                 "%4 INT, %5 BLOB, %6 BLOB, %7 BLOB, %8 BLOB, %9 BLOB, %10 BLOB, PRIMARY KEY(%2, %3))"
                 ).arg(DEALOWNER_TABLE, DEALOWNER_DEAL_TIME, DEALOWNER_OWNER_ADDRESS,
                       DEALOWNER_STATUS, DEALOWNER_ENCRYPT_DATA, DEALOWNER_DECRYPT_DATA,
                       DEALOWNER_SECRETKEY, DEALOWNER_DOC_ID, DEALOWNER_ELASTICID).arg(DEALOWNER_NONCE);

    qDebug() << "create dealowner content " << q;

    if (!query(q)) {
        qDebug() << "Have error when create DEAL_TABLE";
        return false;
    }

    return true;

}

// interact with Deal table
bool InternalDB::insertDealData(const Deal& _data) {
    QString q = "INSERT INTO %1 VALUES (:d2, ':d3', ':d4', ':d5', :d6, :d7, :d8)";
    q = q.arg(DEAL_TABLE);

    q.replace(":d2", convertToString(_data.price));
    q.replace(":d3", convertToString(_data.public_key));
    q.replace(":d4", convertToString(_data.private_key));
    q.replace(":d5", convertToString(_data.keywords));
    q.replace(":d6", convertToString(_data.time));
    q.replace(":d7", convertToString(_data.deal_id));
    q.replace(":d8", convertToString(_data.payment_status));

    return query(q);
}

bool InternalDB::updateDealData(const Deal& _data) {
    QString q = "UPDATE %1 SET %2=:d2, %3=':d3', %4=':d4', %5=':d5', %7=:d7, %8=:d8 WHERE %6=:d6";
    q = q.arg(DEAL_TABLE, DEAL_PRICE, DEAL_PUBLICKEY, DEAL_PRIVATEKEY, DEAL_KEYWORDS, DEAL_TIME, DEAL_GLOBAL_ID, DEAL_PAYMENT_STATUS);

    q.replace(":d2",  convertToString(_data.price));
    q.replace(":d3",  convertToString(_data.public_key));
    q.replace(":d4",  convertToString(_data.private_key));
    q.replace(":d5",  convertToString(_data.keywords));
    q.replace(":d6",  convertToString(_data.time));
    q.replace(":d7",  convertToString(_data.deal_id));
    q.replace(":d8",  convertToString(_data.payment_status));

    return query(q);
}

bool InternalDB::removeDealData(const Deal& _data) {
    QString q = "DELETE FROM %1 WHERE %2=:d2)";
    q.arg(DEAL_TABLE, DEAL_TIME);
    q.replace(":d2", convertToString(_data.time));
    return query(q);
}

InternalDB::Deal InternalDB::getDeal(const qint64 id) {
    Deal deal;
    QString q = "SELECT * FROM %1 WHERE %2=:d2";
    q = q.arg(DEAL_TABLE, DEAL_GLOBAL_ID);

    q.replace(":d2", convertToString(id));

    if (query(q)) {

        while (sqlQuery.next()) {
            deal.deal_id = sqlQuery.value(InternalDB::DEAL_GLOBAL_ID_INDEX).toLongLong();
            deal.keywords = sqlQuery.value(InternalDB::DEAL_KEYWORDS_INDEX).toString();
            deal.price = sqlQuery.value(InternalDB::DEAL_PRICE_INDEX).toReal();
            deal.private_key = sqlQuery.value(InternalDB::DEAL_PRIVATE_KEY_INDEX).toString();
            deal.public_key = sqlQuery.value(InternalDB::DEAL_PUBLIC_KEY_INDEX).toString();
            deal.time = sqlQuery.value(InternalDB::DEAL_TIME_INDEX).toLongLong();
            deal.payment_status = sqlQuery.value(InternalDB::DEAL_PAYMENT_STATUS_INDEX).toLongLong();
            break;
        }
    }

    return deal;
}

// interact with Owner table
bool InternalDB::insertOwnerData(const Owner& _data) {
    QString q =  "INSERT INTO %1 VALUES (':d2')";
    q = q.arg(OWNER_TABLE);
    q.replace(":d2", convertToString(_data.address));
    return query(q);
}

bool InternalDB::updateOwnerData(const Owner& _data) {
    Q_UNUSED(_data);
    //TODO
}

bool InternalDB::removeOwnerData(const Owner& _data) {
    QString q =  "DELETE FROM %1 WHERE %2=':d2')";
    q = q.arg(OWNER_TABLE, OWNER_ADDRESS);
    q.replace(":d2", convertToString(_data.address));
    return query(q);
}

// interact with DealOwner table
bool InternalDB::insertDealOwnerData(const DealOwner& _data) {
    QString q = "INSERT INTO %1 VALUES (:d2,':d3', :d4, ':d5', ':d6', ':d7', ':d8', ':d9', ':d10')";
    q = q.arg(DEALOWNER_TABLE);

    q.replace(":d2", convertToString(_data.deal_time));
    q.replace(":d3", convertToString(_data.owner_address));
    q.replace(":d4", convertToString(_data.status));
    q.replace(":d5", convertToString(_data.encrypt_data));
    q.replace(":d6", convertToString(_data.decrypt_data));
    q.replace(":d7", convertToString(_data.owner_secret_key));
    q.replace(":d8", convertToString(_data.owner_doc_id));
    q.replace(":d9", convertToString(_data.elastic_id));
    q.replace(":d10", convertToString(_data.nonce));
    return query(q);
}

bool InternalDB::updateDealOwnerData(const DealOwner& _data) {
    QString q = "UPDATE %1 SET %2=:d2, %3=':d3', %4=':d4', %5=':d5', %6=':d6', %7=':d7', %8=':d8' "
                "WHERE %9=:d9 AND %10=':d10'";

    q = q.arg(DEALOWNER_TABLE, DEALOWNER_STATUS, DEALOWNER_ENCRYPT_DATA
          ,DEALOWNER_DECRYPT_DATA, DEALOWNER_SECRETKEY,
          DEALOWNER_DOC_ID, DEALOWNER_ELASTICID).arg(DEALOWNER_NONCE,
          DEALOWNER_DEAL_TIME, DEALOWNER_OWNER_ADDRESS);

    q.replace(":d2", convertToString(_data.status));
    q.replace(":d3", convertToString(_data.encrypt_data));
    q.replace(":d4", convertToString(_data.decrypt_data));
    q.replace(":d5", convertToString(_data.owner_secret_key));
    q.replace(":d6", convertToString(_data.owner_doc_id));
    q.replace(":d7", convertToString(_data.elastic_id));
    q.replace(":d8", convertToString(_data.nonce));
    q.replace(":d9", convertToString(_data.deal_time));
    q.replace(":d10", convertToString(_data.owner_address));

    qDebug() << "InternalDB::updateDealOwnerData thangnt " << q;

    return query(q);
}

bool InternalDB::removeDealOwnerData(const DealOwner& _data) {
    QString q = "DELETE FROM %1 WHERE %2=:d2 AND %3=':d3'";
    q = q.arg(DEALOWNER_TABLE, DEALOWNER_DEAL_TIME, DEALOWNER_OWNER_ADDRESS);

    q.replace(":d2", convertToString(_data.deal_time));
    q.replace(":d3", convertToString(_data.owner_address));

    return query(q);
}

InternalDB::DealOwner InternalDB::getDealOwner(const qint64 dealTime, QString owner_address) {
    QString q = "SELECT * FROM %1 WHERE %2=:d2 AND %3=':d3'";
    q = q.arg(DEALOWNER_TABLE, DEALOWNER_DEAL_TIME, DEALOWNER_OWNER_ADDRESS);

    q.replace(":d2", convertToString(dealTime));
    q.replace(":d3", convertToString(owner_address));

    InternalDB::DealOwner dealOwner;

    if (query(q)) {
        while (sqlQuery.next()) {
            dealOwner.deal_time = sqlQuery.value(InternalDB::DEALOWNER_DEALTIME_INDEX).toLongLong();
            dealOwner.decrypt_data = sqlQuery.value(InternalDB::DEALOWNER_DECRYPT_DATA_INDEX).toString();
            dealOwner.encrypt_data = sqlQuery.value(InternalDB::DEALOWNER_ENCRYPT_DATA_INDEX).toString();
            dealOwner.owner_address = sqlQuery.value(InternalDB::DEALOWNER_OWNER_ADDRESS_INDEX).toString();
            dealOwner.owner_doc_id = sqlQuery.value(InternalDB::DEALOWNER_DOC_ID_INDEX).toString();
            dealOwner.owner_secret_key = sqlQuery.value(InternalDB::DEALOWNER_SECRET_KEY_INDEX).toString();
            dealOwner.status = sqlQuery.value(InternalDB::DEALOWNER_STATUS_INDEX).toInt();
            dealOwner.elastic_id =  sqlQuery.value(InternalDB::DEALOWNER_ELASTIC_ID_INDEX).toString();
            break;
        }
    }

    return dealOwner;
}

InternalDB::DealOwner InternalDB::getDealOwner (const QString owner_address) {
    QString q = "SELECT * FROM %1 WHERE %2=':d2'";
    q = q.arg(DEALOWNER_TABLE, DEALOWNER_OWNER_ADDRESS);

    q.replace(":d2", convertToString(owner_address));

    InternalDB::DealOwner dealOwner;

    if (query(q)) {
        while (sqlQuery.next()) {
            dealOwner.deal_time = sqlQuery.value(InternalDB::DEALOWNER_DEALTIME_INDEX).toLongLong();
            dealOwner.decrypt_data = sqlQuery.value(InternalDB::DEALOWNER_DECRYPT_DATA_INDEX).toString();
            dealOwner.encrypt_data = sqlQuery.value(InternalDB::DEALOWNER_ENCRYPT_DATA_INDEX).toString();
            dealOwner.owner_address = sqlQuery.value(InternalDB::DEALOWNER_OWNER_ADDRESS_INDEX).toString();
            dealOwner.owner_doc_id = sqlQuery.value(InternalDB::DEALOWNER_DOC_ID_INDEX).toString();
            dealOwner.owner_secret_key = sqlQuery.value(InternalDB::DEALOWNER_SECRET_KEY_INDEX).toString();
            dealOwner.status = sqlQuery.value(InternalDB::DEALOWNER_STATUS_INDEX).toInt();
            dealOwner.elastic_id =  sqlQuery.value(InternalDB::DEALOWNER_ELASTIC_ID_INDEX).toString();
            break;
        }
    }

    return dealOwner;
}

std::vector<InternalDB::DealOwner> InternalDB::getDealOwner (const qint64 dealTime, const int status) {
    QString q = "SELECT * FROM %1 WHERE %2=:d2 AND %3=:d3";
    q = q.arg(DEALOWNER_TABLE, DEALOWNER_DEAL_TIME, DEALOWNER_STATUS);

    q.replace(":d2", convertToString(dealTime));
    q.replace(":d3", convertToString(status));

    std::vector<InternalDB::DealOwner> results;
    InternalDB::DealOwner dealOwner;

    if (query(q)) {
        while (sqlQuery.next()) {
            dealOwner.deal_time = sqlQuery.value(InternalDB::DEALOWNER_DEALTIME_INDEX).toLongLong();
            dealOwner.decrypt_data = sqlQuery.value(InternalDB::DEALOWNER_DECRYPT_DATA_INDEX).toString();
            dealOwner.encrypt_data = sqlQuery.value(InternalDB::DEALOWNER_ENCRYPT_DATA_INDEX).toString();
            dealOwner.owner_address = sqlQuery.value(InternalDB::DEALOWNER_OWNER_ADDRESS_INDEX).toString();
            dealOwner.owner_doc_id = sqlQuery.value(InternalDB::DEALOWNER_DOC_ID_INDEX).toString();
            dealOwner.owner_secret_key = sqlQuery.value(InternalDB::DEALOWNER_SECRET_KEY_INDEX).toString();
            dealOwner.status = sqlQuery.value(InternalDB::DEALOWNER_STATUS_INDEX).toInt();
            dealOwner.elastic_id =  sqlQuery.value(InternalDB::DEALOWNER_ELASTIC_ID_INDEX).toString();

            results.push_back(dealOwner);
        }
    }

    return results;
}

bool InternalDB::query(QString _query) {
    qDebug() << "InternalDB::query " << _query;

    sqlQuery.prepare(_query);

    if (!sqlQuery.exec()) {
        qDebug() << sqlQuery.lastError().text();
        return false;
    }

    return true;
}
