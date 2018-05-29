#include "dealmanager.h"
#include <QSqlQuery>
#include <QDebug>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QDateTime>


DealManager* DealManager::getInstance() {
    static DealManager* instance = NULL;

    if (instance == NULL) {
        instance = new DealManager();
    }

    return instance;
}

DealManager::DealManager(QObject* parent) : QObject(parent) {
}

DealManager::~DealManager() {

}

void DealManager::updateDealOwnerData() {
    m_dealOwnerMap.clear();
    m_dealOwnerData.clear();

    InternalDB* db = InternalDB::getInstance();
    QString q = "SELECT * FROM DealOwner";

    if (!db->query(q))
        return;

    QSqlQuery* queryObj = db->getSqlQuery();

    InternalDB::DealOwner dealOwner;
    QJsonArray dealOwnerArr;
    QJsonObject dealOwnerItem;
    QDateTime dt;

    while (queryObj->next()) {
        dealOwner.deal_time = queryObj->value(InternalDB::DEALOWNER_DEALTIME_INDEX).toLongLong();
        dealOwner.decrypt_data = queryObj->value(InternalDB::DEALOWNER_DECRYPT_DATA_INDEX).toString();
        dealOwner.encrypt_data = queryObj->value(InternalDB::DEALOWNER_ENCRYPT_DATA_INDEX).toString();
        dealOwner.owner_address = queryObj->value(InternalDB::DEALOWNER_OWNER_ADDRESS_INDEX).toString();
        dealOwner.owner_doc_id = queryObj->value(InternalDB::DEALOWNER_DOC_ID_INDEX).toString();
        dealOwner.owner_secret_key = queryObj->value(InternalDB::DEALOWNER_SECRET_KEY_INDEX).toString();
        dealOwner.status = queryObj->value(InternalDB::DEALOWNER_STATUS_INDEX).toInt();
        dealOwner.elastic_id =  queryObj->value(InternalDB::DEALOWNER_ELASTIC_ID_INDEX).toString();

        QMap<qint64, QList<InternalDB::DealOwner>>::iterator i = m_dealOwnerMap.find(dealOwner.deal_time);

        // create new chunck key if not exists before
        if (i == m_dealOwnerMap.end()) {
            QList<InternalDB::DealOwner> dealOwnerList;
            dealOwnerList.append(dealOwner);
            m_dealOwnerMap.insert(dealOwner.deal_time, dealOwnerList);
        }
        else {
            i.value().append(dealOwner);
        }

        dt = QDateTime::fromMSecsSinceEpoch(dealOwner.deal_time);
        dealOwnerItem[DEALOWNER_DEAL_TIME] = QString("%1").arg(dt.toString("hh:mm:ss dd/MM/yyyy"));
        dealOwnerItem[DEALOWNER_DECRYPT_DATA] = dealOwner.decrypt_data;
        dealOwnerItem[DEALOWNER_ENCRYPT_DATA] = dealOwner.encrypt_data;
        dealOwnerItem[DEALOWNER_OWNER_ADDRESS] = dealOwner.owner_address;
        dealOwnerItem[DEALOWNER_DOC_ID] = dealOwner.owner_doc_id;
        dealOwnerItem[DEALOWNER_ELASTICID] = dealOwner.elastic_id;
        dealOwnerItem[DEALOWNER_STATUS] = QString("%1").arg(dealOwner.status);

        // external value
        dealOwnerItem["timestamp"] = dealOwner.deal_time;
        dealOwnerArr.append(dealOwnerItem);
    }

    m_dealOwnerData = QJsonDocument(dealOwnerArr).toVariant();
    qDebug() << "DealManager::updateDealOwnerData ";
    Q_EMIT dealOwnerDataChanged(m_dealOwnerData);
}

/*
 * get DealOwner information
 * @param: qint64 timestamp when create deal, is primary key
 * @return QVariant list of deal owner
 */
QVariant DealManager::getDealOwnerData(qint64 dealTimestamp) {
    if (dealTimestamp == -1)
        return m_dealOwnerData;

    QMap<qint64,QList<InternalDB::DealOwner>>::iterator i = m_dealOwnerMap.find(dealTimestamp);

    if (i == m_dealOwnerMap.end())
        return QVariant();

    QList<InternalDB::DealOwner>& list = i.value();

    if (list.length() == 0)
        return QVariant();

    InternalDB::DealOwner dealOwner;
    QJsonArray dealOwnerArr;
    QJsonObject dealOwnerItem;
    QDateTime dt;

    int accept = 0;
    int ignore = 0;
    int total = 0;

    for (QList<InternalDB::DealOwner>::iterator j = list.begin(); j != list.end(); j++)
    {
        dealOwner = *j;
        dt = QDateTime::fromMSecsSinceEpoch(dealOwner.deal_time);
        dealOwnerItem[DEALOWNER_DEAL_TIME] = QString("%1").arg(dt.toString("hh:mm:ss dd/MM/yyyy"));
        dealOwnerItem[DEALOWNER_DECRYPT_DATA] = dealOwner.decrypt_data;
        dealOwnerItem[DEALOWNER_ENCRYPT_DATA] = dealOwner.encrypt_data;
        dealOwnerItem[DEALOWNER_OWNER_ADDRESS] = dealOwner.owner_address;
        dealOwnerItem[DEALOWNER_DOC_ID] = dealOwner.owner_doc_id;
        dealOwnerItem[DEALOWNER_ELASTICID] = dealOwner.elastic_id;
        dealOwnerItem[DEALOWNER_STATUS] = QString("%1").arg(dealOwner.status);

        // external value
        dealOwnerItem["timestamp"] = dealOwner.deal_time;

        dealOwnerArr.append(dealOwnerItem);
        total++;

        // status = 2, -> wait
        if (dealOwner.status == InternalDB::DEALOWNER_STATUS_VAL_ACCEPT)
            accept++;
        else if (dealOwner.status == InternalDB::DEALOWNER_STATUS_VAL_IGNORE)
            ignore++;
    }

    /* external information
     * format of doc {
     *                  "data": [],
     *                  "accept": int,
     *                  "ignore": int,
     *                  "total": int
     *               }
     */
    QJsonObject rootObj;
    rootObj["data"] = dealOwnerArr; // pass const string ???
    rootObj["accept"] = accept;     // pass const string ???
    rootObj["ignore"] = ignore;     // pass const string ???
    rootObj["total"] = total;       // pass const string ???

    return QJsonDocument(rootObj).toVariant();
}

QVariant DealManager::getDealData() {
    return m_dealData;
}

void DealManager::updateDealData() {
    m_dealList.clear();

    InternalDB* db = InternalDB::getInstance();
    QString q = "SELECT * FROM Deal";

    if (!db->query(q))
        return;

    QSqlQuery* queryObj = db->getSqlQuery();

    InternalDB::Deal deal;
    QJsonArray dealArr;
    QJsonObject dealItem;
    QDateTime dt;

    while (queryObj->next()) {
        deal.time = queryObj->value(InternalDB::DEAL_TIME_INDEX).toLongLong();
        deal.price = queryObj->value(InternalDB::DEAL_PRICE_INDEX).toDouble();
        deal.keywords = queryObj->value(InternalDB::DEAL_KEYWORDS_INDEX).toString();
        deal.deal_id =  queryObj->value(InternalDB::DEAL_GLOBAL_ID_INDEX).toLongLong();
        deal.payment_status = queryObj->value(InternalDB::DEAL_PAYMENT_STATUS_INDEX).toLongLong();

        m_dealList.append(deal);

        dt = QDateTime::fromMSecsSinceEpoch(deal.time);
        dealItem[DEAL_TIME] = QString("%1").arg(dt.toString("hh:mm:ss dd/MM/yyyy"));
        dealItem[DEAL_PRICE] = deal.price;
        dealItem[DEAL_KEYWORDS] = deal.keywords;
        dealItem[DEAL_GLOBAL_ID] = deal.deal_id;
        dealItem[DEAL_PAYMENT_STATUS] = deal.payment_status;

        // external value
        dealItem["timestamp"] = deal.time;
        dealArr.append(dealItem);
    }

    m_dealData = QJsonDocument(dealArr).toVariant();

    qDebug() << "DealManager::updateDealData";
    Q_EMIT dealDataChanged(m_dealData);
}

QVariant DealManager::getOwnerData() {
    return m_ownerData;
}

void DealManager::updateOwnerData() {
    m_ownerList.clear();

    InternalDB* db = InternalDB::getInstance();
    QString q = "SELECT * from Owner";

    if (!db->query(q))
        return;

    QSqlQuery* queryObj = db->getSqlQuery();

    InternalDB::Owner owner;
    QJsonArray ownerArr;
    QJsonObject ownerItem;

    while (queryObj->next()) {
        owner.address = queryObj->value(InternalDB::OWNER_ADDRESS_INDEX).toString();
        ownerItem[OWNER_ADDRESS] = owner.address;
        ownerArr.append(ownerItem);
    }

    m_ownerData = QJsonDocument(ownerArr).toVariant();
    Q_EMIT ownerDataChanged(m_ownerData);
}
