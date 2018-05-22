#include "mainwindow.h"
#include "internaldb.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDateTime>
#include "dealmanager.h"

MainWindow::MainWindow(QObject *parent) : QObject(parent)
{
    //get current database info

    blockchain_event_ = new BlockchainWorkerThread();

    connect (blockchain_event_, SIGNAL (newAnswers),
             this, SLOT (updateDealAnswers));
    connect (blockchain_event_, SIGNAL (newKeys),
             this, SLOT (updateDealKey));

    blockchain_event_->start();

    account_manager_ = AccountManager::getInstance();

    //connect slots
    connect(account_manager_, SIGNAL(keywords_array_changed()),
            this, SLOT(on_new_keyword_changed()));

    connect(account_manager_, SIGNAL(search_done()),
            this, SLOT(on_search_done()));
}

MainWindow::~MainWindow()
{
}

bool MainWindow::onRegister()
{
    account_manager_->setPassword(m_passTxt.toStdString());
    account_manager_->setUsername(m_accountTxt.toStdString());
    return account_manager_->registerNewUser();
}

bool MainWindow::onLogin()
{
    account_manager_->setPassword(m_passTxt.toStdString());
    account_manager_->setUsername(m_accountTxt.toStdString());

    if (!account_manager_->authenticate())
        return false;

    /* establish connection to internal DB intergrated with account
     * use username for name of db, confirm for change ???
     */
    InternalDB* db = InternalDB::getInstance();
    db->setSqlDbName(account_manager_->getUsername());
    db->establiseConnection();
}

void MainWindow::onLogout()
{
    account_manager_->clearCredential();
    InternalDB::getInstance()->disconnect();
}

void MainWindow::on_new_keyword_changed() {
    /*
    std::set<std::string> keywords = account_manager_->getKeywords();
    while (ui->new_keywordList->count() > 0) {
        delete ui->new_keywordList->takeItem(0);
    }
    if (keywords.size() == 0) {
        ui->new_keywordList->hide();
    }

    for (std::set <std::string>::iterator beg = keywords.begin();
         beg != keywords.end(); beg++) {
        ui->new_keywordList->addItem(QString( (*beg).c_str() ));
    }

    ui->new_keywordList->show();
    */
}

void MainWindow::on_new_keywordList_itemDoubleClicked(QVariant item)
{
    //update controller data
    account_manager_->removeKeyword(item.toString().toStdString());

}

void MainWindow::on_new_searchButton_clicked()
{
    account_manager_->clearKeywords();
    for (QVariantList::iterator i = m_keywords.begin(); i != m_keywords.end(); i++)
        account_manager_->addKeyword((*i).toString().toLower().toStdString());

    account_manager_->search();
}

void MainWindow::on_search_done() {
    std::vector<bitmile::db::Document> docs = account_manager_->getSearchedDoc();
    m_docids.clear();

    for (int i = 0; i < docs.size(); i++) {
        m_docids.append(QString (docs[i].GetElasticDocId().c_str()));
    }

    Q_EMIT docIdsChanged(m_docids);
}


bool MainWindow::on_new_createDealButton_clicked()
{
    bool check = true;
    int global_id = 177; //fake

    check &= account_manager_->createDeal(m_blockchainAddr.toStdString(), m_passphase.toStdString(), m_dealPrice, m_expiredTime, global_id);

    if (!check)
        return false;

    check &= insertToInternalDB(global_id);
    return check;
}

QString MainWindow::usernameTxt() const
{
    return m_accountTxt;
}

QString MainWindow::passwordTxt() const {
    return m_passTxt;
}

void MainWindow::setUsername(QString usernameTxt)
{
    if (m_accountTxt == usernameTxt)
        return;

    m_accountTxt = usernameTxt;
    Q_EMIT userNameChanged(m_accountTxt);
}

void MainWindow::setPassword(QString passwordTxt) {
    if (m_passTxt == passwordTxt)
        return;

    m_passTxt = passwordTxt;
    Q_EMIT passwordChanged(m_passTxt);
}

QList<QVariant> MainWindow::docIds() const{
    return m_docids;
}

void MainWindow::setDocIds(QVariantList docIds) {
    m_docids.clear();
    m_docids = docIds;

    Q_EMIT docIdsChanged(m_docids);
}

qreal MainWindow::dealPrice() const {
    return m_dealPrice;
}

void MainWindow::setDealPrice(qreal dealPrice) {
    if (m_dealPrice == dealPrice)
        return;

    m_dealPrice = dealPrice;

    Q_EMIT dealPriceChanged(m_dealPrice);
}

QDateTime MainWindow::dealExpiredTime() const {
    return m_expiredTime;
}

void MainWindow::setExpiredTime(QDateTime time) {
    m_expiredTime = time;
    Q_EMIT (m_expiredTime);
}

QString MainWindow::blockchainAddr() const {
    return m_blockchainAddr;
}

void MainWindow::setBlockchainAddr(QString blockchainAddr) {
    if (m_blockchainAddr == blockchainAddr)
        return;

    m_blockchainAddr = blockchainAddr;
    Q_EMIT (m_blockchainAddr);
}

QString MainWindow::passphase() const {
    return m_passphase;
}

void MainWindow::setPassphase(QString passphase) {
    if (m_passphase == passphase)
        return;

    m_passphase = passphase;
    Q_EMIT passphaseChanged(m_passphase);
}

QVariantList MainWindow::keywords() const {
    return m_keywords;
}

void MainWindow::setKeywords(QVariantList keywords) {
    m_keywords.clear();
    m_keywords = keywords;
    Q_EMIT keywordsChanged(m_keywords);
}

bool MainWindow::insertToInternalDB(int global_id) {
    std::vector<bitmile::db::Document> searched_doc = account_manager_->getSearchedDoc();

    // if searched doc is empty , not continue process
    if (searched_doc.size() == 0)
        return true;

    // insert deal data to db
    InternalDB::Deal deal;

    deal.global_id = global_id;
    deal.price = m_dealPrice;
    deal.private_key = account_manager_->getSecretKey();
    deal.public_key =  account_manager_->getPublicKey();

    // set current timesamp in local device, confirm for change ???
    deal.time = QDateTime::currentMSecsSinceEpoch();

    // create continuous string from keywords
    QJsonArray listKeyword;
    std::set<std::string> keywords = account_manager_->getKeywords();

    for (std::set<std::string>::iterator i = keywords.begin(); i != keywords.end() ; i++) {
        listKeyword.append(QJsonValue(QString::fromStdString(*i)));
    }

    deal.keywords = QJsonDocument(listKeyword).toJson(QJsonDocument::Compact);
    qDebug() << "MainWindow Controller deal.keywords " << deal.keywords;

    InternalDB::getInstance()->insertDealData(deal);

    InternalDB::Owner owner;
    InternalDB::DealOwner dealOwner;

    for (std::vector<bitmile::db::Document>::iterator i = searched_doc.begin(); i != searched_doc.end(); i++) {
        owner.address = QString::fromStdString((*i).GetOwnerAddress());
        qDebug() << owner.address;

        InternalDB::getInstance()->insertOwnerData(owner);

        dealOwner.deal_time = deal.time;
        dealOwner.owner_address = owner.address;
        dealOwner.status = DEALOWNER_STATUS_WAITING;
        dealOwner.encrypt_data = QString("");
        dealOwner.decrypt_data = QString("");
        dealOwner.owner_secret_key = QString("");
        dealOwner.owner_doc_id = QString::fromStdString((*i).GetOwnerDocId());
        dealOwner.elastic_id = QString::fromStdString((*i).GetElasticDocId());
        InternalDB::getInstance()->insertDealOwnerData(dealOwner);
    }

    DealManager::getInstance()->updateDealData();
    DealManager::getInstance()->updateDealOwnerData();
    return true;
}

void MainWindow::updateDealAnswers (std::vector<int64_t> deal_ids, std::vector<int> answer_numbs) {
    if (deal_ids.size() != answer_numbs.size()) {
        qDebug() << "deal_ids size != answer_numbs size, something went wrong";
        return;
    }

    for (int i = 0; i < deal_ids.size(); i++) {
        qDebug() << deal_ids[i] << " " << answer_numbs[i];
        //get answer from blockchain
        for (int i = 0; i < answer_numbs[i]; i++) {
            std::string get_answer_q = bitmile::blockchain::DealContract::GetAnswer(deal_ids[i], i);
            nlohmann::json ans_json;
            if (blockchain_.SendCall("", Config::getInstance()->getDealContractAddress(), get_answer_q, "1", ans_json)) {
                nlohmann::json ans = bitmile::blockchain::DealContract::ParseGetAnswer(ans_json);

                InternalDB* db = InternalDB::getInstance();
                InternalDB::Deal deal = db->getDeal(deal_ids[i]);

                InternalDB::DealOwner dealOwner;// = db->getDealOwner(deal.time, ans["user_address"]);

                if (dealOwner.status == DEALOWNER_STATUS_WAITING){
                    if (ans["answer"] == "YES") {
                        dealOwner.status = DEALOWNER_STATUS_ACCEPT;
                    }else if (ans["answer"] == "NO"){
                        dealOwner.status = DEALOWNER_STATUS_DONTACCEPT;
                    }

                    //TODO: get file from fileserver

                    db->updateDealOwnerData(dealOwner);
                }
            }
        }
    }

    DealManager::getInstance()->updateDealData();
    DealManager::getInstance()->updateDealOwnerData();
}
void MainWindow::updateDealKey (std::vector<int64_t> deal_ids, std::vector<int> key_numbs){
    if (deal_ids.size() != key_numbs.size()) {
        qDebug() << "deal ids size != key numb size";
        return;
    }
    for (int i = 0; i < deal_ids.size(); i++) {
        qDebug() << deal_ids[i] << " " << key_numbs[i];
        //get answer from blockchain
        for (int i = 0; i < key_numbs[i]; i++) {
            std::string get_key_q = bitmile::blockchain::DealContract::GetKey(deal_ids[i], i);
            nlohmann::json key_json;
            if (blockchain_.SendCall("", Config::getInstance()->getDealContractAddress(), get_key_q, "1", key_json)) {
                nlohmann::json key = bitmile::blockchain::DealContract::ParseGetAnswer(key_json);

                InternalDB* db = InternalDB::getInstance();
                InternalDB::Deal deal = db->getDeal(deal_ids[i]);

                InternalDB::DealOwner dealOwner;// = db->getDealOwner(deal.time, key["user_address"]);

                if (dealOwner.owner_secret_key == ""){
                    std::string extracted_key = key["key"];
                    dealOwner.owner_secret_key = QString(extracted_key.c_str());
                    std::string extracted_nonce = key["nonce"];
                    dealOwner.nonce = QString (extracted_nonce.c_str());
                    //TODO: decrypt file from fileserver
                    db->updateDealOwnerData(dealOwner);
                }
            }
        }
    }

    DealManager::getInstance()->updateDealData();
    DealManager::getInstance()->updateDealOwnerData();
}
