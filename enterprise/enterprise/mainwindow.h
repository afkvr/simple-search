#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QDir>
#include <QDebug>
#include <QObject>
#include "accountmanager.h"
#include <QVector>
#include <QVariant>
#include <QDateTime>
#include "blockchainWorkerThread.h"
#include "blockchain/blockchain_interface.h"
class MainWindow : public QObject
{
    Q_OBJECT

    // account infomation
    Q_PROPERTY(QString usernameTxt READ usernameTxt WRITE setUsername NOTIFY userNameChanged)
    Q_PROPERTY(QString passwordTxt READ passwordTxt WRITE setPassword NOTIFY passwordChanged)

    // deals information
    Q_PROPERTY(QVariantList docIds READ docIds WRITE setDocIds NOTIFY docIdsChanged)
    Q_PROPERTY(qreal dealPrice READ dealPrice WRITE setDealPrice NOTIFY dealPriceChanged)
    Q_PROPERTY(QDateTime dealExpiredTime READ dealExpiredTime WRITE setExpiredTime NOTIFY dealExpiredTimeChanged)
    Q_PROPERTY(QString blockchainAddr READ blockchainAddr WRITE setBlockchainAddr NOTIFY blockchainAddrChanged)
    Q_PROPERTY(QString passphase READ passphase WRITE setPassphase NOTIFY passphaseChanged)
    Q_PROPERTY(QVariantList keywords READ keywords WRITE setKeywords NOTIFY keywordsChanged)

public:
    explicit MainWindow(QObject *parent = 0);
    ~MainWindow();

    QString usernameTxt() const;
    QString passwordTxt() const;
    QVariantList docIds() const;
    qreal dealPrice() const;
    QDateTime dealExpiredTime() const;
    QString blockchainAddr() const;
    QString passphase() const;
    QVariantList keywords() const;

public Q_SLOTS:
    void setUsername(QString usernameTxt);
    void setPassword(QString passwordTxt);
    void setDocIds(QVariantList docIds);
    void setDealPrice(qreal dealPrice);
    void setExpiredTime(QDateTime time);
    void setBlockchainAddr(QString blockchainAddr);
    void setPassphase (QString passphase);
    void setKeywords(QVariantList keywords);

    Q_INVOKABLE void updateDealAnswers (unsigned long long deal_ids);
    void updateDealKey (std::vector<int64_t> deal_ids, std::vector<int> key_numbs);

    //register page slot
    Q_INVOKABLE bool onRegister();
    Q_INVOKABLE bool onLogin();

    // pay for key
    Q_INVOKABLE bool onPayForKey(unsigned long long deal_id);

    //setting page slot
    Q_INVOKABLE void onLogout();

    // pay for key
    Q_INVOKABLE bool onUpdatePayDoc(unsigned long long deal_id);

Q_SIGNALS:
    void userNameChanged(QString usernameTxt);
    void passwordChanged(QString passwordTxt);
    void docIdsChanged(QVariantList docIds);
    void dealPriceChanged(qreal dealPrice);
    void dealExpiredTimeChanged (QDateTime time);
    void blockchainAddrChanged(QString blockchainAddr);
    void passphaseChanged(QString passphase);
    void keywordsChanged(QVariantList keywords);

public Q_SLOTS:
    //new deal page slot
    Q_INVOKABLE void on_new_keyword_changed  ();

    Q_INVOKABLE void on_new_keywordList_itemDoubleClicked(QVariant item);

    Q_INVOKABLE void on_new_searchButton_clicked();

    Q_INVOKABLE void on_search_done();

    Q_INVOKABLE bool on_new_createDealButton_clicked();



private:
    bool insertToInternalDB(int deal_id);

private:
    // account
    QString m_accountTxt;
    QString m_passTxt;

    // deal infor
    QVariantList m_docids;
    qreal m_dealPrice;
    QString m_blockchainAddr;
    QString m_passphase;
    QDateTime m_expiredTime;
    QVariantList m_keywords;

    // interact with blockchain
    BlockchainWorkerThread* blockchain_event_;
    bitmile::blockchain::BlockchainInterface blockchain_;
    AccountManager* account_manager_;

};

#endif // MAINWINDOW_H
