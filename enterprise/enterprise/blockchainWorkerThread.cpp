#include "blockchainWorkerThread.h"

BlockchainWorkerThread::BlockchainWorkerThread()
{
    std::vector<int64_t> deal_ids;
    std::vector<int> answer_numbs;
    std::vector<int> key_numbs;


    InternalDB* db = InternalDB::getInstance();

    //get all deal
    QString deal_q = "SELECT * FROM Deal";

    if (!db->query(deal_q))
        return;
    QSqlQuery* queryObj = db->getSqlQuery();
    QMap<qint64, InternalDB::Deal> dealMap;
    InternalDB::Deal deal;
    while (queryObj->next()) {
        deal.deal_id = queryObj->value(InternalDB::DEAL_GLOBAL_ID_INDEX).toLongLong();
        deal.time = queryObj->value(InternalDB::DEAL_TIME_INDEX).toLongLong();
        dealMap.insert (deal.time, deal);
    }


    QString q = "SELECT * FROM DealOwner";

    if (!db->query(q))
        return;

    queryObj = db->getSqlQuery();

    InternalDB::DealOwner dealOwner;


    while (queryObj->next()) {
        dealOwner.deal_time = queryObj->value(InternalDB::DEALOWNER_DEALTIME_INDEX).toLongLong();
        dealOwner.owner_secret_key = queryObj->value(InternalDB::DEALOWNER_SECRET_KEY_INDEX).toString();
        dealOwner.status = queryObj->value(InternalDB::DEALOWNER_STATUS_INDEX).toInt();

        deal_ids.push_back(dealMap.find(dealOwner.deal_time).value().deal_id);

        int answer_count = 0;
        if (dealOwner.status != DEALOWNER_STATUS_WAITING) {
            answer_count++;
        }
        answer_numbs.push_back(answer_count);

        int key_count = 0;
        if (dealOwner.owner_secret_key != "") {
            key_count++;
        }
        key_numbs.push_back(key_count);
    }

    deal_ids_ = deal_ids;
    answer_numbs_ = answer_numbs;
    key_numbs_ = key_numbs;
    deal_address_ = Config::getInstance()->getDealContractAddress();
}

void BlockchainWorkerThread::run() {


    while (1) {

        std::vector<int64_t> deals_ans;
        std::vector<int> ans;

        std::vector<int64_t> deals_key;
        std::vector<int> keys;

        mutex.lock();

        nlohmann::json result;

        for (int i = 0; i < deal_ids_.size() ; i++) {
            //get number of answer
            std::string answer_query = bitmile::blockchain::DealContract::GetNumberOfAnswer(deal_ids_[i]);

            if (blockchain_.SendCall("", deal_address_, answer_query, "1", result)) {
                nlohmann::json answer_numb_json = bitmile::blockchain::DealContract::ParseGetNumberOfAnswerResult(result);
                int answer_numb = answer_numb_json["amount"];

                if (answer_numb > answer_numbs_[i]) {
                    deals_ans.push_back(deal_ids_[i]);
                    ans.push_back(answer_numb);
                    answer_numbs_[i] = answer_numb;
                }
            }


            //get number of key
            std::string key_query = bitmile::blockchain::DealContract::GetNumberOfKey(deal_ids_[i]);

            if (blockchain_.SendCall("", deal_address_, key_query, "1", result)) {
                nlohmann::json key_numb_json  = bitmile::blockchain::DealContract::ParseGetNumberOfKeyResult(result);

                int key_numb = key_numb_json["amount"];

                if (key_numb > key_numbs_[i]) {
                    deals_key.push_back(deal_ids_[i]);
                    keys.push_back(key_numb);
                    key_numbs_[i] = key_numb;
                }
            }
        }


        mutex.unlock();

        if (deals_ans.size() > 0) {
            Q_EMIT newAnswers(deals_ans, ans);
            deals_ans.clear();
            ans.clear();
        }

        if (deals_key.size() > 0) {
            Q_EMIT newKeys(deals_key, keys);
            deals_key.clear();
            keys.clear();
        }
    }

}

void BlockchainWorkerThread::addDeal(int64_t deal_id, int answer_numb, int key_numb) {
    //lock
    mutex.lock();
    deal_ids_.push_back(deal_id);
    answer_numbs_.push_back(answer_numb);
    key_numbs_.push_back(key_numb);
    mutex.unlock();
}

