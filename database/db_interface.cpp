#include "db_interface.h"
#include <iostream>

namespace bitmile{
  namespace db{
    nlohmann::json Document::ToJson () const {
      nlohmann::json json_doc;
      if (owner_address_.length() > 0) {
        json_doc["owner_address"] = owner_address_;
      }
      if (doc_id_.length() > 0) {
        json_doc["doc_id"] = doc_id_;
      }

      if (elastic_doc_id_.length() > 0) {
        json_doc["elastic_doc_id"] = elastic_doc_id_;
      }

      if (data_.size() > 0) {
        //convert data to base64 form before pass it to json doc
        unsigned b64_len = sodium_base64_ENCODED_LEN(data_.size(), sodium_base64_VARIANT_ORIGINAL);
        if (b64_len > 0) {
          char* b64_str = new char[b64_len];

          //compiler complain it can't convert from char* to const unsigned char* so create a temporary space then copy the data to this space

          sodium_bin2base64 (b64_str, b64_len,
                             reinterpret_cast<const unsigned char*> (data_.data()), data_.size(),
                             sodium_base64_VARIANT_ORIGINAL);

          json_doc["data"] = b64_str;
          json_doc["data_size"] = data_.size();



          delete[] b64_str;
        }
      }

      if (keywords_.size() > 0) {
        json_doc["keywords"] = keywords_;
      }
      return json_doc;

    }

    bool Document::FromJson (nlohmann::json& doc) {

      if (doc.count ("owner_address") == 1){
        owner_address_ = doc["owner_address"];
      }

      if (doc.count ("doc_id") == 1) {
        doc_id_ = doc["doc_id"];
      }

      if (doc.count ("elastic_doc_id") == 1) {
        elastic_doc_id_ = doc["elastic_doc_id"];
      }

      if (doc.find ("data") != doc.end()) {
        if (doc.count ("data_size") != 1 || doc.count("keywords") != 1) {
          return false;
        }
        //get base 64 string
        std::string b64_data = doc["data"];
        size_t bin_size = doc["data_size"];
        data_.resize (bin_size);
        size_t decode_bin_size;
        if (sodium_base642bin (reinterpret_cast<unsigned char*> (data_.data()), bin_size,
                           b64_data.data(), b64_data.length(),
                           NULL, &decode_bin_size,
                               NULL, sodium_base64_VARIANT_ORIGINAL)) {
          //failed to decode string
          data_ = std::vector<char> ();
          return false;
        }

        if (decode_bin_size != bin_size) {
          //binary size get from client should match
          //decoded size
          data_ = std::vector<char> ();
          return false;
        }

        for (auto& word : doc["keywords"]) {
          keywords_.push_back (word.dump());
        }
      }

      return true;
    }

    std::string Document::GetOwnerAddress () const{
      return owner_address_;
    }
    void Document::SetOwnerAddress (const std::string& addr) {
      owner_address_ = addr;
    }

    std::string Document::GetOwnerDocId() const {
      return doc_id_;
    }

    void Document::SetOwnerDocId (const std::string& id) {
      doc_id_ = id;
    }

    std::string Document::GetElasticDocId() const{
      return elastic_doc_id_;
    }

    void Document::SetElasticDocId (const std::string& id) {
      elastic_doc_id_ = id;
    }
    bool Document::ParseJson (Json::Object json_doc) {
      /*     {
       *        "_index": "user_data",
       *        "_type": "_doc",
       *        "_id": "1",
       *        "_score": 0.5753642,
       *        "_source": {
       *          "owner": "fake ethereum address here",
       *          "keywords": "hung thinh is born on october 1993",
       *          "data": "this is a test data",
       *          "docId": "1"
       *        }
       *      }
       */
      //check json doc validity

      //json data must contain _id field which is document identification of elastic and _source which is actual data begin stored

      bool valid = json_doc.member ("_id") &&
        json_doc.member ("_source");

      if (!valid)  {
        return false;
      }

      Json::Object json_source = json_doc["_source"].getObject();

      /* data must contain
       *   1. owner : owner's blockchain address
       *   2. keywords: keywords as search reference
       *   3. data: link to real data
       *   4. docId: document id for owner
       */
      valid = valid && json_source.member ("owner_address") &&
        json_source.member ("keywords") &&
        json_source.member ("doc_id");

      if (!valid) {
         std::cout  << " Document::ParseJson not valid " << std::endl;
        return false;
      }


      //get content data
      elastic_doc_id_ = json_doc["_id"].getString();
      owner_address_ = json_source["owner_address"].getString();
      doc_id_ = json_source["doc_id"].getString();

      return true;
    }

    void Document::SetData (const char* dat, const size_t size) {
      data_.resize (size);
      memcpy (data_.data(), dat, size);
    }

    const std::vector<char>& Document::GetData() const{
      return data_;
    }

    void Document::SetKeywords (const std::vector<std::string>& keywords) {
      keywords_ = keywords;
    }

    const std::vector<std::string>& Document::GetKeywords() const{
      return keywords_;
    }

    DbInterface::DbInterface() {

      //TODO: make port parameter here
      elastic_search_ = new ElasticSearch ("localhost:9200");
      index_ = "user_data";
      type_ = "_doc";
    }

    void DbInterface::QueryDocWithKeywords (const std::vector<std::string>& keywords, std::vector<Document>& result) {

      //create json query from keywords
      /*
        query have form:
        {
        "query" : {
        "bool" : {
        "must" : [
        { "match" : { "keywords" : "input_keyword1" } },
        { "match" : { "keywords" : "input_keyword2" } },
        ]
        }
        }
        }
      */

      Json::Array must_level_arr;
      for (int i = 0; i < keywords.size(); i++){
        //create query
        Json::Object keyword_level;
        keyword_level.addMemberByKey("keywords", keywords[i]);

        Json::Object match_level;
        match_level.addMemberByKey("match", keyword_level);

        must_level_arr.addElement(match_level);

      }

      Json::Object must_level;
      must_level.addMemberByKey("must", must_level_arr);

      Json::Object bool_level;
      bool_level.addMemberByKey("bool", must_level);

      Json::Object query_level;
      query_level.addMemberByKey("query", bool_level);

      std::cout << "query: " << query_level.str() << std::endl;
      /* send query to elastic and get json result
       *
       *example result format:
       *{
       *  "took": 2,
       *  "timed_out": false,
       *  "_shards": {
       *    "total": 5,
       *    "successful": 5,
       *    "skipped": 0,
       *    "failed": 0
       *  },
       *  "hits": {
       *    "total": 1,
       *    "max_score": 0.5753642,
       *    "hits": [
       *      {
       *        "_index": "user_data",
       *        "_type": "_doc",
       *        "_id": "1",
       *        "_score": 0.5753642,
       *        "_source": {
       *          "owner": "fake ethereum address here",
       *          "keywords": "hung thinh is born on october 1993",
       *          "data": "this is a test data",
       *          "docId": "1"
       *        }
       *      }
       *    ]
       *  }
       *}
       */
      Json::Object j_result;
      try{
        if (!elastic_search_->search(index_, type_, query_level.str(), j_result)) {
          std::cout << "can't find any doc matched query" << std::endl;
          return;
        }
      }catch (Exception& e) {
        std::cerr << "failed in DbInterface::Querydocwithkeywords. Exception caught: " << e.what() << std::endl;
        return;
      }

      Json::Array hit_list;
      hit_list = j_result.getValue("hits").getObject().getValue("hits").getArray();
      Json::Array::const_iterator hit_list_iter = hit_list.begin();

      std::cout << "hit: " << hit_list.str() << std::endl;

      while (hit_list_iter != hit_list.end()) {
        std::cout << "obj data  " << *hit_list_iter << std::endl;
        Document doc;
        if (doc.ParseJson ((*hit_list_iter).getObject())) {
          result.push_back (doc);
        }
        else {
            std::cout << "parse json false " << std::endl;
        }
        ++hit_list_iter;
      }
      std::cout << "result: " << result.size() << std::endl;
    }

    std::string DbInterface::InsertDoc (const Document& doc) {
      std::string json_str = doc.ToJson().dump();

      Json::Object json_obj;

      bool flag = true;

      try {
        json_obj.addMember (json_str.c_str(), json_str.c_str() + json_str.length());
      }catch (std::logic_error& e) {
        std::cerr << "failed to convert to json_obj: " << json_str << std::endl;
        flag = false;
      }

      std::string result;
      if (flag) {
        try {
          result = elastic_search_->index (index_, type_, json_obj);
        }catch (Exception& e) {
          std::cerr << "failed in DbInterface::InsertDoc. Exception cauth: " << e.what() << std::endl;
        }
      }
      return result;
    }
    void DbInterface::QueryDocWithId (const std::vector<int> id_list, std::vector<Document>& result) {

    }
  }//namespace db
}//namespace bitmile
